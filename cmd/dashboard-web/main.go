package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"db26/internal/paths"
)

//go:embed index.html
var staticFS embed.FS

type DashState struct {
	mu   sync.RWMutex
	data DashData
}

type DashData struct {
	// Recruiter
	Elapsed    string `json:"elapsed"`
	ProbesSent int64  `json:"probes_sent"`
	RPS        int    `json:"rps"`
	HTTPOK     int64  `json:"http_ok"`
	HTTPSOK    int64  `json:"https_ok"`
	Errors     int64  `json:"errors"`
	DNSCb      int64  `json:"dns_cb"`
	HTTPCb     int64  `json:"http_cb"`
	HTTPSCb    int64  `json:"https_cb"`
	Candidates int64  `json:"candidates"`
	AuthTotal  int64  `json:"auth_total"`
	Running    bool   `json:"running"`

	// Trap
	TrapTotal    int64 `json:"trap_total"`
	TrapExternal int64 `json:"trap_external"`
	TrapAuth     int64 `json:"trap_auth"`

	// Subfinder
	SubfinderCount  int64 `json:"subfinder_count"`
	SubfinderRoots  int64 `json:"subfinder_roots"`

	// Recent events
	RecentCandidates []string    `json:"recent_candidates"`
	RecentFetches    []FetchEvt  `json:"recent_fetches"`
	RecentAuth       []string    `json:"recent_auth"`

	// Screens
	Screens []string `json:"screens"`

	Timestamp string `json:"timestamp"`
}

type FetchEvt struct {
	IP     string `json:"ip"`
	Host   string `json:"host"`
	Method string `json:"method"`
	URI    string `json:"uri"`
	Proto  string `json:"proto"`
	Auth   string `json:"auth"`
	Time   string `json:"time"`
}

var state = &DashState{}

func main() {
	port := "8888"
	if p := os.Getenv("DASH_PORT"); p != "" {
		port = p
	}

	// Auth credentials from env or defaults
	authUser := os.Getenv("DASH_USER")
	authPass := os.Getenv("DASH_PASS")
	if authUser == "" {
		authUser = "db26"
	}
	if authPass == "" {
		authPass = "databouncing"
		fmt.Println("[!] Using default credentials — set DASH_USER and DASH_PASS env vars")
	}

	// Bind to localhost only — access via SSH tunnel: ssh -L 8888:127.0.0.1:8888 root@vps
	listenAddr := "127.0.0.1:" + port
	if os.Getenv("DASH_EXPOSE") == "true" {
		listenAddr = "0.0.0.0:" + port
		fmt.Println("[!] Dashboard exposed on all interfaces — ensure auth is strong")
	}

	go pollLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/state", serveState)
	mux.HandleFunc("/api/stream", serveSSE)

	handler := authMiddleware(mux, authUser, authPass)

	fmt.Printf("[*] DB26 Dashboard on http://%s\n", listenAddr)
	fmt.Printf("[*] Access via: ssh -L %s:127.0.0.1:%s root@<YOUR_VPS_IP>\n", port, port)
	fmt.Printf("[*] Then open: http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(listenAddr, handler))
}

func authMiddleware(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="DB26 Dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	data, _ := staticFS.ReadFile("index.html")
	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
}

func serveState(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state.data)
}

func serveSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	for {
		state.mu.RLock()
		data, _ := json.Marshal(state.data)
		state.mu.RUnlock()

		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()

		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func pollLoop() {
	for {
		d := DashData{Timestamp: time.Now().UTC().Format(time.RFC3339)}

		// Parse recruiter log
		parseRecruiterLog(&d)

		// Parse trap stats
		parseTrapStats(&d)

		// Parse subfinder
		parseSubfinder(&d)

		// Screen sessions
		d.Screens = getScreens()

		state.mu.Lock()
		state.data = d
		state.mu.Unlock()

		time.Sleep(2 * time.Second)
	}
}

func parseRecruiterLog(d *DashData) {
	// Find active run log
	logPaths := []string{}

	// Check for active screen recruiter log
	runsDir := paths.Runs()
	entries, _ := os.ReadDir(runsDir)
	for _, e := range entries {
		if e.IsDir() {
			p := filepath.Join(runsDir, e.Name(), "recruiter.log")
			if _, err := os.Stat(p); err == nil {
				logPaths = append(logPaths, p)
			}
		}
	}
	// Also check logs directory
	legacyLog := filepath.Join(paths.Logs(), "recruiter_run.log")
	if _, err := os.Stat(legacyLog); err == nil {
		logPaths = append(logPaths, legacyLog)
	}

	// Use most recently modified
	var bestPath string
	var bestTime time.Time
	for _, p := range logPaths {
		info, err := os.Stat(p)
		if err == nil && info.ModTime().After(bestTime) {
			bestTime = info.ModTime()
			bestPath = p
		}
	}

	if bestPath == "" {
		return
	}

	// Check if actively being written to (within last 30s)
	if time.Since(bestTime) < 30*time.Second {
		d.Running = true
	}

	// Find latest stats line — tac + grep -m1 to avoid scanning entire file
	cmd := exec.Command("bash", "-c", fmt.Sprintf("tac '%s' | grep -m1 -a 'Sent:'", bestPath))
	out, _ := cmd.Output()
	lastStats := strings.TrimSpace(strings.ReplaceAll(string(out), "\r", ""))
	if strings.Contains(lastStats, "Sent:") {
		parseStatsLine(lastStats, d)
	}

	// Tail for recent candidates and auth
	lines := tailFile(bestPath, 100)
	var candidates []string

	for _, line := range lines {
		line = strings.ReplaceAll(line, "\r", "")
		if strings.HasPrefix(line, "[+] CANDIDATE:") {
			candidates = append(candidates, line[15:])
		}
		if strings.HasPrefix(line, "[AUTH]") {
			d.RecentAuth = append(d.RecentAuth, line[7:])
		}
	}

	if len(candidates) > 10 {
		candidates = candidates[len(candidates)-10:]
	}
	d.RecentCandidates = candidates

	if len(d.RecentAuth) > 10 {
		d.RecentAuth = d.RecentAuth[len(d.RecentAuth)-10:]
	}
}

func parseStatsLine(line string, d *DashData) {
	// [*] 5m30s | Sent: 28002 (598/s) | DNS: 110759 | HTTP: 0 | HTTPS: 0 | Candidates: 9849 | Auth: 1
	// Extract key:value pairs using simple string parsing
	parts := strings.Split(line, "|")
	for _, p := range parts {
		p = strings.TrimSpace(p)

		if strings.HasPrefix(p, "[*]") {
			fields := strings.Fields(p)
			if len(fields) >= 2 {
				d.Elapsed = fields[1]
			}
		}

		// Extract numbers after known labels
		if i := strings.Index(p, "Sent:"); i >= 0 {
			rest := strings.TrimSpace(p[i+5:])
			fields := strings.Fields(rest)
			if len(fields) >= 1 {
				fmt.Sscanf(fields[0], "%d", &d.ProbesSent)
			}
			// Parse (NNN/s)
			if len(fields) >= 2 {
				s := strings.Trim(fields[1], "()/s")
				fmt.Sscanf(s, "%d", &d.RPS)
			}
		}
		if i := strings.Index(p, "DNS:"); i >= 0 && !strings.Contains(p[:max(i,1)], "HTTPS") {
			rest := strings.TrimSpace(p[i+4:])
			fmt.Sscanf(rest, "%d", &d.DNSCb)
		}
		if strings.HasPrefix(p, "HTTP:") {
			rest := strings.TrimSpace(p[5:])
			fmt.Sscanf(rest, "%d", &d.HTTPCb)
		}
		if strings.HasPrefix(p, "HTTPS:") {
			rest := strings.TrimSpace(p[6:])
			fmt.Sscanf(rest, "%d", &d.HTTPSCb)
		}
		if i := strings.Index(p, "Candidates:"); i >= 0 {
			rest := strings.TrimSpace(p[i+11:])
			fmt.Sscanf(rest, "%d", &d.Candidates)
		}
		if i := strings.Index(p, "Auth:"); i >= 0 {
			rest := strings.TrimSpace(p[i+5:])
			fmt.Sscanf(rest, "%d", &d.AuthTotal)
		}
	}
}

func max(a, b int) int {
	if a > b { return a }
	return b
}

func parseTrapStats(d *DashData) {
	// Find most recent trap captures file
	trapPaths := []string{}
	runsDir := paths.Runs()
	trapEntries, _ := os.ReadDir(runsDir)
	for _, e := range trapEntries {
		if e.IsDir() {
			p := filepath.Join(runsDir, e.Name(), "trap_captures.json")
			if _, err := os.Stat(p); err == nil {
				trapPaths = append(trapPaths, p)
			}
		}
	}

	var bestTrapPath string
	var bestTrapTime time.Time
	for _, p := range trapPaths {
		info, err := os.Stat(p)
		if err == nil && info.ModTime().After(bestTrapTime) {
			bestTrapTime = info.ModTime()
			bestTrapPath = p
		}
	}

	if bestTrapPath == "" {
		return
	}

	f, err := os.Open(bestTrapPath)
	if err != nil {
		return
	}
	defer f.Close()

	// Count lines and extract external hits
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 1024*1024)

	var fetches []FetchEvt

	for scanner.Scan() {
		d.TrapTotal++
		line := scanner.Text()
		if !strings.Contains(line, "<YOUR_VPS_IP>") {
			d.TrapExternal++

			var cap struct {
				RemoteAddr    string `json:"remote_addr"`
				Host          string `json:"host"`
				Method        string `json:"method"`
				URI           string `json:"uri"`
				TLS           bool   `json:"tls"`
				Authorization string `json:"authorization"`
				Timestamp     string `json:"timestamp"`
			}
			if json.Unmarshal([]byte(line), &cap) == nil {
				proto := "HTTP"
				if cap.TLS {
					proto = "HTTPS"
				}
				auth := ""
				if cap.Authorization != "" {
					auth = cap.Authorization[:min(40, len(cap.Authorization))]
					d.TrapAuth++
				}
				fetches = append(fetches, FetchEvt{
					IP:     cap.RemoteAddr,
					Host:   cap.Host,
					Method: cap.Method,
					URI:    cap.URI,
					Proto:  proto,
					Auth:   auth,
					Time:   cap.Timestamp,
				})
			}
		}
	}

	if len(fetches) > 20 {
		fetches = fetches[len(fetches)-20:]
	}
	d.RecentFetches = fetches
}

func parseSubfinder(d *DashData) {
	subdomainsFile := filepath.Join(paths.Targets(), "subdomains_all.txt")
	info, err := os.Stat(subdomainsFile)
	if err != nil {
		return
	}
	// Estimate line count from file size (avg ~30 bytes per line)
	d.SubfinderCount = info.Size() / 30

	// Get accurate count if file is small enough, otherwise estimate
	if info.Size() < 500*1024*1024 {
		cmd := exec.Command("wc", "-l", subdomainsFile)
		out, err := cmd.Output()
		if err == nil {
			fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &d.SubfinderCount)
		}
	}
}

func getScreens() []string {
	cmd := exec.Command("screen", "-ls")
	out, _ := cmd.CombinedOutput()
	var screens []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ".") && (strings.Contains(line, "Detached") || strings.Contains(line, "Attached")) {
			screens = append(screens, line)
		}
	}
	return screens
}

func tailFile(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Seek to near end — use large buffer to capture stats lines among candidate output
	info, _ := f.Stat()
	offset := info.Size() - 128*1024
	if offset < 0 {
		offset = 0
	}
	f.Seek(offset, io.SeekStart)

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
