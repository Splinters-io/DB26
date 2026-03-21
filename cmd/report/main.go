package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Interaction struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	QType         string `json:"q-type"`
	RawRequest    string `json:"raw-request"`
	RemoteAddress string `json:"remote-address"`
	Timestamp     string `json:"timestamp"`
}

type TrapCapture struct {
	Timestamp     string              `json:"timestamp"`
	RemoteAddr    string              `json:"remote_addr"`
	Host          string              `json:"host"`
	Method        string              `json:"method"`
	URI           string              `json:"uri"`
	TLS           bool                `json:"tls"`
	Authorization string              `json:"authorization"`
	UserAgent     string              `json:"user_agent"`
	AllHeaders    map[string][]string `json:"all_headers"`
}

var knownPrefixes = map[string]bool{
	"host": true, "xff": true, "wafp": true, "contact": true,
	"rip": true, "trip": true, "xclip": true, "ff": true,
	"origip": true, "clip": true, "ref": true, "from": true,
	"origin": true, "ua": true, "n0x00": true,
}

// Output structs — all JSON

type CandidateRecord struct {
	Domain      string            `json:"domain"`
	Callbacks   int               `json:"callbacks"`
	Headers     map[string]int    `json:"headers"`
	Protocols   map[string]int    `json:"protocols"`
	SourceIPs   []string          `json:"source_ips"`
	FirstSeen   string            `json:"first_seen"`
}

type FetchRecord struct {
	SourceIP    string `json:"source_ip"`
	Host        string `json:"host"`
	Protocol    string `json:"protocol"`
	Method      string `json:"method"`
	URI         string `json:"uri"`
	UserAgent   string `json:"user_agent"`
	Class       string `json:"class"`
	Timestamp   string `json:"timestamp"`
	HasAuth     bool   `json:"has_auth"`
	AuthType    string `json:"auth_type,omitempty"`
	Credentials string `json:"credentials,omitempty"`
}

type CredentialRecord struct {
	SourceIP    string `json:"source_ip"`
	Host        string `json:"host"`
	Protocol    string `json:"protocol"`
	Method      string `json:"method"`
	URI         string `json:"uri"`
	AuthType    string `json:"auth_type"`
	RawAuth     string `json:"raw_auth"`
	Credentials string `json:"credentials"`
	UserAgent   string `json:"user_agent"`
	Timestamp   string `json:"timestamp"`
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: report <interactsh_log> <trap_captures.json> <correlation_id> <vps_ip>\n")
		fmt.Fprintf(os.Stderr, "\nGenerates:\n")
		fmt.Fprintf(os.Stderr, "  databouncing_candidates.jsonl  — DNS callback domains\n")
		fmt.Fprintf(os.Stderr, "  tainted_fetches.jsonl          — HTTP/HTTPS SSRF/RFI requests\n")
		fmt.Fprintf(os.Stderr, "  credential_captures.jsonl      — Auth responses with creds\n")
		os.Exit(1)
	}

	logPath := os.Args[1]
	trapPath := os.Args[2]
	corrID := strings.ToLower(os.Args[3])
	vpsIP := os.Args[4]

	fmt.Printf("[*] Correlation ID: %s\n", corrID)

	candidates := parseCandidates(logPath, corrID)
	writeCandidates(candidates)

	fetches, creds := parseFetches(trapPath, vpsIP)
	writeFetchesJSON(fetches)
	writeCredsJSON(creds)

	fmt.Printf("\n[*] Reports:\n")
	fmt.Printf("    databouncing_candidates.jsonl  %d domains\n", len(candidates))
	fmt.Printf("    tainted_fetches.jsonl          %d requests\n", len(fetches))
	fmt.Printf("    credential_captures.jsonl      %d captures\n", len(creds))
}

func parseCandidates(logPath, corrID string) []*candidateState {
	cmap := make(map[string]*candidateState)

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(strings.ToLower(line), corrID) {
			continue
		}
		if !strings.Contains(line, `"full-id"`) {
			continue
		}

		jsonStart := strings.Index(line, "{")
		if jsonStart == -1 {
			continue
		}

		var interaction Interaction
		if err := json.Unmarshal([]byte(line[jsonStart:]), &interaction); err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(interaction.FullID), "acme") {
			continue
		}

		prefix, domain := parseFullID(interaction.FullID, corrID)
		if domain == "" {
			continue
		}

		c, exists := cmap[domain]
		if !exists {
			c = &candidateState{
				domain:    domain,
				headers:   make(map[string]int),
				protocols: make(map[string]int),
				sources:   make(map[string]bool),
				firstSeen: interaction.Timestamp,
			}
			cmap[domain] = c
		}
		c.count++
		if prefix != "" {
			c.headers[prefix]++
		}
		c.protocols[interaction.Protocol]++
		c.sources[interaction.RemoteAddress] = true

		count++
		if count%200000 == 0 {
			fmt.Printf("[*] %d interactions, %d candidates...\n", count, len(cmap))
		}
	}

	fmt.Printf("[*] %d interactions → %d candidates\n", count, len(cmap))

	result := make([]*candidateState, 0, len(cmap))
	for _, c := range cmap {
		result = append(result, c)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].count > result[j].count
	})
	return result
}

type candidateState struct {
	domain    string
	count     int
	headers   map[string]int
	protocols map[string]int
	sources   map[string]bool
	firstSeen string
}

func parseFullID(fullID, corrID string) (prefix, domain string) {
	lower := strings.ToLower(fullID)
	idx := strings.Index(lower, corrID)
	if idx <= 0 {
		return "", ""
	}
	before := strings.TrimSuffix(lower[:idx], ".")
	parts := strings.SplitN(before, ".", 2)

	if len(parts) == 2 && knownPrefixes[parts[0]] {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return "", parts[0]
	}
	return "", before
}

func writeCandidates(candidates []*candidateState) {
	f, err := os.Create("databouncing_candidates.jsonl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, c := range candidates {
		sources := make([]string, 0, len(c.sources))
		for s := range c.sources {
			sources = append(sources, s)
		}
		sort.Strings(sources)

		rec := CandidateRecord{
			Domain:    c.domain,
			Callbacks: c.count,
			Headers:   c.headers,
			Protocols: c.protocols,
			SourceIPs: sources,
			FirstSeen: c.firstSeen,
		}
		enc.Encode(rec)
	}
}

func parseFetches(trapPath, vpsIP string) ([]FetchRecord, []CredentialRecord) {
	var fetches []FetchRecord
	var creds []CredentialRecord

	f, err := os.Open(trapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		return fetches, creds
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var cap TrapCapture
		if err := json.Unmarshal(scanner.Bytes(), &cap); err != nil {
			continue
		}

		if strings.Contains(cap.RemoteAddr, vpsIP) {
			continue
		}

		proto := "http"
		if cap.TLS {
			proto = "https"
		}

		authType, decoded := "", ""
		hasAuth := false
		if cap.Authorization != "" {
			hasAuth = true
			authType, decoded = decodeAuth(cap.Authorization)
		}

		fe := FetchRecord{
			SourceIP:  cap.RemoteAddr,
			Host:      cap.Host,
			Protocol:  proto,
			Method:    cap.Method,
			URI:       cap.URI,
			UserAgent: cap.UserAgent,
			Class:     classifyURI(cap.URI),
			Timestamp: cap.Timestamp,
			HasAuth:   hasAuth,
		}
		if hasAuth {
			fe.AuthType = authType
			fe.Credentials = decoded
		}

		fetches = append(fetches, fe)

		if hasAuth {
			cr := CredentialRecord{
				SourceIP:    cap.RemoteAddr,
				Host:        cap.Host,
				Protocol:    proto,
				Method:      cap.Method,
				URI:         cap.URI,
				AuthType:    authType,
				RawAuth:     cap.Authorization,
				Credentials: decoded,
				UserAgent:   cap.UserAgent,
				Timestamp:   cap.Timestamp,
			}
			creds = append(creds, cr)
		}
	}

	return fetches, creds
}

func writeFetchesJSON(fetches []FetchRecord) {
	f, err := os.Create("tainted_fetches.jsonl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, fe := range fetches {
		enc.Encode(fe)
	}
}

func writeCredsJSON(creds []CredentialRecord) {
	f, err := os.Create("credential_captures.jsonl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, c := range creds {
		enc.Encode(c)
	}
}

func classifyURI(uri string) string {
	u := strings.ToLower(uri)
	switch {
	case u == "/":
		return "root_fetch"
	case strings.Contains(u, ".git"):
		return "git_exposure"
	case strings.Contains(u, "_ignition"):
		return "laravel_rce"
	case strings.Contains(u, ".env"):
		return "env_exposure"
	case strings.Contains(u, "wp-"):
		return "wordpress_probe"
	case strings.Contains(u, "/api"):
		return "api_fetch"
	case strings.Contains(u, "/admin"):
		return "admin_probe"
	case strings.Contains(u, "/login") || strings.Contains(u, "/auth"):
		return "auth_probe"
	case strings.HasSuffix(u, ".xml"):
		return "xml_fetch"
	case strings.HasSuffix(u, ".json"):
		return "config_fetch"
	case strings.Contains(u, "/wap"):
		return "wap_profile"
	case strings.Contains(u, "robots.txt"):
		return "crawl_probe"
	case strings.Contains(u, "favicon"):
		return "asset_fetch"
	case strings.Contains(u, "/.well-known"):
		return "discovery"
	case strings.HasSuffix(u, ".php"):
		return "php_include"
	case strings.HasSuffix(u, ".asp"), strings.HasSuffix(u, ".aspx"):
		return "asp_include"
	default:
		return "other"
	}
}

func decodeAuth(auth string) (string, string) {
	switch {
	case strings.HasPrefix(auth, "NTLM "):
		return "ntlm", auth[5:]
	case strings.HasPrefix(auth, "Negotiate "):
		return "negotiate", auth[10:]
	case strings.HasPrefix(auth, "Basic "):
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			return "basic", "(decode_failed)"
		}
		return "basic", string(decoded)
	case strings.HasPrefix(auth, "Digest "):
		return "digest", auth[7:]
	default:
		return "unknown", auth
	}
}
