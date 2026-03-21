package logparser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"time"

	"db26/internal/metrics"
)

// Interaction matches the JSON structure interactsh-server writes to its log.
type Interaction struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	QType         string `json:"q-type"`
	RawRequest    string `json:"raw-request"`
	RemoteAddress string `json:"remote-address"`
	Timestamp     string `json:"timestamp"`
}

// Candidate is an immutable record of a domain that responded to a specific header.
type Candidate struct {
	Domain        string
	Prefix        string
	Protocol      string
	RemoteAddress string
	QType         string
	Timestamp     string
}

// Parser reads the interactsh server log and extracts candidates in real-time.
type Parser struct {
	correlationID string
	metrics       *metrics.Counters
	mu            sync.Mutex
	candidates    map[string]map[string]bool // domain → set of prefixes
	onCandidate   func(Candidate)
}

// NewParser creates a log parser that filters for the given correlation ID.
func NewParser(correlationID string, m *metrics.Counters, onCandidate func(Candidate)) *Parser {
	return &Parser{
		correlationID: strings.ToLower(correlationID),
		metrics:       m,
		candidates:    make(map[string]map[string]bool),
		onCandidate:   onCandidate,
	}
}

// knownPrefixes are the header correlation prefixes we look for.
var knownPrefixes = map[string]bool{
	"host": true, "xff": true, "wafp": true, "contact": true,
	"rip": true, "trip": true, "xclip": true, "ff": true,
	"origip": true, "clip": true, "ref": true, "from": true,
	"origin": true, "ua": true, "n0x00": true,
}

// TailLog reads the interactsh log file continuously (like tail -f),
// parsing JSON interactions and extracting candidates.
// Blocks until ctx is done or the reader is closed.
func (p *Parser) TailLog(logPath string, done <-chan struct{}) error {
	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	// Seek to end — we only want new interactions
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for {
		select {
		case <-done:
			return nil
		default:
		}

		if scanner.Scan() {
			p.processLine(scanner.Text())
		} else {
			// No new data — brief pause then retry
			time.Sleep(200 * time.Millisecond)
			// Scanner may be exhausted, re-read from current position
			scanner = bufio.NewScanner(f)
			scanner.Buffer(buf, 1024*1024)
		}
	}
}

// ReadExistingLog processes an entire log file (not tailing). For post-hoc analysis.
func (p *Parser) ReadExistingLog(logPath string) error {
	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		p.processLine(scanner.Text())
	}
	return scanner.Err()
}

func (p *Parser) processLine(line string) {
	// Quick pre-filter: must contain our correlation ID
	lower := strings.ToLower(line)
	if !strings.Contains(lower, p.correlationID) {
		return
	}

	// Must be a JSON interaction line
	if !strings.Contains(line, `"full-id"`) {
		return
	}

	// Find the JSON object in the line (may have prefix text from interactsh formatting)
	jsonStart := strings.Index(line, "{")
	if jsonStart == -1 {
		return
	}

	var interaction Interaction
	if err := json.Unmarshal([]byte(line[jsonStart:]), &interaction); err != nil {
		return
	}

	// Skip ACME challenge queries
	if strings.Contains(strings.ToLower(interaction.FullID), "acme") {
		return
	}

	// Parse the full-id: prefix.domain.correlationID
	prefix, domain := parseFullID(interaction.FullID, p.correlationID)
	if domain == "" {
		return
	}

	// Update metrics
	switch interaction.Protocol {
	case "dns":
		p.metrics.IncCallbackDNS()
	case "http":
		p.metrics.IncCallbackHTTP()
	case "https":
		p.metrics.IncCallbackHTTPS()
	}

	// Domain is already in its original form (dots preserved)
	realDomain := domain

	candidate := Candidate{
		Domain:        realDomain,
		Prefix:        prefix,
		Protocol:      interaction.Protocol,
		RemoteAddress: interaction.RemoteAddress,
		QType:         interaction.QType,
		Timestamp:     interaction.Timestamp,
	}

	// Track unique domain+prefix combinations (keyed by real domain)
	isNew := false
	p.mu.Lock()
	if _, exists := p.candidates[realDomain]; !exists {
		p.candidates[realDomain] = make(map[string]bool)
		p.metrics.IncViableDomains()
		isNew = true
	}
	if prefix != "" && !p.candidates[realDomain][prefix] {
		p.candidates[realDomain][prefix] = true
		isNew = true
	}
	p.mu.Unlock()

	if isNew && p.onCandidate != nil {
		p.onCandidate(candidate)
	}
}

// parseFullID extracts prefix and domain from a full-id string.
// Format: "prefix.real.domain.com.correlationID" — dots preserved, domain returned as-is.
func parseFullID(fullID, corrID string) (prefix, domain string) {
	lower := strings.ToLower(fullID)

	// Remove correlationID suffix
	idx := strings.Index(lower, corrID)
	if idx <= 0 {
		return "", ""
	}

	// Everything before the correlation ID, minus the trailing dot
	beforeCorr := lower[:idx]
	beforeCorr = strings.TrimSuffix(beforeCorr, ".")

	parts := strings.SplitN(beforeCorr, ".", 2)

	if len(parts) == 2 && knownPrefixes[parts[0]] {
		// prefix.domain
		return parts[0], parts[1]
	}

	if len(parts) == 1 {
		// Just domain, no prefix (some servers strip the prefix subdomain)
		return "", parts[0]
	}

	// First part isn't a known prefix — treat whole thing as domain
	return "", beforeCorr
}

// Results returns an immutable snapshot of all discovered candidates.
func (p *Parser) Results() map[string][]string {
	p.mu.Lock()
	defer p.mu.Unlock()

	results := make(map[string][]string, len(p.candidates))
	for domain, prefixes := range p.candidates {
		plist := make([]string, 0, len(prefixes))
		for prefix := range prefixes {
			plist = append(plist, prefix)
		}
		results[domain] = plist
	}
	return results
}

// CandidateCount returns the number of unique candidate domains.
func (p *Parser) CandidateCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.candidates)
}
