package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"db26/internal/auth"
	"db26/internal/correlate"
)

// Writer handles all file output for the recruiter.
// Methods are goroutine-safe.
type Writer struct {
	mu          sync.Mutex
	targetsFile *os.File
	jsonLogFile *os.File
	authFile    *os.File
}

// NewWriter opens all output files. The caller must call Close() when done.
func NewWriter(targetsPath, jsonLogPath, authPath string) (*Writer, error) {
	targets, err := os.OpenFile(targetsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open targets file: %w", err)
	}

	jsonLog, err := os.OpenFile(jsonLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		targets.Close()
		return nil, fmt.Errorf("open json log file: %w", err)
	}

	authFile, err := os.OpenFile(authPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		targets.Close()
		jsonLog.Close()
		return nil, fmt.Errorf("open auth file: %w", err)
	}

	return &Writer{
		targetsFile: targets,
		jsonLogFile: jsonLog,
		authFile:    authFile,
	}, nil
}

// WriteViableDomain appends a newly discovered viable domain to targets.txt.
func (w *Writer) WriteViableDomain(result correlate.DomainResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	line := fmt.Sprintf("%s [%s]\n", result.Domain, strings.Join(result.Headers, ","))
	_, err := w.targetsFile.WriteString(line)
	return err
}

// LogEntry is the JSON structure for each event in the log.
type LogEntry struct {
	Type      string    `json:"type"`      // "callback", "auth", "probe"
	Domain    string    `json:"domain"`
	Protocol  string    `json:"protocol"`
	Prefix    string    `json:"prefix,omitempty"`
	Headers   []string  `json:"headers,omitempty"`
	Scheme    string    `json:"scheme,omitempty"`
	Realm     string    `json:"realm,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// WriteCallbackLog appends a callback event to the JSON log.
func (w *Writer) WriteCallbackLog(result correlate.DomainResult) error {
	entry := LogEntry{
		Type:      "callback",
		Domain:    result.Domain,
		Headers:   result.Headers,
		Timestamp: result.LastSeen,
	}
	if len(result.Events) > 0 {
		last := result.Events[len(result.Events)-1]
		entry.Protocol = last.Protocol
		entry.Prefix = last.Prefix
		entry.RemoteIP = last.RemoteAddress
	}
	return w.writeJSON(w.jsonLogFile, entry)
}

// WriteAuthDetection appends an auth detection to both the auth file and JSON log.
func (w *Writer) WriteAuthDetection(det auth.Detection) error {
	entry := LogEntry{
		Type:      "auth",
		Domain:    det.Domain,
		Protocol:  det.Protocol,
		Scheme:    det.Scheme,
		Realm:     det.Realm,
		Timestamp: det.Timestamp,
	}

	if err := w.writeJSON(w.authFile, entry); err != nil {
		return err
	}
	return w.writeJSON(w.jsonLogFile, entry)
}

func (w *Writer) writeJSON(f *os.File, v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}

// TargetsFile returns the underlying targets file for direct writes.
func (w *Writer) TargetsFile() *os.File {
	return w.targetsFile
}

// Close flushes and closes all output files.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var errs []string
	if err := w.targetsFile.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := w.jsonLogFile.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := w.authFile.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
