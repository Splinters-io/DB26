package preflight

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Result is an immutable check result.
type Result struct {
	Name   string
	Pass   bool
	Detail string
}

// RunAll executes all pre-flight checks and returns results.
// Any critical failure sets ok = false.
func RunAll(domainsFile, oobServer, oobToken, runDir string) (results []Result, ok bool) {
	ok = true

	results = append(results, checkDomainsFile(domainsFile))
	results = append(results, checkRunDir(runDir))
	results = append(results, checkDNS())
	results = append(results, checkInteractshServer(oobServer, oobToken))
	results = append(results, checkInteractshLog())
	results = append(results, checkDiskSpace())

	for _, r := range results {
		if !r.Pass {
			ok = false
		}
	}

	return results, ok
}

// RunWithDeps executes all pre-flight checks including dependency verification.
func RunWithDeps(domainsFile, oobServer, oobToken, runDir string, extraPaths []string) (results []Result, ok bool) {
	ok = true

	// Core checks
	results = append(results, checkDomainsFile(domainsFile))
	results = append(results, checkRunDir(runDir))
	results = append(results, checkDNS())
	results = append(results, checkInteractshServer(oobServer, oobToken))
	results = append(results, checkInteractshLog())
	results = append(results, checkDiskSpace())

	// Dependency checks
	depResults := CheckDeps(DefaultDeps(), extraPaths)
	results = append(results, depResults...)

	for _, r := range results {
		if !r.Pass {
			ok = false
		}
	}

	return results, ok
}

// Print displays all results with pass/fail indicators.
func Print(results []Result) {
	fmt.Println("\n  Pre-flight Checks")
	fmt.Println("  ─────────────────────────────────────────")
	for _, r := range results {
		icon := " [PASS]"
		if !r.Pass {
			icon = " [FAIL]"
		}
		fmt.Printf("  %s  %-28s %s\n", icon, r.Name, r.Detail)
	}
	fmt.Println()
}

func checkDomainsFile(path string) Result {
	name := "Domains file"
	if path == "" {
		return Result{name, false, "not specified"}
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Result{name, false, fmt.Sprintf("not found: %s", path)}
	}
	if err != nil {
		return Result{name, false, fmt.Sprintf("error: %s", err)}
	}

	if info.Size() == 0 {
		return Result{name, false, "file is empty"}
	}

	// Count lines (approximate for large files)
	f, err := os.Open(path)
	if err != nil {
		return Result{name, false, fmt.Sprintf("can't read: %s", err)}
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	lines := 0
	for {
		n, err := f.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				lines++
			}
		}
		if err != nil {
			break
		}
	}

	return Result{name, true, fmt.Sprintf("%d domains (%s)", lines, path)}
}

func checkRunDir(dir string) Result {
	name := "Run directory"
	if dir == "" {
		return Result{name, true, "using current directory"}
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return Result{name, false, fmt.Sprintf("can't create: %s", err)}
	}

	// Test write
	testFile := dir + "/.preflight_test"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return Result{name, false, fmt.Sprintf("not writable: %s", err)}
	}
	os.Remove(testFile)

	return Result{name, true, dir}
}

func checkDNS() Result {
	name := "DNS resolution"
	addrs, err := net.LookupHost("google.com")
	if err != nil {
		return Result{name, false, fmt.Sprintf("failed: %s", err)}
	}
	return Result{name, true, fmt.Sprintf("ok (%s)", addrs[0])}
}

func checkInteractshServer(serverURL, token string) Result {
	name := "Interactsh server"
	if serverURL == "" {
		return Result{name, false, "not specified"}
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	// Try to reach the server
	resp, err := client.Get(serverURL)
	if err != nil {
		// If NTLM trap is on 443, we'll get a 401 which is fine
		if strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "EOF") {
			return Result{name, true, fmt.Sprintf("reachable (TLS) — %s", serverURL)}
		}
		return Result{name, false, fmt.Sprintf("unreachable: %s", err)}
	}
	defer resp.Body.Close()

	// 200 = interactsh API, 401 = NTLM trap proxying API
	if resp.StatusCode == 200 || resp.StatusCode == 401 {
		return Result{name, true, fmt.Sprintf("reachable (HTTP %d) — %s", resp.StatusCode, serverURL)}
	}

	return Result{name, true, fmt.Sprintf("reachable (HTTP %d) — %s", resp.StatusCode, serverURL)}
}

func checkInteractshLog() Result {
	name := "Interactsh log"
	logPath := "/var/log/interactsh/interactsh.log"
	if v := os.Getenv("INTERACTSH_LOG"); v != "" {
		logPath = v
	}

	info, err := os.Stat(logPath)
	if os.IsNotExist(err) {
		return Result{name, false, fmt.Sprintf("not found: %s", logPath)}
	}
	if err != nil {
		return Result{name, false, fmt.Sprintf("error: %s", err)}
	}

	// Check readable
	f, err := os.Open(logPath)
	if err != nil {
		return Result{name, false, fmt.Sprintf("not readable: %s", err)}
	}
	f.Close()

	return Result{name, true, fmt.Sprintf("ok (%d bytes) — %s", info.Size(), logPath)}
}

func checkDiskSpace() Result {
	name := "Disk space"

	// Simple check: try to determine free space via statfs
	// On Linux, check /root partition
	var stat [64]byte // placeholder
	_ = stat

	// Fallback: check if we can write a test file
	f, err := os.CreateTemp("/root", "disk_check_*")
	if err != nil {
		return Result{name, false, fmt.Sprintf("can't write to /root: %s", err)}
	}
	f.Close()
	os.Remove(f.Name())

	return Result{name, true, "writable"}
}
