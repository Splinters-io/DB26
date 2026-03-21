package preflight

import (
	"fmt"
	"os/exec"
	"strings"
)

// Dependency defines an external tool the recruiter may need.
type Dependency struct {
	Name     string `json:"name"`
	Binary   string `json:"binary"`
	Required bool   `json:"required"`
	Purpose  string `json:"purpose"`
}

// DefaultDeps returns the standard dependency list.
func DefaultDeps() []Dependency {
	return []Dependency{
		{Name: "interactsh-server", Binary: "interactsh-server", Required: true, Purpose: "OOB callback server (DNS/HTTP/HTTPS/SMTP)"},
		{Name: "interactsh-client", Binary: "interactsh-client", Required: false, Purpose: "Standalone callback collector"},
		{Name: "subfinder", Binary: "subfinder", Required: false, Purpose: "Subdomain enumeration"},
		{Name: "screen", Binary: "screen", Required: true, Purpose: "Session management for long-running tasks"},
		{Name: "curl", Binary: "curl", Required: false, Purpose: "HTTP testing and verification"},
		{Name: "dig", Binary: "dig", Required: false, Purpose: "DNS verification"},
	}
}

// CheckDeps verifies which dependencies are installed and returns results.
func CheckDeps(deps []Dependency, extraPaths []string) []Result {
	var results []Result

	for _, dep := range deps {
		r := checkBinary(dep, extraPaths)
		results = append(results, r)
	}

	return results
}

func checkBinary(dep Dependency, extraPaths []string) Result {
	name := dep.Name

	// Check standard PATH
	path, err := exec.LookPath(dep.Binary)
	if err == nil {
		version := getBinaryVersion(path)
		return Result{name, true, fmt.Sprintf("%s %s", path, version)}
	}

	// Check extra paths (e.g. /root/go/bin)
	for _, dir := range extraPaths {
		candidate := dir + "/" + dep.Binary
		if _, err := exec.LookPath(candidate); err == nil {
			version := getBinaryVersion(candidate)
			return Result{name, true, fmt.Sprintf("%s %s", candidate, version)}
		}
		// Also try just running it
		cmd := exec.Command(candidate, "--version")
		if out, err := cmd.CombinedOutput(); err == nil {
			ver := extractVersion(string(out))
			return Result{name, true, fmt.Sprintf("%s %s", candidate, ver)}
		}
	}

	if dep.Required {
		return Result{name, false, fmt.Sprintf("NOT FOUND — %s", dep.Purpose)}
	}
	return Result{name, true, fmt.Sprintf("not installed (optional — %s)", dep.Purpose)}
}

func getBinaryVersion(path string) string {
	// Try --version, -version, version
	for _, flag := range []string{"--version", "-version", "version"} {
		cmd := exec.Command(path, flag)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return extractVersion(string(out))
		}
	}
	return ""
}

func extractVersion(output string) string {
	// Take first line, trim noise
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return ""
	}
	first := strings.TrimSpace(lines[0])
	// Shorten if too long
	if len(first) > 40 {
		first = first[:40] + "..."
	}
	return first
}
