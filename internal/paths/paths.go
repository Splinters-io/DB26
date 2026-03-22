package paths

import (
	"os"
	"path/filepath"
)

// Default base directory for all DB26 data on the server.
// Override with DB26_BASE environment variable.
const DefaultBase = "/opt/db26"

// Base returns the DB26 base directory, respecting DB26_BASE env override.
func Base() string {
	if v := os.Getenv("DB26_BASE"); v != "" {
		return v
	}
	return DefaultBase
}

// Bin returns the path to the bin directory.
func Bin() string { return filepath.Join(Base(), "bin") }

// Etc returns the path to the etc (config) directory.
func Etc() string { return filepath.Join(Base(), "etc") }

// Runs returns the path to the runs directory.
func Runs() string { return filepath.Join(Base(), "runs") }

// Logs returns the path to the logs directory.
func Logs() string { return filepath.Join(Base(), "logs") }

// Data returns the path to the data directory.
func Data() string { return filepath.Join(Base(), "data") }

// Targets returns the path to the data/targets directory.
func Targets() string { return filepath.Join(Data(), "targets") }

// Candidates returns the path to the data/candidates directory.
func Candidates() string { return filepath.Join(Data(), "candidates") }

// Received returns the path to the data/received directory.
func Received() string { return filepath.Join(Data(), "received") }

// Poc returns the path to the poc directory.
func Poc() string { return filepath.Join(Base(), "poc") }

// Tmp returns the path to the tmp directory.
func Tmp() string { return filepath.Join(Base(), "tmp") }

// InteractshLog returns the default interactsh log directory.
func InteractshLog() string { return filepath.Join(Logs(), "interactsh") }

// InteractshLogFile returns the default path to the interactsh server log.
func InteractshLogFile() string { return filepath.Join(InteractshLog(), "interactsh.log") }

// Responder returns the path to the responder output directory.
func Responder() string { return filepath.Join(Logs(), "responder") }

// ConfigDir returns the path to the user config directory (~/.db26).
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".db26")
}

// ConfigFile returns the path to the user config file (~/.db26/config.json).
func ConfigFile() string {
	return filepath.Join(ConfigDir(), "config.json")
}

// CertDir returns the default certificate directory.
func CertDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "certmagic", "certificates", "acme-v02.api.letsencrypt.org-directory")
}

// BinPaths returns the default binary search paths.
func BinPaths() []string {
	return []string{Bin(), "/usr/local/go/bin"}
}

// Run returns the path to a specific run directory.
func Run(name string) string { return filepath.Join(Runs(), name) }

// RunFile returns the path to a file within a run directory.
func RunFile(runName, fileName string) string { return filepath.Join(Runs(), runName, fileName) }
