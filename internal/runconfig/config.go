package runconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the persistent configuration file for the DB26 recruiter.
// Stored at ~/.db26/config.json or specified via --config flag.
type Config struct {
	// Server
	InteractshServer string `json:"interactsh_server"`
	InteractshToken  string `json:"interactsh_token"`
	VPSAddress       string `json:"vps_address"`

	// Paths
	InteractshLog string   `json:"interactsh_log"`
	RunsDir       string   `json:"runs_dir"`
	BinPaths      []string `json:"bin_paths"`

	// Defaults
	Workers   int  `json:"workers"`
	RPS       int  `json:"rps"`
	Timeout   int  `json:"timeout"`
	Grace     int  `json:"grace"`
	ProbeHTTPS bool `json:"probe_https"`

	// Dependencies
	Dependencies []DepConfig `json:"dependencies"`
}

// DepConfig overrides dependency settings.
type DepConfig struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Required bool   `json:"required"`
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		InteractshServer: "",
		InteractshLog:    "/var/log/interactsh/interactsh.log",
		RunsDir:          "/root/db26/runs",
		BinPaths:         []string{"/root/go/bin", "/usr/local/go/bin"},
		Workers:          2000,
		RPS:              5000,
		Timeout:          1,
		Grace:            120,
		ProbeHTTPS:       true,
		Dependencies: []DepConfig{
			{Name: "interactsh-server", Required: true},
			{Name: "interactsh-client", Required: false},
			{Name: "subfinder", Required: false},
			{Name: "screen", Required: true},
		},
	}
}

// Load reads config from a JSON file. Returns defaults if file doesn't exist.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		path = defaultPath()
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil // Use defaults
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save writes config to a JSON file.
func Save(path string, cfg Config) error {
	if path == "" {
		path = defaultPath()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// Init creates a default config file if one doesn't exist.
func Init(path string) (string, error) {
	if path == "" {
		path = defaultPath()
	}

	if _, err := os.Stat(path); err == nil {
		return path, nil // Already exists
	}

	cfg := DefaultConfig()
	if err := Save(path, cfg); err != nil {
		return "", err
	}

	return path, nil
}

func defaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".db26", "config.json")
}
