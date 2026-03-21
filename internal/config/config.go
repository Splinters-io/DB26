package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config holds all recruiter configuration. Immutable after creation.
type Config struct {
	DomainsFile    string
	OOBServer      string
	OOBToken       string
	Workers        int
	RPS            int
	TimeoutSecs    int
	GracePeriodSec int
	OutputFile     string
	AuthFile       string
	JSONLog        string
	ProbeHTTPS     bool
	Verbose        bool
	VerifyHeaders  bool   // Print headers for first N domains then exit
	OOBDomain      string // Use external OOB domain (skip interactsh client)
	RunDir         string // Output directory for this run's reports
}

// Defaults
const (
	DefaultWorkers        = 500
	DefaultRPS            = 1000
	DefaultTimeoutSecs    = 2
	DefaultGracePeriodSec = 60
	DefaultOutputFile     = "targets.txt"
	DefaultAuthFile       = "auth_results.json"
	DefaultJSONLog        = "recruiter_log.json"
	MaxWorkers            = 5000
	MinWorkers            = 1
	MinRPS                = 1
	MaxRPS                = 50000
)

// Load parses CLI flags and environment variables, validates, and returns an immutable Config.
func Load() (Config, error) {
	var c Config

	flag.StringVar(&c.DomainsFile, "domains", "", "Path to domains file (required)")
	flag.StringVar(&c.DomainsFile, "d", "", "Path to domains file (shorthand)")
	flag.StringVar(&c.OOBServer, "server", "", "Interactsh server URL (e.g. https://oob.yourdomain.com)")
	flag.StringVar(&c.OOBServer, "s", "", "Interactsh server URL (shorthand)")
	flag.StringVar(&c.OOBToken, "token", "", "Interactsh server auth token")
	flag.StringVar(&c.OOBToken, "t", "", "Interactsh server auth token (shorthand)")
	flag.IntVar(&c.Workers, "workers", DefaultWorkers, "Number of concurrent workers")
	flag.IntVar(&c.Workers, "w", DefaultWorkers, "Number of concurrent workers (shorthand)")
	flag.IntVar(&c.RPS, "rps", DefaultRPS, "Maximum requests per second")
	flag.IntVar(&c.TimeoutSecs, "timeout", DefaultTimeoutSecs, "HTTP request timeout in seconds")
	flag.IntVar(&c.GracePeriodSec, "grace", DefaultGracePeriodSec, "Seconds to wait for late callbacks after probing completes")
	flag.StringVar(&c.OutputFile, "output", DefaultOutputFile, "Output file for viable domains")
	flag.StringVar(&c.OutputFile, "o", DefaultOutputFile, "Output file (shorthand)")
	flag.StringVar(&c.AuthFile, "auth-output", DefaultAuthFile, "Output file for auth detections")
	flag.StringVar(&c.JSONLog, "json-log", DefaultJSONLog, "JSON log file for all events")
	flag.BoolVar(&c.ProbeHTTPS, "https", true, "Also probe HTTPS endpoints")
	flag.BoolVar(&c.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&c.Verbose, "v", false, "Verbose output (shorthand)")
	flag.BoolVar(&c.VerifyHeaders, "verify-headers", false, "Print headers for first 3 domains and exit (no probing)")
	flag.StringVar(&c.OOBDomain, "oob-domain", "", "Use external OOB domain (e.g. from interactsh-client CLI)")
	flag.StringVar(&c.RunDir, "run-dir", "", "Output directory for reports (auto-created if set)")

	flag.Parse()

	// Override with env vars if flags not set
	c = applyEnvOverrides(c)

	if err := validate(c); err != nil {
		return Config{}, err
	}

	return c, nil
}

// applyEnvOverrides returns a new Config with environment variable overrides applied.
func applyEnvOverrides(c Config) Config {
	if c.OOBServer == "" {
		if v := os.Getenv("DB26_OOB_SERVER"); v != "" {
			c.OOBServer = v
		}
	}
	if c.OOBToken == "" {
		if v := os.Getenv("DB26_OOB_TOKEN"); v != "" {
			c.OOBToken = v
		}
	}
	if c.DomainsFile == "" {
		if v := os.Getenv("DB26_DOMAINS_FILE"); v != "" {
			c.DomainsFile = v
		}
	}
	return c
}

func validate(c Config) error {
	var errs []string

	if c.DomainsFile == "" {
		errs = append(errs, "domains file is required (-d/--domains or DB26_DOMAINS_FILE)")
	} else if _, err := os.Stat(c.DomainsFile); os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("domains file not found: %s", c.DomainsFile))
	}

	if c.OOBServer == "" && !c.VerifyHeaders && c.OOBDomain == "" {
		errs = append(errs, "interactsh server URL is required (-s/--server or --oob-domain)")
	}

	if c.Workers < MinWorkers || c.Workers > MaxWorkers {
		errs = append(errs, fmt.Sprintf("workers must be between %d and %d", MinWorkers, MaxWorkers))
	}

	if c.RPS < MinRPS || c.RPS > MaxRPS {
		errs = append(errs, fmt.Sprintf("rps must be between %d and %d", MinRPS, MaxRPS))
	}

	if c.TimeoutSecs < 1 || c.TimeoutSecs > 30 {
		errs = append(errs, "timeout must be between 1 and 30 seconds")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
