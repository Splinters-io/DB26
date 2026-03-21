# Cloudflare DNS Setup for oob.yourdomain.com

## Required DNS Records

Log into Cloudflare dashboard for `yourdomain.com` and add these records.
**CRITICAL**: Both must be "DNS only" (grey cloud icon), NOT proxied.

| Type | Name | Content | Proxy | TTL |
|------|------|---------|-------|-----|
| A | `ns1` | `<YOUR_VPS_IP>` | DNS only | 300 |
| NS | `oob` | `ns1.yourdomain.com` | DNS only | 300 |

## What this does

1. The `A` record tells the internet that `ns1.yourdomain.com` resolves to `<YOUR_VPS_IP>` (VPS IP)
2. The `NS` record delegates all DNS queries for `*.oob.yourdomain.com` to `ns1.yourdomain.com`
3. When anyone resolves `anything.oob.yourdomain.com`, the query goes to `<YOUR_VPS_IP>:53`
4. interactsh-server on the VPS answers these queries and logs the interactions

## Verification

After adding records, wait 2-5 minutes for propagation, then test:

```bash
# From any machine:
dig ns1.yourdomain.com
# Should return A record: <YOUR_VPS_IP>

dig NS oob.yourdomain.com
# Should return NS record: ns1.yourdomain.com

# Test interactsh is responding:
dig test123.oob.yourdomain.com @<YOUR_VPS_IP>
# Should get a response (interactsh answers all queries)
```

## Troubleshooting

- **No response**: Check VPS firewall allows port 53 UDP+TCP
- **SERVFAIL**: systemd-resolved may still be running on VPS (conflicts on port 53)
- **NXDOMAIN on oob.yourdomain.com**: NS record propagation can take up to 48h (usually 5min)
- **Cloudflare proxy warning**: NS and A records for this MUST NOT be proxied (orange cloud)
