package headers

import (
	"fmt"
	"strings"
)

// HeaderDef defines a single HTTP header to inject for data bouncing.
// Each header has a unique prefix used for correlation when callbacks arrive.
type HeaderDef struct {
	Name   string // HTTP header name (e.g. "X-Forwarded-For")
	Prefix string // Correlation prefix (e.g. "xff")
	Format string // fmt template: %s = prefix.domain.oob payload
}

// All returns the canonical set of 15 headers used for data bouncing probes.
// These match the headers from Unknown.sh (lines 89-105) and Nick Dunn's recruiter.py.
func All() []HeaderDef {
	return []HeaderDef{
		{Name: "Host", Prefix: "host", Format: "%s"},
		{Name: "X-Forwarded-For", Prefix: "xff", Format: "%s"},
		{Name: "X-Wap-Profile", Prefix: "wafp", Format: "http://%s/wap.xml"},
		{Name: "Contact", Prefix: "contact", Format: "root@%s"},
		{Name: "X-Real-IP", Prefix: "rip", Format: "%s"},
		{Name: "True-Client-IP", Prefix: "trip", Format: "%s"},
		{Name: "X-Client-IP", Prefix: "xclip", Format: "%s"},
		{Name: "Forwarded", Prefix: "ff", Format: "for=%s"},
		{Name: "X-Originating-IP", Prefix: "origip", Format: "%s"},
		{Name: "Client-IP", Prefix: "clip", Format: "%s"},
		{Name: "Referer", Prefix: "ref", Format: "%s"},
		{Name: "From", Prefix: "from", Format: "root@%s"},
		{Name: "Origin", Prefix: "origin", Format: "https://%s"},
		{Name: "User-Agent", Prefix: "ua", Format: "%s"},
		{Name: "n0x00", Prefix: "n0x00", Format: "%s"},
	}
}

// HeaderPayload is an immutable header name + value pair ready to inject.
type HeaderPayload struct {
	Name  string
	Value string
}

// Build constructs all header payloads for a given domain and OOB base domain.
// Returns an immutable slice of HeaderPayload structs.
//
// Example: Build("example.com", "abc123.oob.yourdomain.com")
// → X-Forwarded-For: xff.example-com.abc123.oob.yourdomain.com
func Build(domain, oobDomain string) []HeaderPayload {
	clean := CleanDomain(domain)
	defs := All()
	payloads := make([]HeaderPayload, 0, len(defs))

	for _, def := range defs {
		// Construct the subdomain: prefix.domain.oob-domain (dots preserved)
		subdomain := fmt.Sprintf("%s.%s.%s", def.Prefix, clean, oobDomain)

		// Validate DNS label constraints
		if !isValidDNSName(subdomain) {
			// Skip headers that would produce invalid DNS names for this domain
			continue
		}

		// Apply the format template
		value := fmt.Sprintf(def.Format, subdomain)
		payloads = append(payloads, HeaderPayload{
			Name:  def.Name,
			Value: value,
		})
	}

	return payloads
}

// CleanDomain strips protocol, path, port, and trailing dots from a domain.
// Dots are preserved — DNS handles them natively as label separators.
//   "example.com"           → "example.com"
//   "https://my-site.com/"  → "my-site.com"
func CleanDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

// SanitizeDomain is an alias for CleanDomain. Kept for backward compat.
func SanitizeDomain(domain string) string {
	return CleanDomain(domain)
}

// UnsanitizeDomain is a no-op — domains are no longer encoded.
func UnsanitizeDomain(sanitized string) string {
	return sanitized
}

// ParseCallbackID extracts the prefix and original domain from an interactsh callback FullId.
// FullId format: "prefix.sanitized-domain.{correlationID}{nonce}"
// Returns prefix, sanitized domain, and whether parsing succeeded.
func ParseCallbackID(fullID, oobDomain string) (prefix string, domain string, ok bool) {
	// Strip the OOB domain suffix
	oobSuffix := "." + oobDomain
	if !strings.HasSuffix(fullID, oobSuffix) {
		// Try without leading dot
		if !strings.Contains(fullID, oobDomain) {
			return "", "", false
		}
	}

	// Remove the OOB domain portion (correlationID + nonce + server domain)
	// The fullID from interactsh looks like: prefix.domain.{corrID}{nonce}
	// We need to find the prefix (first label) and domain (second label)
	parts := strings.SplitN(fullID, ".", 3)
	if len(parts) < 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// isValidDNSName checks that each label in the DNS name is within bounds.
// Max 63 chars per label, max 253 chars total.
func isValidDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 63 || len(label) == 0 {
			return false
		}
	}
	return true
}
