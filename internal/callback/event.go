package callback

import (
	"strings"
	"time"
)

// Event is an immutable record of an OOB interaction received from interactsh.
type Event struct {
	Protocol      string    // "dns", "http", "https", "smtp", "ldap", "smb", "ftp"
	FullID        string    // Raw FullId from interactsh
	Prefix        string    // Parsed header prefix (e.g. "xff", "host")
	Domain        string    // Parsed sanitized domain (e.g. "example-com")
	RemoteAddress string    // Source IP of the interaction
	QType         string    // DNS query type (e.g. "A", "AAAA") — empty for non-DNS
	RawData       string    // Full interaction data (HTTP request dump, etc.)
	Timestamp     time.Time // When the interaction was received
}

// IsDNS returns true if this is a DNS callback.
func (e Event) IsDNS() bool {
	return e.Protocol == "dns"
}

// IsHTTP returns true if this is an HTTP callback.
func (e Event) IsHTTP() bool {
	return e.Protocol == "http"
}

// IsHTTPS returns true if this is an HTTPS callback.
func (e Event) IsHTTPS() bool {
	return e.Protocol == "https"
}

// UnsanitizedDomain converts the sanitized domain back to dotted form.
// Uses "--" → "." reversal so original hyphens are preserved.
// e.g. "my-site--com" → "my-site.com"
func (e Event) UnsanitizedDomain() string {
	return strings.ReplaceAll(e.Domain, "--", ".")
}
