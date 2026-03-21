package callback

import (
	"fmt"
	"strings"
	"time"

	"db26/internal/metrics"
)

// Handler processes raw interactsh interactions and emits parsed Events.
// It wraps the interactsh client polling callback.
type Handler struct {
	events  chan<- Event
	metrics *metrics.Counters
}

// NewHandler creates a callback handler that sends parsed events to the given channel.
func NewHandler(events chan<- Event, m *metrics.Counters) *Handler {
	return &Handler{
		events:  events,
		metrics: m,
	}
}

// OnInteraction is called by the interactsh client for each interaction.
// It parses the interaction into an Event and sends it to the events channel.
// This function is goroutine-safe (called from the polling goroutine).
//
// Parameters match the interactsh Interaction struct fields:
//   - protocol: "dns", "http", "https", "smtp", "ldap", "smb", "ftp"
//   - fullID: the full interaction ID including prefix and domain
//   - remoteAddr: source IP
//   - qType: DNS query type (empty for non-DNS)
//   - rawData: full interaction payload
//   - ts: when the server recorded the interaction
func (h *Handler) OnInteraction(protocol, fullID, remoteAddr, qType, rawData string, ts time.Time) {
	// Parse prefix and domain from the fullID
	prefix, domain := parseFullID(fullID)

	event := Event{
		Protocol:      protocol,
		FullID:        fullID,
		Prefix:        prefix,
		Domain:        domain,
		RemoteAddress: remoteAddr,
		QType:         qType,
		RawData:       rawData,
		Timestamp:     ts,
	}

	// Update metrics based on protocol
	switch protocol {
	case "dns":
		h.metrics.IncCallbackDNS()
	case "http":
		h.metrics.IncCallbackHTTP()
	case "https":
		h.metrics.IncCallbackHTTPS()
	}

	// Non-blocking send — if the channel is full, log and skip
	select {
	case h.events <- event:
	default:
		fmt.Printf("[WARN] callback channel full, dropping event for %s\n", fullID)
	}
}

// parseFullID extracts the prefix and sanitized domain from an interactsh FullId.
// The FullId format is: "prefix.sanitized-domain.{correlationID}{nonce}"
// where correlationID+nonce are alphanumeric characters appended by interactsh.
//
// Example: "xff.example-com.abc123def456" → prefix="xff", domain="example-com"
func parseFullID(fullID string) (prefix, domain string) {
	// Split on dots
	parts := strings.Split(fullID, ".")

	if len(parts) < 2 {
		return "", fullID
	}

	// First part is the prefix (header identifier)
	prefix = parts[0]

	// Check if this prefix matches one of our known header prefixes
	if !isKnownPrefix(prefix) {
		// Might not be from our probes, return raw
		return "", fullID
	}

	// Second part is the sanitized domain
	// Everything after is correlationID, nonce, server domain parts
	domain = parts[1]

	return prefix, domain
}

// isKnownPrefix checks if the prefix matches one of our header correlation prefixes.
func isKnownPrefix(p string) bool {
	known := map[string]bool{
		"host":    true,
		"xff":     true,
		"wafp":    true,
		"contact": true,
		"rip":     true,
		"trip":    true,
		"xclip":   true,
		"ff":      true,
		"origip":  true,
		"clip":    true,
		"ref":     true,
		"from":    true,
		"origin":  true,
		"ua":      true,
		"n0x00":   true,
	}
	return known[p]
}
