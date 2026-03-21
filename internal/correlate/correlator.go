package correlate

import (
	"sync"
	"time"

	"db26/internal/callback"
	"db26/internal/metrics"
)

// DomainResult is an immutable record of a viable domain with its callback details.
type DomainResult struct {
	Domain    string          // Sanitized domain (e.g. "example-com")
	Headers   []string        // Which header prefixes triggered callbacks
	Protocols []string        // Which protocols were seen (dns, http, https)
	Events    []callback.Event // All callback events for this domain
	FirstSeen time.Time       // When the first callback arrived
	LastSeen  time.Time       // When the most recent callback arrived
}

// Correlator matches incoming callback events to probed domains.
// It maintains an internal map of domains that have received callbacks
// and tracks which headers triggered them.
type Correlator struct {
	mu      sync.Mutex
	domains map[string]*domainState
	metrics *metrics.Counters
	notify  chan<- DomainResult // Notifies when a new domain is first seen
}

// domainState tracks internal mutable state per domain. Only accessed under lock.
type domainState struct {
	headers   map[string]bool
	protocols map[string]bool
	events    []callback.Event
	firstSeen time.Time
	lastSeen  time.Time
}

// NewCorrelator creates a correlator that notifies on the given channel
// whenever a new viable domain is discovered.
func NewCorrelator(notify chan<- DomainResult, m *metrics.Counters) *Correlator {
	return &Correlator{
		domains: make(map[string]*domainState),
		metrics: m,
		notify:  notify,
	}
}

// Handle processes a callback event, correlating it with probed domains.
// This method is goroutine-safe.
func (c *Correlator) Handle(event callback.Event) {
	if event.Domain == "" {
		return
	}

	c.mu.Lock()

	state, exists := c.domains[event.Domain]
	if !exists {
		// New viable domain discovered
		state = &domainState{
			headers:   make(map[string]bool),
			protocols: make(map[string]bool),
			firstSeen: event.Timestamp,
		}
		c.domains[event.Domain] = state
		c.metrics.IncViableDomains()
	}

	state.lastSeen = event.Timestamp
	state.events = append(state.events, event)

	if event.Prefix != "" {
		state.headers[event.Prefix] = true
	}
	state.protocols[event.Protocol] = true

	// Take a snapshot while we hold the lock
	result := c.snapshot(event.Domain, state)

	c.mu.Unlock()

	// Notify about the updated domain (non-blocking)
	if !exists {
		select {
		case c.notify <- result:
		default:
		}
	}
}

// Results returns an immutable snapshot of all discovered viable domains.
func (c *Correlator) Results() []DomainResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	results := make([]DomainResult, 0, len(c.domains))
	for domain, state := range c.domains {
		results = append(results, c.snapshot(domain, state))
	}
	return results
}

// Count returns the number of unique viable domains discovered.
func (c *Correlator) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.domains)
}

// snapshot creates an immutable DomainResult from internal state.
// Must be called with c.mu held.
func (c *Correlator) snapshot(domain string, state *domainState) DomainResult {
	hdrs := make([]string, 0, len(state.headers))
	for h := range state.headers {
		hdrs = append(hdrs, h)
	}

	protos := make([]string, 0, len(state.protocols))
	for p := range state.protocols {
		protos = append(protos, p)
	}

	events := make([]callback.Event, len(state.events))
	copy(events, state.events)

	return DomainResult{
		Domain:    domain,
		Headers:   hdrs,
		Protocols: protos,
		Events:    events,
		FirstSeen: state.firstSeen,
		LastSeen:  state.lastSeen,
	}
}
