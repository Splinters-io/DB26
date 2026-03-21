package correlate

import (
	"testing"
	"time"

	"db26/internal/callback"
	"db26/internal/metrics"
)

func TestCorrelatorNewDomain(t *testing.T) {
	m := metrics.New()
	viableCh := make(chan DomainResult, 10)
	corr := NewCorrelator(viableCh, m)

	event := callback.Event{
		Protocol:      "dns",
		FullID:        "xff.example-com.abc123",
		Prefix:        "xff",
		Domain:        "example-com",
		RemoteAddress: "1.2.3.4",
		QType:         "A",
		Timestamp:     time.Now(),
	}

	corr.Handle(event)

	// Should have received a notification
	select {
	case result := <-viableCh:
		if result.Domain != "example-com" {
			t.Errorf("domain = %q, want example-com", result.Domain)
		}
		if len(result.Headers) != 1 || result.Headers[0] != "xff" {
			t.Errorf("headers = %v, want [xff]", result.Headers)
		}
	default:
		t.Error("expected notification on viable channel")
	}

	if corr.Count() != 1 {
		t.Errorf("count = %d, want 1", corr.Count())
	}

	snap := m.Snap()
	if snap.ViableDomains != 1 {
		t.Errorf("metrics.ViableDomains = %d, want 1", snap.ViableDomains)
	}
}

func TestCorrelatorMultipleHeaders(t *testing.T) {
	m := metrics.New()
	viableCh := make(chan DomainResult, 10)
	corr := NewCorrelator(viableCh, m)

	ts := time.Now()

	// First callback - xff header
	corr.Handle(callback.Event{
		Protocol: "dns", Prefix: "xff", Domain: "test-org",
		Timestamp: ts,
	})
	<-viableCh // Drain first notification

	// Second callback - host header, same domain
	corr.Handle(callback.Event{
		Protocol: "dns", Prefix: "host", Domain: "test-org",
		Timestamp: ts.Add(time.Second),
	})

	// Third callback - HTTP protocol
	corr.Handle(callback.Event{
		Protocol: "http", Prefix: "ref", Domain: "test-org",
		Timestamp: ts.Add(2 * time.Second),
	})

	// Should still be one domain
	if corr.Count() != 1 {
		t.Errorf("count = %d, want 1", corr.Count())
	}

	results := corr.Results()
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}

	r := results[0]
	if len(r.Headers) != 3 {
		t.Errorf("headers count = %d, want 3", len(r.Headers))
	}
	if len(r.Protocols) != 2 {
		t.Errorf("protocols count = %d, want 2 (dns, http)", len(r.Protocols))
	}
	if len(r.Events) != 3 {
		t.Errorf("events count = %d, want 3", len(r.Events))
	}
}

func TestCorrelatorMultipleDomains(t *testing.T) {
	m := metrics.New()
	viableCh := make(chan DomainResult, 10)
	corr := NewCorrelator(viableCh, m)

	domains := []string{"domain-a", "domain-b", "domain-c"}
	for _, d := range domains {
		corr.Handle(callback.Event{
			Protocol: "dns", Prefix: "xff", Domain: d,
			Timestamp: time.Now(),
		})
	}

	if corr.Count() != 3 {
		t.Errorf("count = %d, want 3", corr.Count())
	}

	// Drain notifications
	for range 3 {
		<-viableCh
	}
}

func TestCorrelatorEmptyDomain(t *testing.T) {
	m := metrics.New()
	viableCh := make(chan DomainResult, 10)
	corr := NewCorrelator(viableCh, m)

	// Event with empty domain should be ignored
	corr.Handle(callback.Event{
		Protocol: "dns", Domain: "",
		Timestamp: time.Now(),
	})

	if corr.Count() != 0 {
		t.Errorf("count = %d, want 0", corr.Count())
	}
}

func TestResultsImmutability(t *testing.T) {
	m := metrics.New()
	viableCh := make(chan DomainResult, 10)
	corr := NewCorrelator(viableCh, m)

	corr.Handle(callback.Event{
		Protocol: "dns", Prefix: "xff", Domain: "test-org",
		Timestamp: time.Now(),
	})
	<-viableCh

	results1 := corr.Results()

	// Add another event
	corr.Handle(callback.Event{
		Protocol: "http", Prefix: "host", Domain: "test-org",
		Timestamp: time.Now(),
	})

	results2 := corr.Results()

	// results1 should still show 1 event
	if len(results1[0].Events) != 1 {
		t.Errorf("results1 events = %d, want 1 (should be immutable)", len(results1[0].Events))
	}
	// results2 should show 2 events
	if len(results2[0].Events) != 2 {
		t.Errorf("results2 events = %d, want 2", len(results2[0].Events))
	}
}
