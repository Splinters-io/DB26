package metrics

import (
	"sync"
	"testing"
)

func TestCountersBasic(t *testing.T) {
	c := New()

	c.IncProbesSent()
	c.IncProbesSent()
	c.IncProbesHTTPOK()
	c.IncCallbackDNS()
	c.IncCallbackHTTP()
	c.IncCallbackHTTPS()
	c.IncAuthNTLM()
	c.IncAuthBasic()
	c.IncViableDomains()

	snap := c.Snap()

	if snap.ProbesSent != 2 {
		t.Errorf("ProbesSent = %d, want 2", snap.ProbesSent)
	}
	if snap.ProbesHTTPOK != 1 {
		t.Errorf("ProbesHTTPOK = %d, want 1", snap.ProbesHTTPOK)
	}
	if snap.CallbackDNS != 1 {
		t.Errorf("CallbackDNS = %d, want 1", snap.CallbackDNS)
	}
	if snap.CallbackTotal != 3 {
		t.Errorf("CallbackTotal = %d, want 3", snap.CallbackTotal)
	}
	if snap.AuthTotal != 2 {
		t.Errorf("AuthTotal = %d, want 2", snap.AuthTotal)
	}
	if snap.ViableDomains != 1 {
		t.Errorf("ViableDomains = %d, want 1", snap.ViableDomains)
	}
	if snap.Elapsed <= 0 {
		t.Error("Elapsed should be > 0")
	}
}

func TestCountersConcurrent(t *testing.T) {
	c := New()
	var wg sync.WaitGroup

	// Hammer counters from 100 goroutines
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.IncProbesSent()
				c.IncCallbackDNS()
			}
		}()
	}
	wg.Wait()

	snap := c.Snap()
	if snap.ProbesSent != 100000 {
		t.Errorf("ProbesSent = %d, want 100000", snap.ProbesSent)
	}
	if snap.CallbackDNS != 100000 {
		t.Errorf("CallbackDNS = %d, want 100000", snap.CallbackDNS)
	}
}

func TestSnapshotImmutability(t *testing.T) {
	c := New()
	c.IncProbesSent()

	snap1 := c.Snap()
	c.IncProbesSent()
	snap2 := c.Snap()

	// snap1 should not be affected by subsequent increments
	if snap1.ProbesSent != 1 {
		t.Errorf("snap1.ProbesSent = %d, want 1 (snapshot should be immutable)", snap1.ProbesSent)
	}
	if snap2.ProbesSent != 2 {
		t.Errorf("snap2.ProbesSent = %d, want 2", snap2.ProbesSent)
	}
}
