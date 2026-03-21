package metrics

import (
	"sync/atomic"
	"time"
)

// Counters tracks all recruiter metrics using atomic operations.
// All methods are goroutine-safe. Reads return immutable snapshots.
type Counters struct {
	probesSent    atomic.Int64
	probesHTTPOK  atomic.Int64
	probesHTTPSOK atomic.Int64
	probesErrors  atomic.Int64
	callbackDNS   atomic.Int64
	callbackHTTP  atomic.Int64
	callbackHTTPS atomic.Int64
	authNTLM      atomic.Int64
	authBasic     atomic.Int64
	authNegotiate atomic.Int64
	viableDomains atomic.Int64
	startTime     time.Time
}

// Snapshot is an immutable point-in-time view of all counters.
type Snapshot struct {
	ProbesSent    int64
	ProbesHTTPOK  int64
	ProbesHTTPSOK int64
	ProbesErrors  int64
	CallbackDNS   int64
	CallbackHTTP  int64
	CallbackHTTPS int64
	CallbackTotal int64
	AuthNTLM      int64
	AuthBasic     int64
	AuthNegotiate int64
	AuthTotal     int64
	ViableDomains int64
	Elapsed       time.Duration
	RPS           float64
}

// New creates a new Counters instance with the start time set to now.
func New() *Counters {
	return &Counters{
		startTime: time.Now(),
	}
}

// Increment methods — each returns nothing, fire-and-forget.
func (c *Counters) IncProbesSent()    { c.probesSent.Add(1) }
func (c *Counters) IncProbesHTTPOK()  { c.probesHTTPOK.Add(1) }
func (c *Counters) IncProbesHTTPSOK() { c.probesHTTPSOK.Add(1) }
func (c *Counters) IncProbesErrors()  { c.probesErrors.Add(1) }
func (c *Counters) IncCallbackDNS()   { c.callbackDNS.Add(1) }
func (c *Counters) IncCallbackHTTP()  { c.callbackHTTP.Add(1) }
func (c *Counters) IncCallbackHTTPS() { c.callbackHTTPS.Add(1) }
func (c *Counters) IncAuthNTLM()      { c.authNTLM.Add(1) }
func (c *Counters) IncAuthBasic()     { c.authBasic.Add(1) }
func (c *Counters) IncAuthNegotiate() { c.authNegotiate.Add(1) }
func (c *Counters) IncViableDomains() { c.viableDomains.Add(1) }

// Snap returns an immutable snapshot of all current counter values.
func (c *Counters) Snap() Snapshot {
	elapsed := time.Since(c.startTime)
	sent := c.probesSent.Load()
	cbDNS := c.callbackDNS.Load()
	cbHTTP := c.callbackHTTP.Load()
	cbHTTPS := c.callbackHTTPS.Load()
	authNTLM := c.authNTLM.Load()
	authBasic := c.authBasic.Load()
	authNeg := c.authNegotiate.Load()

	var rps float64
	if elapsed.Seconds() > 0 {
		rps = float64(sent) / elapsed.Seconds()
	}

	return Snapshot{
		ProbesSent:    sent,
		ProbesHTTPOK:  c.probesHTTPOK.Load(),
		ProbesHTTPSOK: c.probesHTTPSOK.Load(),
		ProbesErrors:  c.probesErrors.Load(),
		CallbackDNS:   cbDNS,
		CallbackHTTP:  cbHTTP,
		CallbackHTTPS: cbHTTPS,
		CallbackTotal: cbDNS + cbHTTP + cbHTTPS,
		AuthNTLM:      authNTLM,
		AuthBasic:     authBasic,
		AuthNegotiate: authNeg,
		AuthTotal:     authNTLM + authBasic + authNeg,
		ViableDomains: c.viableDomains.Load(),
		Elapsed:       elapsed,
		RPS:           rps,
	}
}
