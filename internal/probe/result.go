package probe

import "time"

// Result is an immutable record of a single HTTP probe attempt.
type Result struct {
	Domain     string
	Protocol   string // "http" or "https"
	StatusCode int
	Headers    map[string]string // Response headers (copy, not reference)
	Error      string           // Empty if no error
	Timestamp  time.Time
	Duration   time.Duration
}

// NewResult creates an immutable Result. Headers are copied defensively.
func NewResult(domain, protocol string, statusCode int, headers map[string]string, err error, ts time.Time, dur time.Duration) Result {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}

	// Defensive copy of headers map
	hdrs := make(map[string]string, len(headers))
	for k, v := range headers {
		hdrs[k] = v
	}

	return Result{
		Domain:     domain,
		Protocol:   protocol,
		StatusCode: statusCode,
		Headers:    hdrs,
		Error:      errStr,
		Timestamp:  ts,
		Duration:   dur,
	}
}

// IsSuccess returns true if the probe got a response (any status code).
func (r Result) IsSuccess() bool {
	return r.Error == ""
}

// HasAuthChallenge returns true if the response contains a WWW-Authenticate header.
func (r Result) HasAuthChallenge() bool {
	_, ok := r.Headers["Www-Authenticate"]
	return ok
}
