package probe

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"db26/internal/headers"
	"github.com/valyala/fasthttp"
)

// Client wraps a fasthttp.Client configured for data bouncing probes.
type Client struct {
	http  *fasthttp.Client
	https *fasthttp.Client
}

// NewClient creates a probe client with the given timeout.
// Fire-and-forget design: short write timeout to send headers fast,
// minimal read timeout since we mostly don't care about responses.
func NewClient(timeoutSecs int) *Client {
	writeTimeout := time.Duration(timeoutSecs) * time.Second
	// Read timeout is short — we only need the response for auth detection
	// If we miss a few auth headers, that's fine. Speed > completeness here.
	readTimeout := 500 * time.Millisecond

	httpClient := &fasthttp.Client{
		MaxConnsPerHost:          4,
		MaxIdleConnDuration:      5 * time.Second,
		ReadTimeout:              readTimeout,
		WriteTimeout:             writeTimeout,
		MaxResponseBodySize:      1024, // Only need response headers
		NoDefaultUserAgentHeader: true,
	}

	httpsClient := &fasthttp.Client{
		MaxConnsPerHost:          4,
		MaxIdleConnDuration:      5 * time.Second,
		ReadTimeout:              readTimeout,
		WriteTimeout:             writeTimeout,
		MaxResponseBodySize:      1024,
		NoDefaultUserAgentHeader: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &Client{
		http:  httpClient,
		https: httpsClient,
	}
}

// Send dispatches an HTTP probe to the given domain with all data bouncing headers.
// Fire-and-forget: the headers trigger DNS lookups on the target regardless of
// whether we read the full response. This method is goroutine-safe.
func (c *Client) Send(domain string, protocol string, payloads []headers.HeaderPayload) Result {
	start := time.Now()

	var scheme string
	var client *fasthttp.Client
	switch protocol {
	case "https":
		scheme = "https"
		client = c.https
	default:
		scheme = "http"
		client = c.http
	}

	url := fmt.Sprintf("%s://%s/", scheme, domain)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("GET")

	// Inject all data bouncing headers
	for _, p := range payloads {
		if strings.EqualFold(p.Name, "Host") {
			req.SetHost(p.Value)
		} else {
			req.Header.Set(p.Name, p.Value)
		}
	}

	// Fire the request — we mostly care that headers were SENT,
	// not that we got a clean response back
	err := client.Do(req, resp)
	dur := time.Since(start)

	if err != nil {
		// Even on error, the headers may have been sent and processed.
		// Timeout errors are expected and fine — the DNS lookup
		// happens on the target's side when it processes our headers.
		return NewResult(domain, protocol, 0, nil, err, start, dur)
	}

	// Extract response headers for auth detection (opportunistic)
	respHeaders := extractResponseHeaders(resp)

	return NewResult(domain, protocol, resp.StatusCode(), respHeaders, nil, start, dur)
}

// extractResponseHeaders pulls relevant headers from the response.
func extractResponseHeaders(resp *fasthttp.Response) map[string]string {
	hdrs := make(map[string]string)

	interesting := []string{
		"Www-Authenticate",
		"Server",
		"X-Powered-By",
	}

	for _, name := range interesting {
		val := resp.Header.Peek(name)
		if len(val) > 0 {
			hdrs[name] = string(val)
		}
	}

	return hdrs
}
