package worker

import (
	"context"
	"sync"

	"db26/internal/headers"
	"db26/internal/metrics"
	"db26/internal/probe"
	"golang.org/x/time/rate"
)

// Pool manages a fixed-size pool of goroutine workers that probe domains.
type Pool struct {
	workers int
	limiter *rate.Limiter
	client  *probe.Client
	metrics *metrics.Counters
}

// NewPool creates a worker pool with the given concurrency and rate limit.
func NewPool(workers, rps int, client *probe.Client, m *metrics.Counters) *Pool {
	return &Pool{
		workers: workers,
		limiter: rate.NewLimiter(rate.Limit(rps), rps/10+1), // Burst = 10% of RPS
		client:  client,
		metrics: m,
	}
}

// ProbeJob is a domain to probe with its pre-built header payloads.
type ProbeJob struct {
	Domain   string
	Payloads []headers.HeaderPayload
}

// ResultPair holds HTTP and optional HTTPS results for a single domain.
type ResultPair struct {
	HTTP  probe.Result
	HTTPS *probe.Result // nil if HTTPS not probed
}

// Run starts all workers, reads jobs from the input channel, and sends results
// to the output channel. Blocks until all jobs are processed.
// The caller must close the jobs channel when all domains are queued.
func (p *Pool) Run(ctx context.Context, jobs <-chan ProbeJob, results chan<- ResultPair, probeHTTPS bool) {
	var wg sync.WaitGroup

	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.worker(ctx, jobs, results, probeHTTPS)
		}()
	}

	wg.Wait()
}

func (p *Pool) worker(ctx context.Context, jobs <-chan ProbeJob, results chan<- ResultPair, probeHTTPS bool) {
	for job := range jobs {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Rate limit
		if err := p.limiter.Wait(ctx); err != nil {
			return // Context cancelled
		}

		// HTTP probe
		httpResult := p.client.Send(job.Domain, "http", job.Payloads)
		p.metrics.IncProbesSent()

		if httpResult.IsSuccess() {
			p.metrics.IncProbesHTTPOK()
		} else {
			p.metrics.IncProbesErrors()
		}

		pair := ResultPair{HTTP: httpResult}

		// HTTPS probe (if enabled)
		if probeHTTPS {
			// Rate limit again for the second request
			if err := p.limiter.Wait(ctx); err != nil {
				results <- pair
				return
			}

			httpsResult := p.client.Send(job.Domain, "https", job.Payloads)
			p.metrics.IncProbesSent()

			if httpsResult.IsSuccess() {
				p.metrics.IncProbesHTTPSOK()
			} else {
				p.metrics.IncProbesErrors()
			}

			pair.HTTPS = &httpsResult
		}

		results <- pair
	}
}
