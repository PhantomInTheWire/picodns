package resolver

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"picodns/internal/dns"
)

func (r *Recursive) Warmup(ctx context.Context) {
	defer r.tracers.warmup.Trace()()

	r.logger.Info("warming up recursive resolver cache for common TLDs")
	infoEnabled := r.logger != nil && r.logger.Enabled(ctx, slog.LevelInfo)
	var start time.Time
	if infoEnabled {
		start = time.Now()
	}

	r.warmupRTT(ctx)

	jobs := make(chan string)
	var wg sync.WaitGroup

	workerCount := warmupParallelism
	if workerCount > len(commonTLDs) {
		workerCount = len(commonTLDs)
	}
	if workerCount <= 0 {
		workerCount = 1
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tld := range jobs {
				// Keep cancellation semantics for long-running warmup jobs.
				tctx, cancel := context.WithTimeout(ctx, warmupQueryTimeout)
				id := secureRandUint16()
				reqHeader := dns.Header{ID: id, QDCount: 1, Flags: dns.FlagRD}
				questions := []dns.Question{{Name: tld + ".", Type: dns.TypeNS, Class: dns.ClassIN}}

				resp, cleanup, _ := r.resolveIterative(tctx, reqHeader, questions, tld+".", 0, nil, nil, false)
				if cleanup != nil {
					cleanup()
				}
				_ = resp
				cancel()
			}
		}()
	}

	for _, tld := range commonTLDs {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			if infoEnabled {
				r.logger.Info("warmup canceled", "duration", time.Since(start))
			}
			return
		case jobs <- tld:
		}
		time.Sleep(warmupStagger)
	}
	close(jobs)
	wg.Wait()

	if infoEnabled {
		r.logger.Info("warmup complete", "duration", time.Since(start))
	}
}

func (r *Recursive) warmupRTT(ctx context.Context) {
	defer r.tracers.warmupRTT.Trace()()

	if r.transport == nil || len(r.rootServers) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, server := range r.rootServers {
		wg.Add(1)
		go func(srv string) {
			defer wg.Done()
			// Avoid per-query timeout context allocation; transport enforces timeout.
			tctx := ctx

			id := secureRandUint16()
			bufPtr := r.bufPool.Get()
			buf := *bufPtr
			n, err := dns.BuildQueryIntoWithEDNS(buf, id, ".", dns.TypeNS, dns.ClassIN, ednsUDPSize)
			if err != nil {
				r.bufPool.Put(bufPtr)
				return
			}
			query := buf[:n]
			startQ := time.Now()
			resp, cleanup, err := r.transport.Query(tctx, srv, query, warmupQueryTimeout)
			r.bufPool.Put(bufPtr)
			if err != nil {
				if cleanup != nil {
					cleanup()
				}
				return
			}
			if dns.ValidateResponseWithRequest(dns.Header{ID: id, QDCount: 1}, []dns.Question{{Name: ".", Type: dns.TypeNS, Class: dns.ClassIN}}, resp) == nil {
				r.rttTracker.Update(tctx, srv, time.Since(startQ))
			}
			if cleanup != nil {
				cleanup()
			}
		}(server)
		time.Sleep(warmupStagger)
	}
	wg.Wait()
}
