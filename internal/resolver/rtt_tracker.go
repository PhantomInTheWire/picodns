package resolver

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/obs"
)

// rttTracker tracks nameserver response times.
type rttTracker struct {
	mu       sync.RWMutex
	rtts     map[string]time.Duration
	timeouts map[string]uint32
	cooldown map[string]time.Time
	dirty    atomic.Bool

	tracers struct {
		update   *obs.FuncTracer
		timeout  *obs.FuncTracer
		get      *obs.FuncTracer
		sortBest *obs.FuncTracer
	}
}

func newRTTTracker(parent *obs.FuncTracer) *rttTracker {
	t := &rttTracker{
		rtts:     make(map[string]time.Duration),
		timeouts: make(map[string]uint32),
		cooldown: make(map[string]time.Time),
	}

	t.tracers.update = obs.NewFuncTracer("rttTracker.Update", parent)
	t.tracers.timeout = obs.NewFuncTracer("rttTracker.Timeout", parent)
	t.tracers.get = obs.NewFuncTracer("rttTracker.Get", parent)
	t.tracers.sortBest = obs.NewFuncTracer("rttTracker.SortBest", parent)

	obs.GlobalRegistry.Register(t.tracers.update)
	obs.GlobalRegistry.Register(t.tracers.timeout)
	obs.GlobalRegistry.Register(t.tracers.get)
	obs.GlobalRegistry.Register(t.tracers.sortBest)

	return t
}

func (t *rttTracker) Update(ctx context.Context, server string, d time.Duration) {
	defer t.tracers.update.Trace()()

	t.mu.Lock()
	if len(t.rtts) > maxRTTTrackerEntries {
		for k := range t.rtts {
			delete(t.rtts, k)
			delete(t.timeouts, k)
			delete(t.cooldown, k)
			break
		}
	}
	prev, ok := t.rtts[server]
	if !ok {
		t.rtts[server] = d
	} else {
		t.rtts[server] = (prev*4 + d) / 5
	}
	delete(t.timeouts, server)
	delete(t.cooldown, server)
	t.mu.Unlock()
	t.dirty.Store(true)
}

func (t *rttTracker) Timeout(ctx context.Context, server string) {
	defer t.tracers.timeout.Trace()()

	t.mu.Lock()
	if len(t.timeouts) > maxRTTTrackerEntries {
		for k := range t.timeouts {
			delete(t.timeouts, k)
			delete(t.cooldown, k)
			break
		}
	}
	count := t.timeouts[server] + 1
	if count < 1 {
		count = 1
	}
	if count > 6 {
		count = 6
	}
	backoff := baseTimeoutBackoff << (count - 1)
	if backoff > maxTimeoutBackoff {
		backoff = maxTimeoutBackoff
	}
	t.timeouts[server] = count
	t.cooldown[server] = time.Now().Add(backoff)
	t.mu.Unlock()
}

func (t *rttTracker) Get(ctx context.Context, server string) time.Duration {
	defer t.tracers.get.Trace()()

	t.mu.RLock()
	defer t.mu.RUnlock()
	d, ok := t.rtts[server]
	if !ok {
		return unknownRTT
	}
	return d
}

func (t *rttTracker) SortBest(ctx context.Context, servers []string, n int) []string {
	defer t.tracers.sortBest.Trace()()

	if len(servers) <= 1 {
		return servers
	}
	if n <= 0 {
		return nil
	}
	if n > len(servers) {
		n = len(servers)
	}

	now := time.Now()
	var candidates []string

	t.mu.RLock()
	for _, srv := range servers {
		if until, ok := t.cooldown[srv]; ok && until.After(now) {
			continue
		}
		candidates = append(candidates, srv)
	}
	if len(candidates) == 0 {
		candidates = servers
	}

	type serverRTT struct {
		name string
		rtt  time.Duration
	}

	best := make([]serverRTT, 0, n)
	var maxIdx int
	var maxRTT time.Duration

	for _, srv := range candidates {
		rtt, ok := t.rtts[srv]
		if !ok {
			rtt = unknownRTT
		}

		if len(best) < n {
			best = append(best, serverRTT{name: srv, rtt: rtt})
			if rtt > maxRTT {
				maxRTT = rtt
				maxIdx = len(best) - 1
			}
		} else if rtt < maxRTT {
			best[maxIdx] = serverRTT{name: srv, rtt: rtt}
			maxRTT = best[0].rtt
			maxIdx = 0
			for i := 1; i < len(best); i++ {
				if best[i].rtt > maxRTT {
					maxRTT = best[i].rtt
					maxIdx = i
				}
			}
		}
	}

	for i := 0; i < len(best)-1; i++ {
		for j := i + 1; j < len(best); j++ {
			if best[j].rtt < best[i].rtt {
				best[i], best[j] = best[j], best[i]
			}
		}
	}

	t.mu.RUnlock()

	result := make([]string, len(best))
	for i, s := range best {
		result[i] = s.name
	}
	return result
}
