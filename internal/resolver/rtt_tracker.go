package resolver

import (
	"context"
	"sync"
	"time"

	"picodns/internal/obs"
)

type rttTracker struct {
	mu       sync.Mutex
	rtts     map[string]time.Duration
	timeouts map[string]uint32
	cooldown map[string]time.Time

	tracers struct {
		update   *obs.FuncTracer
		failure  *obs.FuncTracer
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
	t.tracers.failure = obs.NewFuncTracer("rttTracker.Failure", parent)
	t.tracers.get = obs.NewFuncTracer("rttTracker.Get", parent)
	t.tracers.sortBest = obs.NewFuncTracer("rttTracker.SortBest", parent)

	obs.GlobalRegistry.Register(t.tracers.update)
	obs.GlobalRegistry.Register(t.tracers.failure)
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
}

func (t *rttTracker) Failure(ctx context.Context, server string) {
	defer t.tracers.failure.Trace()()

	t.mu.Lock()
	if len(t.timeouts) > maxRTTTrackerEntries {
		for k := range t.timeouts {
			delete(t.timeouts, k)
			delete(t.cooldown, k)
			break
		}
	}
	count := t.timeouts[server] + 1
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

func (t *rttTracker) Get(ctx context.Context, server string) (time.Duration, bool) {
	defer t.tracers.get.Trace()()

	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.rtts[server]
	if !ok {
		return unknownRTT, false
	}
	return d, true
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

	type serverRTT struct {
		name string
		rtt  time.Duration
	}

	// Collect candidates under lock, then sort outside.
	candidates := make([]serverRTT, 0, len(servers))

	t.mu.Lock()
	for _, srv := range servers {
		if until, ok := t.cooldown[srv]; ok && until.After(now) {
			continue
		}
		rtt, ok := t.rtts[srv]
		if !ok {
			rtt = unknownRTT
		}
		candidates = append(candidates, serverRTT{name: srv, rtt: rtt})
	}
	if len(candidates) == 0 {
		for _, srv := range servers {
			rtt, ok := t.rtts[srv]
			if !ok {
				rtt = unknownRTT
			}
			candidates = append(candidates, serverRTT{name: srv, rtt: rtt})
		}
	}
	t.mu.Unlock()

	// Trivial bubble sort by RTT (ascending).
	for i := 0; i < len(candidates); i++ {
		swapped := false
		for j := 0; j+1 < len(candidates)-i; j++ {
			if candidates[j+1].rtt < candidates[j].rtt {
				candidates[j], candidates[j+1] = candidates[j+1], candidates[j]
				swapped = true
			}
		}
		if !swapped {
			break
		}
	}

	if n > len(candidates) {
		n = len(candidates)
	}
	result := make([]string, 0, n)
	for i := 0; i < n; i++ {
		result = append(result, candidates[i].name)
	}
	return result
}
