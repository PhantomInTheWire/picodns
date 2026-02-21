package resolver

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/obs"
	"picodns/internal/pool"
	"picodns/internal/types"
)

// Cached wraps a resolver with DNS response caching
type Cached struct {
	cache      *cache.Cache
	upstream   types.Resolver
	bufPool    *pool.Bytes
	Prefetch   bool
	ObsEnabled bool
	refreshing sync.Map
	inflightMu sync.Mutex
	inflight   map[uint64]*inflightCall
	clock      func() time.Time
	logger     *slog.Logger
	CacheHits  atomic.Uint64
	CacheMiss  atomic.Uint64

	// Function tracers for observability
	tracers struct {
		resolveFromCache *obs.FuncTracer
		resolve          *obs.FuncTracer
		getCachedWithKey *obs.FuncTracer
		acquireInflight  *obs.FuncTracer
		releaseInflight  *obs.FuncTracer
		setInflightErr   *obs.FuncTracer
		setCache         *obs.FuncTracer
		maybePrefetch    *obs.FuncTracer
		cacheKeyFromQ    *obs.FuncTracer
	}
}

type inflightCall struct {
	done chan struct{}
	err  error
}

func NewCached(cacheStore *cache.Cache, upstream types.Resolver) *Cached {
	c := &Cached{
		cache:    cacheStore,
		upstream: upstream,
		bufPool:  pool.DefaultPool,
		inflight: make(map[uint64]*inflightCall),
		clock:    time.Now,
		logger:   slog.Default(),
	}

	// Initialize tracers
	c.tracers.resolveFromCache = obs.NewFuncTracer("Cached.ResolveFromCache", nil)
	c.tracers.resolve = obs.NewFuncTracer("Cached.Resolve", nil)
	c.tracers.getCachedWithKey = obs.NewFuncTracer("Cached.getCachedWithMetadataKey", c.tracers.resolve)
	c.tracers.acquireInflight = obs.NewFuncTracer("Cached.acquireInflight", c.tracers.resolve)
	c.tracers.releaseInflight = obs.NewFuncTracer("Cached.releaseInflight", c.tracers.resolve)
	c.tracers.setInflightErr = obs.NewFuncTracer("Cached.setInflightErr", c.tracers.resolve)
	c.tracers.setCache = obs.NewFuncTracer("Cached.setCache", c.tracers.resolve)
	c.tracers.maybePrefetch = obs.NewFuncTracer("Cached.maybePrefetchKey", c.tracers.resolve)
	c.tracers.cacheKeyFromQ = obs.NewFuncTracer("cacheKeyFromQuestion", c.tracers.resolve)

	// Register with global registry
	obs.GlobalRegistry.Register(c.tracers.resolveFromCache)
	obs.GlobalRegistry.Register(c.tracers.resolve)
	obs.GlobalRegistry.Register(c.tracers.getCachedWithKey)
	obs.GlobalRegistry.Register(c.tracers.acquireInflight)
	obs.GlobalRegistry.Register(c.tracers.releaseInflight)
	obs.GlobalRegistry.Register(c.tracers.setInflightErr)
	obs.GlobalRegistry.Register(c.tracers.setCache)
	obs.GlobalRegistry.Register(c.tracers.maybePrefetch)
	obs.GlobalRegistry.Register(c.tracers.cacheKeyFromQ)

	return c
}

type CachedStatsSnapshot struct {
	Hits uint64
	Miss uint64
}

func (c *Cached) StatsSnapshot() CachedStatsSnapshot {
	return CachedStatsSnapshot{
		Hits: c.CacheHits.Load(),
		Miss: c.CacheMiss.Load(),
	}
}

func (c *Cached) ResolveFromCache(ctx context.Context, req []byte) ([]byte, func(), bool) {
	defer c.tracers.resolveFromCache.Trace()()

	if c.cache == nil {
		return nil, nil, false
	}
	hdr, err := dns.ReadHeader(req)
	if err != nil || hdr.QDCount == 0 {
		return nil, nil, false
	}
	key, _, _, _, compressed, err := dns.HashQuestionKeyFromWire(req, dns.HeaderLen)
	if err != nil || compressed {
		return nil, nil, false
	}
	resp, cleanup, _, _, _, ok := c.getCachedWithMetadataKey(ctx, key, hdr.ID, false)
	if ok {
		if c.ObsEnabled {
			c.CacheHits.Add(1)
		}
		return resp, cleanup, true
	}
	return nil, nil, false
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	defer c.tracers.resolve.Trace()()

	var start time.Time
	debugEnabled := c.logger != nil && c.logger.Enabled(ctx, slog.LevelDebug)
	if debugEnabled {
		start = time.Now()
	}

	// Fast path: avoid full parsing when we can.
	if c.cache != nil {
		hdr, hErr := dns.ReadHeader(req)
		if hErr == nil && hdr.QDCount > 0 {
			key, _, _, _, compressed, kErr := dns.HashQuestionKeyFromWire(req, dns.HeaderLen)
			if kErr == nil && !compressed {
				cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadataKey(ctx, key, hdr.ID, c.ObsEnabled)
				if ok {
					if c.ObsEnabled {
						c.CacheHits.Add(1)
					}
					if c.Prefetch && hits > prefetchThreshold {
						remaining := expires.Sub(c.clock())
						if remaining < origTTL/prefetchRemainingRatio {
							c.maybePrefetchKey(ctx, key, req)
						}
					}
					if debugEnabled {
						c.logger.Debug("dns cache hit", "duration", time.Since(start))
					}
					return cached, cleanup, nil
				}
			}
		}
	}

	reqMsg, err := dns.ReadMessagePooled(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}
	q := reqMsg.Questions[0]
	reqHeader := reqMsg.Header
	key := c.cacheKeyFromQuestion(ctx, q)

	cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadata(ctx, q, reqHeader.ID, c.ObsEnabled)
	if ok {
		if c.ObsEnabled {
			c.CacheHits.Add(1)
		}
		if c.Prefetch && hits > prefetchThreshold {
			remaining := expires.Sub(c.clock())
			if remaining < origTTL/prefetchRemainingRatio {
				c.maybePrefetchKey(ctx, key, req)
			}
		}
		if debugEnabled {
			c.logger.Debug("dns cache hit",
				"name", q.Name,
				"type", q.Type,
				"remaining", expires.Sub(c.clock()),
				"duration", time.Since(start))
		}
		reqMsg.Release()
		return cached, cleanup, nil
	}

	call, leader := c.acquireInflight(ctx, key)
	if !leader {
		reqMsg.Release()
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-call.done:
		}
		if cached, cleanup, _, _, _, ok := c.getCachedWithMetadataKey(ctx, key, reqHeader.ID, c.ObsEnabled); ok {
			if c.ObsEnabled {
				c.CacheHits.Add(1)
			}
			return cached, cleanup, nil
		}
		if c.ObsEnabled {
			c.CacheMiss.Add(1)
		}
		if call.err != nil {
			return nil, nil, call.err
		}
		return c.upstream.Resolve(ctx, req)
	}
	defer c.releaseInflight(ctx, key)

	if c.ObsEnabled {
		c.CacheMiss.Add(1)
	}

	resp, cleanupResp, err := c.upstream.Resolve(ctx, req)

	if err != nil {
		if debugEnabled {
			c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start), "error", err)
		}
		c.setInflightErr(ctx, key, err)
		reqMsg.Release()
		return resp, cleanupResp, err
	}

	vErr := dns.ValidateResponseWithRequest(reqHeader, reqMsg.Questions, resp)
	if vErr != nil {
		if vErr == dns.ErrIDMismatch || vErr == dns.ErrNotResponse {
			c.setInflightErr(ctx, key, vErr)
			reqMsg.Release()
			return resp, cleanupResp, vErr
		}
		if debugEnabled {
			c.logger.Debug("dns response validation mismatch; skip cache", "name", q.Name, "type", q.Type, "error", vErr)
		}
		c.setInflightErr(ctx, key, nil)
		reqMsg.Release()
		return resp, cleanupResp, nil
	}
	reqMsg.Release()

	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := cacheTTLForResponse(resp, *respMsg, q); ok {
			c.setCache(ctx, q, resp, ttl)
		}
		respMsg.Release()
	}

	setRAFlag(resp)

	if debugEnabled {
		c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start))
	}
	c.setInflightErr(ctx, key, nil)
	return resp, cleanupResp, nil
}

func (c *Cached) acquireInflight(ctx context.Context, key uint64) (*inflightCall, bool) {
	defer c.tracers.acquireInflight.Trace()()

	c.inflightMu.Lock()
	defer c.inflightMu.Unlock()
	if call, ok := c.inflight[key]; ok {
		return call, false
	}
	call := &inflightCall{done: make(chan struct{})}
	c.inflight[key] = call
	return call, true
}

func (c *Cached) setInflightErr(ctx context.Context, key uint64, err error) {
	defer c.tracers.setInflightErr.Trace()()

	c.inflightMu.Lock()
	call := c.inflight[key]
	if call != nil {
		call.err = err
	}
	c.inflightMu.Unlock()
}

func (c *Cached) releaseInflight(ctx context.Context, key uint64) {
	defer c.tracers.releaseInflight.Trace()()

	c.inflightMu.Lock()
	call := c.inflight[key]
	delete(c.inflight, key)
	c.inflightMu.Unlock()
	if call != nil {
		close(call.done)
	}
}

func (c *Cached) maybePrefetchKey(ctx context.Context, key uint64, req []byte) {
	defer c.tracers.maybePrefetch.Trace()()

	if _, loading := c.refreshing.LoadOrStore(key, true); loading {
		return
	}

	reqCopy := make([]byte, len(req))
	copy(reqCopy, req)

	go func() {
		defer c.refreshing.Delete(key)
		ctx, cancel := context.WithTimeout(context.Background(), prefetchTimeout)
		defer cancel()

		qMsg, qErr := dns.ReadMessagePooled(reqCopy)
		var q dns.Question
		if qErr == nil && len(qMsg.Questions) > 0 {
			q = qMsg.Questions[0]
		}
		if qErr == nil {
			qMsg.Release()
		}

		resp, cleanup, err := c.upstream.Resolve(ctx, reqCopy)
		if err == nil {
			if cleanup != nil {
				defer cleanup()
			}
			if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
				if (q != dns.Question{}) {
					if ttl, ok := cacheTTLForResponse(resp, *respMsg, q); ok {
						c.setCache(ctx, q, resp, ttl)
					}
				}
				respMsg.Release()
			}
		}
	}()
}

func (c *Cached) getCachedWithMetadata(ctx context.Context, q dns.Question, queryID uint16, sample bool) ([]byte, func(), time.Time, uint64, time.Duration, bool) {
	if c.cache == nil {
		return nil, nil, time.Time{}, 0, 0, false
	}
	key := c.cacheKeyFromQuestion(ctx, q)
	return c.getCachedWithMetadataKey(ctx, key, queryID, sample)
}

func (c *Cached) cacheKeyFromQuestion(ctx context.Context, q dns.Question) uint64 {
	defer c.tracers.cacheKeyFromQ.Trace()()

	q = q.Normalize()
	h := dns.HashNormalizedNameString(q.Name)
	h ^= uint64(q.Type) << 32
	h ^= uint64(q.Class)
	return h
}

func (c *Cached) getCachedWithMetadataKey(ctx context.Context, key uint64, queryID uint16, sample bool) ([]byte, func(), time.Time, uint64, time.Duration, bool) {
	defer c.tracers.getCachedWithKey.Trace()()

	cachedData, expires, hits, origTTL, ttlOffs, ok := c.cache.GetWithMetadataKey(key)
	if !ok || len(cachedData) < 4 {
		return nil, nil, time.Time{}, 0, 0, false
	}

	bufPtr := c.bufPool.Get()
	fromPool := true
	if cap(*bufPtr) < len(cachedData) {
		c.bufPool.Put(bufPtr)
		newBuf := make([]byte, len(cachedData))
		bufPtr = &newBuf
		fromPool = false
	}
	resp := (*bufPtr)[:len(cachedData)]
	copy(resp, cachedData)

	binary.BigEndian.PutUint16(resp[0:2], queryID)
	setRAFlag(resp)

	remaining := expires.Sub(c.clock())
	sec := uint32(0)
	if remaining > 0 {
		sec = uint32(remaining / time.Second)
	}
	if sec > 0 {
		if orig := uint32(origTTL / time.Second); orig == 0 || sec < orig {
			dns.RewriteTTLsAtOffsets(resp, sec, ttlOffs)
		}
	}

	cleanup := func() {
		if fromPool {
			c.bufPool.Put(bufPtr)
		}
	}

	return resp, cleanup, expires, hits, origTTL, true
}

func (c *Cached) setCache(ctx context.Context, q dns.Question, resp []byte, ttl time.Duration) {
	defer c.tracers.setCache.Trace()()

	if c.cache == nil || ttl <= 0 {
		return
	}

	c.cache.Set(q, resp, ttl)
}

// rttTracker tracks nameserver response times
type rttTracker struct {
	mu       sync.RWMutex
	rtts     map[string]time.Duration
	timeouts map[string]uint32
	cooldown map[string]time.Time
	dirty    atomic.Bool

	// Tracers
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
