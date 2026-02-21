package resolver

import (
	"context"
	"encoding/binary"
	"log/slog"
	"strings"
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
	sample     atomic.Uint64

	parseReq   obs.DurationStat
	cacheGet   obs.DurationStat
	cacheCopy  obs.DurationStat
	upstreamDo obs.DurationStat
	validate   obs.DurationStat
	cacheSet   obs.DurationStat
	total      obs.DurationStat
}

const durationSampleMask = 0xFF // 1/256 samples

type inflightCall struct {
	done chan struct{}
	err  error
}

func NewCached(cacheStore *cache.Cache, upstream types.Resolver) *Cached {
	return &Cached{
		cache:    cacheStore,
		upstream: upstream,
		bufPool:  pool.DefaultPool,
		inflight: make(map[uint64]*inflightCall),
		clock:    time.Now,
		logger:   slog.Default(),
	}
}

type CachedStatsSnapshot struct {
	Hits uint64
	Miss uint64

	ParseReq  obs.DurationSnapshot
	CacheGet  obs.DurationSnapshot
	CacheCopy obs.DurationSnapshot
	Upstream  obs.DurationSnapshot
	Validate  obs.DurationSnapshot
	CacheSet  obs.DurationSnapshot
	Total     obs.DurationSnapshot
}

func (c *Cached) StatsSnapshot() CachedStatsSnapshot {
	return CachedStatsSnapshot{
		Hits:      c.CacheHits.Load(),
		Miss:      c.CacheMiss.Load(),
		ParseReq:  c.parseReq.Snapshot(),
		CacheGet:  c.cacheGet.Snapshot(),
		CacheCopy: c.cacheCopy.Snapshot(),
		Upstream:  c.upstreamDo.Snapshot(),
		Validate:  c.validate.Snapshot(),
		CacheSet:  c.cacheSet.Snapshot(),
		Total:     c.total.Snapshot(),
	}
}

func (c *Cached) ResolveFromCache(req []byte) ([]byte, func(), bool) {
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
	resp, cleanup, _, _, _, ok := c.getCachedWithMetadataKey(key, hdr.ID, false)
	if ok {
		if c.ObsEnabled {
			c.CacheHits.Add(1)
		}
		return resp, cleanup, true
	}
	return nil, nil, false
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	var start time.Time
	debugEnabled := c.logger != nil && c.logger.Enabled(ctx, slog.LevelDebug)
	if debugEnabled {
		start = time.Now()
	}
	sample := c.ObsEnabled && (c.sample.Add(1)&durationSampleMask) == 0
	var totalStart time.Time
	var parseStart time.Time
	if sample {
		totalStart = time.Now()
		parseStart = totalStart
	}
	// Fast path: avoid full parsing when we can.
	if c.cache != nil {
		hdr, hErr := dns.ReadHeader(req)
		if hErr == nil && hdr.QDCount > 0 {
			key, _, _, _, compressed, kErr := dns.HashQuestionKeyFromWire(req, dns.HeaderLen)
			if kErr == nil && !compressed {
				cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadataKey(key, hdr.ID, sample)
				if ok {
					if c.ObsEnabled {
						c.CacheHits.Add(1)
					}
					if c.Prefetch && hits > prefetchThreshold {
						remaining := expires.Sub(c.clock())
						if remaining < origTTL/prefetchRemainingRatio {
							c.maybePrefetchKey(key, req)
						}
					}
					if debugEnabled {
						c.logger.Debug("dns cache hit", "duration", time.Since(start))
					}
					if sample {
						c.total.Observe(time.Since(totalStart))
					}
					return cached, cleanup, nil
				}
			}
		}
	}

	parseStart = time.Now()
	reqMsg, err := dns.ReadMessagePooled(req)
	if sample {
		c.parseReq.Observe(time.Since(parseStart))
	}
	if err != nil || len(reqMsg.Questions) == 0 {
		if sample {
			c.total.Observe(time.Since(totalStart))
		}
		return c.upstream.Resolve(ctx, req)
	}
	q := reqMsg.Questions[0]
	reqHeader := reqMsg.Header
	key := cacheKeyFromQuestion(q)

	cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadata(q, reqHeader.ID, sample)
	if ok {
		if c.ObsEnabled {
			c.CacheHits.Add(1)
		}
		if c.Prefetch && hits > prefetchThreshold {
			remaining := expires.Sub(c.clock())
			if remaining < origTTL/prefetchRemainingRatio {
				c.maybePrefetchKey(key, req)
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
		if sample {
			c.total.Observe(time.Since(totalStart))
		}
		return cached, cleanup, nil
	}

	call, leader := c.acquireInflight(key)
	if !leader {
		reqMsg.Release()
		select {
		case <-ctx.Done():
			if sample {
				c.total.Observe(time.Since(totalStart))
			}
			return nil, nil, ctx.Err()
		case <-call.done:
		}
		if cached, cleanup, _, _, _, ok := c.getCachedWithMetadataKey(key, reqHeader.ID, sample); ok {
			if c.ObsEnabled {
				c.CacheHits.Add(1)
			}
			if sample {
				c.total.Observe(time.Since(totalStart))
			}
			return cached, cleanup, nil
		}
		if c.ObsEnabled {
			c.CacheMiss.Add(1)
		}
		if sample {
			c.total.Observe(time.Since(totalStart))
		}
		if call.err != nil {
			return nil, nil, call.err
		}
		return c.upstream.Resolve(ctx, req)
	}
	defer c.releaseInflight(key)

	if c.ObsEnabled {
		c.CacheMiss.Add(1)
	}
	var upStart time.Time
	if sample {
		upStart = time.Now()
	}
	resp, cleanup, err := c.upstream.Resolve(ctx, req)
	if sample {
		c.upstreamDo.Observe(time.Since(upStart))
	}

	var validateStart time.Time
	if sample {
		validateStart = time.Now()
	}
	if err != nil {
		if sample {
			c.validate.Observe(time.Since(validateStart))
		}
		if debugEnabled {
			c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start), "error", err)
		}
		c.setInflightErr(key, err)
		reqMsg.Release()
		if sample {
			c.total.Observe(time.Since(totalStart))
		}
		return resp, cleanup, err
	}
	vErr := dns.ValidateResponseWithRequest(reqHeader, reqMsg.Questions, resp)
	if sample {
		c.validate.Observe(time.Since(validateStart))
	}
	if vErr != nil {
		// ID/QR mismatches are fatal; question mismatches are common during recursion (CNAME follow).
		if vErr == dns.ErrIDMismatch || vErr == dns.ErrNotResponse {
			c.setInflightErr(key, vErr)
			reqMsg.Release()
			if sample {
				c.total.Observe(time.Since(totalStart))
			}
			return resp, cleanup, vErr
		}
		// Non-fatal: return the response, but don't cache it.
		// This preserves prior behavior and avoids caching responses that don't match the original question.
		if debugEnabled {
			c.logger.Debug("dns response validation mismatch; skip cache", "name", q.Name, "type", q.Type, "error", vErr)
		}
		c.setInflightErr(key, nil)
		reqMsg.Release()
		if sample {
			c.total.Observe(time.Since(totalStart))
		}
		return resp, cleanup, nil
	}
	reqMsg.Release()

	var setStart time.Time
	if sample {
		setStart = time.Now()
	}
	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := cacheTTLForResponse(resp, *respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
		respMsg.Release()
	}
	if sample {
		c.cacheSet.Observe(time.Since(setStart))
	}

	setRAFlag(resp)

	if debugEnabled {
		c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start))
	}
	c.setInflightErr(key, nil)
	if sample {
		c.total.Observe(time.Since(totalStart))
	}
	return resp, cleanup, nil
}

func (c *Cached) acquireInflight(key uint64) (*inflightCall, bool) {
	c.inflightMu.Lock()
	defer c.inflightMu.Unlock()
	if call, ok := c.inflight[key]; ok {
		return call, false
	}
	call := &inflightCall{done: make(chan struct{})}
	c.inflight[key] = call
	return call, true
}

func (c *Cached) setInflightErr(key uint64, err error) {
	c.inflightMu.Lock()
	call := c.inflight[key]
	if call != nil {
		call.err = err
	}
	c.inflightMu.Unlock()
}

func (c *Cached) releaseInflight(key uint64) {
	c.inflightMu.Lock()
	call := c.inflight[key]
	delete(c.inflight, key)
	c.inflightMu.Unlock()
	if call != nil {
		close(call.done)
	}
}

func (c *Cached) maybePrefetchKey(key uint64, req []byte) {
	if _, loading := c.refreshing.LoadOrStore(key, true); loading {
		return
	}

	// Copy req before goroutine to avoid data race with buffer pool reuse
	reqCopy := make([]byte, len(req))
	copy(reqCopy, req)

	go func() {
		defer c.refreshing.Delete(key)
		ctx, cancel := context.WithTimeout(context.Background(), prefetchTimeout)
		defer cancel()

		// Parse request in the goroutine to derive q for TTL selection.
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
						c.setCache(q, resp, ttl)
					}
				}
				respMsg.Release()
			}
		}
	}()
}

// getCachedWithMetadata retrieves a cached response and metadata
func (c *Cached) getCachedWithMetadata(q dns.Question, queryID uint16, sample bool) ([]byte, func(), time.Time, uint64, time.Duration, bool) {
	if c.cache == nil {
		return nil, nil, time.Time{}, 0, 0, false
	}
	key := cacheKeyFromQuestion(q)
	return c.getCachedWithMetadataKey(key, queryID, sample)

	// unreachable
}

func cacheKeyFromQuestion(q dns.Question) uint64 {
	q = q.Normalize()
	h := dns.HashNormalizedNameString(q.Name)
	h ^= uint64(q.Type) << 32
	h ^= uint64(q.Class)
	return h
}

func (c *Cached) getCachedWithMetadataKey(key uint64, queryID uint16, sample bool) ([]byte, func(), time.Time, uint64, time.Duration, bool) {
	var getStart time.Time
	if sample {
		getStart = time.Now()
	}
	cachedData, expires, hits, origTTL, ttlOffs, ok := c.cache.GetWithMetadataKey(key)
	if sample {
		c.cacheGet.Observe(time.Since(getStart))
	}
	if !ok || len(cachedData) < 4 {
		return nil, nil, time.Time{}, 0, 0, false
	}
	var copyStart time.Time
	if sample {
		copyStart = time.Now()
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
	// Rewrite TTLs to reflect remaining lifetime.
	remaining := expires.Sub(c.clock())
	sec := uint32(0)
	if remaining > 0 {
		sec = uint32(remaining / time.Second)
	}
	if sec > 0 {
		// Only rewrite when TTL is actually decayed.
		if orig := uint32(origTTL / time.Second); orig == 0 || sec < orig {
			dns.RewriteTTLsAtOffsets(resp, sec, ttlOffs)
		}
	}
	if sample {
		c.cacheCopy.Observe(time.Since(copyStart))
	}

	cleanup := func() {
		if fromPool {
			c.bufPool.Put(bufPtr)
		}
	}

	return resp, cleanup, expires, hits, origTTL, true
}

// setCache stores a raw DNS response in the cache
func (c *Cached) setCache(q dns.Question, resp []byte, ttl time.Duration) {
	if c.cache == nil || ttl <= 0 {
		return
	}

	c.cache.Set(q, resp, ttl)
}

// delegationCache caches zone to nameserver IP mappings with TTL clamping.
type delegationCache struct {
	*cache.TTL[string, []string]
}

func newDelegationCache() *delegationCache {
	ttl := cache.NewTTL[string, []string](nil)
	ttl.MaxLen = maxDelegationCacheEntries
	return &delegationCache{TTL: ttl}
}

// Set stores servers with TTL clamping (min 5s, max 24h).
func (c *delegationCache) Set(zone string, servers []string, ttl time.Duration) {
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	c.TTL.Set(zone, servers, ttl)
}

// FindLongestMatchingZone finds the longest matching zone for a name.
func (c *delegationCache) FindLongestMatchingZone(name string) (string, []string, bool) {
	name = dns.NormalizeName(name)

	zone := name
	for {
		if servers, ok := c.Get(zone); ok {
			return zone, servers, true
		}

		idx := strings.Index(zone, ".")
		if idx == -1 || idx == len(zone)-1 {
			break
		}
		zone = zone[idx+1:]
	}

	if servers, ok := c.Get("."); ok {
		return ".", servers, true
	}

	return ".", nil, false
}

// rttTracker tracks nameserver response times
type rttTracker struct {
	mu       sync.RWMutex
	rtts     map[string]time.Duration
	timeouts map[string]uint32
	cooldown map[string]time.Time
	dirty    atomic.Bool
}

func newRTTTracker() *rttTracker {
	return &rttTracker{
		rtts:     make(map[string]time.Duration),
		timeouts: make(map[string]uint32),
		cooldown: make(map[string]time.Time),
	}
}

func (t *rttTracker) Update(server string, d time.Duration) {
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

func (t *rttTracker) Timeout(server string) {
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

func (t *rttTracker) Get(server string) time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	d, ok := t.rtts[server]
	if !ok {
		return unknownRTT
	}
	return d
}

// SortBest selects the best n servers from the provided list.
// Uses linear scan - cache friendly for small n (typical DNS selection of 2-3 servers).
func (t *rttTracker) SortBest(servers []string, n int) []string {
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

	// Linear scan: maintain slice of best n servers in unsorted order
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
			// Replace the worst with this one
			best[maxIdx] = serverRTT{name: srv, rtt: rtt}
			// Find new max
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

	// Sort the result by RTT (lowest first)
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
