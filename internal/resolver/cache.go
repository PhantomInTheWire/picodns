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
	"picodns/internal/pool"
	"picodns/internal/types"
)

// Cached wraps a resolver with DNS response caching
type Cached struct {
	cache      *cache.Cache
	upstream   types.Resolver
	bufPool    *pool.Bytes
	Prefetch   bool
	refreshing sync.Map
	clock      func() time.Time
	logger     *slog.Logger
	CacheHits  atomic.Uint64
	CacheMiss  atomic.Uint64
}

func NewCached(cacheStore *cache.Cache, upstream types.Resolver) *Cached {
	return &Cached{
		cache:    cacheStore,
		upstream: upstream,
		bufPool:  pool.DefaultPool,
		clock:    time.Now,
		logger:   slog.Default(),
	}
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	var start time.Time
	debugEnabled := c.logger != nil && c.logger.Enabled(ctx, slog.LevelDebug)
	if debugEnabled {
		start = time.Now()
	}
	reqMsg, err := dns.ReadMessagePooled(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}
	q := reqMsg.Questions[0]
	reqHeader := reqMsg.Header
	// Always copy questions to avoid race with pooled message reuse
	questions := make([]dns.Question, len(reqMsg.Questions))
	copy(questions, reqMsg.Questions)

	if cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadata(q, reqHeader.ID); ok {
		c.CacheHits.Add(1)
		if c.Prefetch && hits > prefetchThreshold {
			remaining := expires.Sub(c.clock())
			if remaining < origTTL/prefetchRemainingRatio {
				c.maybePrefetch(q, req)
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
	reqMsg.Release()
	c.CacheMiss.Add(1)

	resp, cleanup, err := c.upstream.Resolve(ctx, req)
	if err != nil || dns.ValidateResponseWithRequest(reqHeader, questions, resp) != nil {
		if debugEnabled {
			c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start), "error", err)
		}
		return resp, cleanup, err
	}

	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := extractTTL(*respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
		respMsg.Release()
	}

	setRAFlag(resp)

	if debugEnabled {
		c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start))
	}

	return resp, cleanup, nil
}

func (c *Cached) maybePrefetch(q dns.Question, req []byte) {
	if _, loading := c.refreshing.LoadOrStore(q, true); loading {
		return
	}

	// Copy req before goroutine to avoid data race with buffer pool reuse
	reqCopy := make([]byte, len(req))
	copy(reqCopy, req)

	go func() {
		defer c.refreshing.Delete(q)
		ctx, cancel := context.WithTimeout(context.Background(), prefetchTimeout)
		defer cancel()

		resp, cleanup, err := c.upstream.Resolve(ctx, reqCopy)
		if err == nil {
			if cleanup != nil {
				defer cleanup()
			}
			if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
				if ttl, ok := extractTTL(*respMsg, q); ok {
					c.setCache(q, resp, ttl)
				}
				respMsg.Release()
			}
		}
	}()
}

// getCachedWithMetadata retrieves a cached response and metadata
func (c *Cached) getCachedWithMetadata(q dns.Question, queryID uint16) ([]byte, func(), time.Time, uint64, time.Duration, bool) {
	if c.cache == nil {
		return nil, nil, time.Time{}, 0, 0, false
	}

	cachedData, expires, hits, origTTL, ok := c.cache.GetWithMetadata(q)
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
	return &delegationCache{
		TTL: cache.NewTTL[string, []string](nil),
	}
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
