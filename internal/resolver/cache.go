package resolver

import (
	"container/heap"
	"context"
	"encoding/binary"
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
}

func NewCached(cacheStore *cache.Cache, upstream types.Resolver) *Cached {
	return &Cached{
		cache:    cacheStore,
		upstream: upstream,
		bufPool:  pool.DefaultPool,
		clock:    time.Now,
	}
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	reqMsg, err := dns.ReadMessagePooled(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}
	q := reqMsg.Questions[0]
	reqHeader := reqMsg.Header
	var questions []dns.Question
	if len(reqMsg.Questions) == 1 {
		questions = reqMsg.Questions
	} else {
		questions = make([]dns.Question, len(reqMsg.Questions))
		copy(questions, reqMsg.Questions)
	}

	if cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadata(q, reqHeader.ID); ok {
		if c.Prefetch && hits > prefetchThreshold {
			remaining := expires.Sub(c.clock())
			if remaining < origTTL/prefetchRemainingRatio {
				c.maybePrefetch(q, req)
			}
		}
		reqMsg.Release()
		return cached, cleanup, nil
	}
	reqMsg.Release()

	resp, cleanup, err := c.upstream.Resolve(ctx, req)
	if err != nil || dns.ValidateResponseWithRequest(reqHeader, questions, resp) != nil {
		return resp, cleanup, err
	}

	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := extractTTL(*respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
		respMsg.Release()
	}

	setRAFlag(resp)

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
	mu    sync.RWMutex
	rtts  map[string]time.Duration
	dirty atomic.Bool
}

func newRTTTracker() *rttTracker {
	return &rttTracker{
		rtts: make(map[string]time.Duration),
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
	t.mu.Unlock()
	t.dirty.Store(true)
}

func (t *rttTracker) Get(server string) time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	d, ok := t.rtts[server]
	if !ok {
		return 200 * time.Millisecond
	}
	return d
}

// SortBest selects the best n servers from the provided list.
// It uses a heap-based selection to find the top n in O(m log n) where m is len(servers).
// Max-Heap of size n to find smallest RTTs
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

	t.mu.RLock()
	defer t.mu.RUnlock()

	h := &serverHeap{
		servers: make([]serverRTT, 0, n),
	}

	for _, srv := range servers {
		rtt, ok := t.rtts[srv]
		if !ok {
			rtt = 200 * time.Millisecond
		}

		if h.Len() < n {
			heap.Push(h, serverRTT{name: srv, rtt: rtt})
		} else if rtt < h.servers[0].rtt {
			h.servers[0] = serverRTT{name: srv, rtt: rtt}
			heap.Fix(h, 0)
		}
	}

	result := make([]string, h.Len())
	for i := h.Len() - 1; i >= 0; i-- {
		result[i] = heap.Pop(h).(serverRTT).name
	}
	return result
}

type serverRTT struct {
	name string
	rtt  time.Duration
}

// serverHeap is a Max-Heap of serverRTT based on rtt
type serverHeap struct {
	servers []serverRTT
}

func (h *serverHeap) Len() int           { return len(h.servers) }
func (h *serverHeap) Less(i, j int) bool { return h.servers[i].rtt > h.servers[j].rtt }
func (h *serverHeap) Swap(i, j int)      { h.servers[i], h.servers[j] = h.servers[j], h.servers[i] }
func (h *serverHeap) Push(x any)         { h.servers = append(h.servers, x.(serverRTT)) }
func (h *serverHeap) Pop() any {
	old := h.servers
	n := len(old)
	x := old[n-1]
	h.servers = old[0 : n-1]
	return x
}
