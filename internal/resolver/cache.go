package resolver

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"
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
	prefetch   bool
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

func (c *Cached) SetClock(clock func() time.Time) {
	c.clock = clock
}

func (c *Cached) EnablePrefetch(enabled bool) {
	c.prefetch = enabled
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	reqMsg, err := dns.ReadMessagePooled(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}
	q := reqMsg.Questions[0]
	reqHeader := reqMsg.Header
	questions := make([]dns.Question, len(reqMsg.Questions))
	copy(questions, reqMsg.Questions)

	if cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadata(q, reqHeader.ID); ok {
		if c.prefetch && hits > prefetchThreshold {
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

func extractTTL(msg dns.Message, q dns.Question) (time.Duration, bool) {
	if (msg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
		for _, rr := range msg.Authorities {
			if rr.Type == dns.TypeSOA && len(rr.Data) >= 22 {
				_, nextM, err := dns.DecodeName(rr.Data, 0)
				if err != nil {
					continue
				}
				_, nextR, err := dns.DecodeName(rr.Data, nextM)
				if err != nil {
					continue
				}
				if len(rr.Data) >= nextR+20 {
					return time.Duration(binary.BigEndian.Uint32(rr.Data[nextR+16:nextR+20])) * time.Second, true
				}
			}
		}
		return 0, false
	}

	q = q.Normalize()
	for _, rr := range msg.Answers {
		if rr.Type == q.Type && rr.Class == q.Class && rr.TTL > 0 {
			if dns.NormalizeName(rr.Name) == q.Name {
				return time.Duration(rr.TTL) * time.Second, true
			}
		}
	}
	return 0, false
}

// setRAFlag sets the Recursion Available (RA) flag in a DNS response header.
func setRAFlag(resp []byte) {
	if len(resp) >= 4 {
		flags := binary.BigEndian.Uint16(resp[2:4])
		flags |= dns.FlagRA
		binary.BigEndian.PutUint16(resp[2:4], flags)
	}
}

// nsCacheEntry stores resolved NS name IPs with expiration
type nsCacheEntry struct {
	ips     []string
	expires time.Time
}

// nsCache caches NS name to IP mappings
type nsCache struct {
	mu    sync.RWMutex
	items map[string]nsCacheEntry
}

func newNSCache() *nsCache {
	return &nsCache{
		items: make(map[string]nsCacheEntry),
	}
}

func (c *nsCache) Get(key string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.items[key]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.ips, true
}

func (c *nsCache) Set(key string, ips []string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = nsCacheEntry{
		ips:     ips,
		expires: time.Now().Add(ttl),
	}
}

// delegationEntry stores nameservers for a zone
type delegationEntry struct {
	servers []string
	expires time.Time
}

// delegationCache caches zone to nameserver IP mappings
type delegationCache struct {
	mu    sync.RWMutex
	items map[string]delegationEntry
}

func newDelegationCache() *delegationCache {
	return &delegationCache{
		items: make(map[string]delegationEntry),
	}
}

func (c *delegationCache) Get(zone string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.items[zone]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.servers, true
}

func (c *delegationCache) Set(zone string, servers []string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	c.items[zone] = delegationEntry{
		servers: servers,
		expires: time.Now().Add(ttl),
	}
}

func (c *delegationCache) FindLongestMatchingZone(name string) (string, []string, bool) {
	name = dns.NormalizeName(name)
	labels := strings.Split(name, ".")

	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := 0; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		if entry, ok := c.items[zone]; ok && time.Now().Before(entry.expires) {
			return zone, entry.servers, true
		}
	}

	return ".", nil, false
}

// rttTracker tracks nameserver response times
type rttTracker struct {
	mu   sync.RWMutex
	rtts map[string]time.Duration
}

func newRTTTracker() *rttTracker {
	return &rttTracker{
		rtts: make(map[string]time.Duration),
	}
}

func (t *rttTracker) Update(server string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.rtts[server]
	if !ok {
		t.rtts[server] = d
	} else {
		t.rtts[server] = (prev*4 + d) / 5
	}
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
