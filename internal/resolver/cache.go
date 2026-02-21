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

func (c *Cached) keyFromWire(req []byte) (dns.Header, uint64, bool) {
	hdr, err := dns.ReadHeader(req)
	if err != nil || hdr.QDCount == 0 {
		return dns.Header{}, 0, false
	}
	key, _, _, _, compressed, err := dns.HashQuestionKeyFromWire(req, dns.HeaderLen)
	if err != nil || compressed {
		return dns.Header{}, 0, false
	}
	return hdr, key, true
}

func (c *Cached) ResolveFromCache(ctx context.Context, req []byte) ([]byte, func(), bool) {
	defer c.tracers.resolveFromCache.Trace()()

	if c.cache == nil {
		return nil, nil, false
	}
	hdr, key, ok := c.keyFromWire(req)
	if !ok {
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
	defer c.tracers.resolve.Trace()()

	var start time.Time
	debugEnabled := c.logger != nil && c.logger.Enabled(ctx, slog.LevelDebug)
	if debugEnabled {
		start = time.Now()
	}

	// Fast path: avoid full parsing when we can.
	if c.cache != nil {
		hdr, key, ok := c.keyFromWire(req)
		if ok {
			cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadataKey(key, hdr.ID, c.ObsEnabled)
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
				return cached, cleanup, nil
			}
		}
	}

	reqMsg, err := dns.ReadMessagePooled(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}
	q := reqMsg.Questions[0]
	reqHeader := reqMsg.Header
	key := c.cacheKeyFromQuestion(q)

	cached, cleanup, expires, hits, origTTL, ok := c.getCachedWithMetadataKey(key, reqHeader.ID, c.ObsEnabled)
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
		return cached, cleanup, nil
	}

	call, leader := c.acquireInflight(key)
	if !leader {
		reqMsg.Release()
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-call.done:
		}
		if cached, cleanup, _, _, _, ok := c.getCachedWithMetadataKey(key, reqHeader.ID, c.ObsEnabled); ok {
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
	defer c.releaseInflight(key)

	if c.ObsEnabled {
		c.CacheMiss.Add(1)
	}

	resp, cleanupResp, err := c.upstream.Resolve(ctx, req)

	if err != nil {
		if debugEnabled {
			c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start), "error", err)
		}
		c.setInflightErr(key, err)
		reqMsg.Release()
		return resp, cleanupResp, err
	}

	vErr := dns.ValidateResponseWithRequest(reqHeader, reqMsg.Questions, resp)
	if vErr != nil {
		if vErr == dns.ErrIDMismatch || vErr == dns.ErrNotResponse {
			c.setInflightErr(key, vErr)
			reqMsg.Release()
			return resp, cleanupResp, vErr
		}
		if debugEnabled {
			c.logger.Debug("dns response validation mismatch; skip cache", "name", q.Name, "type", q.Type, "error", vErr)
		}
		c.setInflightErr(key, nil)
		reqMsg.Release()
		return resp, cleanupResp, nil
	}
	reqMsg.Release()

	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := cacheTTLForResponse(resp, *respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
		respMsg.Release()
	}

	setRAFlag(resp)

	if debugEnabled {
		c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start))
	}
	c.setInflightErr(key, nil)
	return resp, cleanupResp, nil
}

func (c *Cached) acquireInflight(key uint64) (*inflightCall, bool) {
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

func (c *Cached) setInflightErr(key uint64, err error) {
	defer c.tracers.setInflightErr.Trace()()

	c.inflightMu.Lock()
	call := c.inflight[key]
	if call != nil {
		call.err = err
	}
	c.inflightMu.Unlock()
}

func (c *Cached) releaseInflight(key uint64) {
	defer c.tracers.releaseInflight.Trace()()

	c.inflightMu.Lock()
	call := c.inflight[key]
	delete(c.inflight, key)
	c.inflightMu.Unlock()
	if call != nil {
		close(call.done)
	}
}

func (c *Cached) maybePrefetchKey(key uint64, req []byte) {
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
						c.setCache(q, resp, ttl)
					}
				}
				respMsg.Release()
			}
		}
	}()
}

func (c *Cached) cacheKeyFromQuestion(q dns.Question) uint64 {
	defer c.tracers.cacheKeyFromQ.Trace()()

	q = q.Normalize()
	h := dns.HashNormalizedNameString(q.Name)
	h ^= uint64(q.Type) << 32
	h ^= uint64(q.Class)
	return h
}

func (c *Cached) getCachedWithMetadataKey(key uint64, queryID uint16, sample bool) ([]byte, func(), time.Time, uint64, time.Duration, bool) {
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

func (c *Cached) setCache(q dns.Question, resp []byte, ttl time.Duration) {
	defer c.tracers.setCache.Trace()()

	if c.cache == nil || ttl <= 0 {
		return
	}

	c.cache.Set(q, resp, ttl)
}
