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

	tracers struct {
		resolveFromCache *obs.FuncTracer
		resolve          *obs.FuncTracer
		resolveFastPath  *obs.FuncTracer
		resolveParseReq  *obs.FuncTracer
		resolveInflight  *obs.FuncTracer
		resolveUpstream  *obs.FuncTracer
		resolveValidate  *obs.FuncTracer
		resolveCacheSet  *obs.FuncTracer
		getCachedWithKey *obs.FuncTracer
		acquireInflight  *obs.FuncTracer
		releaseInflight  *obs.FuncTracer
		setCache         *obs.FuncTracer
		maybePrefetch    *obs.FuncTracer
	}
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

	c.tracers.resolveFromCache = obs.NewFuncTracer("Cached.ResolveFromCache", nil)
	c.tracers.resolve = obs.NewFuncTracer("Cached.Resolve", nil)
	c.tracers.resolveFastPath = obs.NewFuncTracer("Cached.Resolve.fastPath", c.tracers.resolve)
	c.tracers.resolveParseReq = obs.NewFuncTracer("Cached.Resolve.parseReq", c.tracers.resolve)
	c.tracers.resolveInflight = obs.NewFuncTracer("Cached.Resolve.inflightWait", c.tracers.resolve)
	c.tracers.resolveUpstream = obs.NewFuncTracer("Cached.Resolve.upstream", c.tracers.resolve)
	c.tracers.resolveValidate = obs.NewFuncTracer("Cached.Resolve.validate", c.tracers.resolve)
	c.tracers.resolveCacheSet = obs.NewFuncTracer("Cached.Resolve.cacheSet", c.tracers.resolve)
	c.tracers.getCachedWithKey = obs.NewFuncTracer("Cached.getCachedWithMetadataKey", c.tracers.resolve)
	c.tracers.acquireInflight = obs.NewFuncTracer("Cached.acquireInflight", c.tracers.resolve)
	c.tracers.releaseInflight = obs.NewFuncTracer("Cached.releaseInflight", c.tracers.resolve)
	c.tracers.setCache = obs.NewFuncTracer("Cached.setCache", c.tracers.resolve)
	c.tracers.maybePrefetch = obs.NewFuncTracer("Cached.maybePrefetchKey", c.tracers.resolve)

	obs.GlobalRegistry.Register(c.tracers.resolveFromCache)
	obs.GlobalRegistry.Register(c.tracers.resolve)
	obs.GlobalRegistry.Register(c.tracers.resolveFastPath)
	obs.GlobalRegistry.Register(c.tracers.resolveParseReq)
	obs.GlobalRegistry.Register(c.tracers.resolveInflight)
	obs.GlobalRegistry.Register(c.tracers.resolveUpstream)
	obs.GlobalRegistry.Register(c.tracers.resolveValidate)
	obs.GlobalRegistry.Register(c.tracers.resolveCacheSet)
	obs.GlobalRegistry.Register(c.tracers.getCachedWithKey)
	obs.GlobalRegistry.Register(c.tracers.acquireInflight)
	obs.GlobalRegistry.Register(c.tracers.releaseInflight)
	obs.GlobalRegistry.Register(c.tracers.setCache)
	obs.GlobalRegistry.Register(c.tracers.maybePrefetch)

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

func (c *Cached) maybePrefetch(key uint64, req []byte, expires time.Time, hits uint64, origTTL time.Duration, stale bool) {
	if stale {
		// Expired entry was served; refresh opportunistically.
		c.maybePrefetchKey(key, req)
		return
	}
	if !c.Prefetch || hits <= prefetchThreshold {
		return
	}
	remaining := expires.Sub(c.clock())
	if remaining < origTTL/prefetchRemainingRatio {
		c.maybePrefetchKey(key, req)
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

func readQuestions(req []byte, qdCount uint16) ([]dns.Question, bool) {
	if qdCount == 0 {
		return nil, false
	}
	if qdCount == 1 {
		q, _, err := dns.ReadQuestion(req, dns.HeaderLen)
		if err != nil {
			return nil, false
		}
		return []dns.Question{q}, true
	}
	qs := make([]dns.Question, 0, qdCount)
	off := dns.HeaderLen
	for i := 0; i < int(qdCount); i++ {
		q, next, err := dns.ReadQuestion(req, off)
		if err != nil {
			return nil, false
		}
		qs = append(qs, q)
		off = next
	}
	return qs, true
}

func (c *Cached) ResolveFromCache(ctx context.Context, req []byte) ([]byte, func(), bool) {
	sampled := c.tracers.resolveFromCache.ShouldSample()
	done := c.tracers.resolveFromCache.TraceSampled(sampled)
	defer done()

	if c.cache == nil {
		return nil, nil, false
	}
	hdr, key, ok := c.keyFromWire(req)
	if !ok {
		return nil, nil, false
	}
	resp, cleanup, expires, hits, origTTL, stale, ok := c.getCachedWithMetadataKey(key, hdr.ID)
	if ok {
		if c.ObsEnabled {
			c.CacheHits.Add(1)
		}
		c.maybePrefetch(key, req, expires, hits, origTTL, stale)
		return resp, cleanup, true
	}
	return nil, nil, false
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	sampled := c.tracers.resolve.ShouldSample()
	done := c.tracers.resolve.TraceSampled(sampled)
	defer done()

	if c.cache == nil {
		return c.upstream.Resolve(ctx, req)
	}

	var start time.Time
	debugEnabled := c.logger != nil && c.logger.Enabled(ctx, slog.LevelDebug)
	if debugEnabled {
		start = time.Now()
	}

	var key uint64
	var reqHeader dns.Header

	segFast := c.tracers.resolveFastPath.TraceNested(sampled)
	hdr, fastKey, fastOK := c.keyFromWire(req)
	if fastOK {
		cached, cleanup, expires, hits, origTTL, stale, cacheOK := c.getCachedWithMetadataKey(fastKey, hdr.ID)
		if cacheOK {
			segFast()
			if c.ObsEnabled {
				c.CacheHits.Add(1)
			}
			c.maybePrefetch(fastKey, req, expires, hits, origTTL, stale)
			if debugEnabled {
				c.logger.Debug("dns cache hit", "duration", time.Since(start))
			}
			return cached, cleanup, nil
		}
		key = fastKey
		reqHeader = hdr
	}
	segFast()

	var questions []dns.Question
	var q dns.Question
	segParse := c.tracers.resolveParseReq.TraceNested(sampled)
	if key == 0 {
		var err error
		reqHeader, err = dns.ReadHeader(req)
		if err != nil || reqHeader.QDCount == 0 {
			segParse()
			return c.upstream.Resolve(ctx, req)
		}
		var qOK bool
		questions, qOK = readQuestions(req, reqHeader.QDCount)
		if !qOK || len(questions) == 0 {
			segParse()
			return c.upstream.Resolve(ctx, req)
		}
		q = questions[0]
		key = hashQuestion(q.Name, q.Type, q.Class)

		// Only do the second lookup if we just computed the key for the first time
		cached, cleanup, expires, hits, origTTL, stale, cacheOK := c.getCachedWithMetadataKey(key, reqHeader.ID)
		if cacheOK {
			segParse()
			if c.ObsEnabled {
				c.CacheHits.Add(1)
			}
			c.maybePrefetch(key, req, expires, hits, origTTL, stale)
			if debugEnabled {
				c.logger.Debug("dns cache hit",
					"name", q.Name,
					"type", q.Type,
					"remaining", expires.Sub(c.clock()),
					"duration", time.Since(start))
			}
			return cached, cleanup, nil
		}
	} else {
		// We already checked this key in the fast path and it was a miss.
		// We still need to parse the questions for validation later.
		var qOK bool
		questions, qOK = readQuestions(req, reqHeader.QDCount)
		if !qOK || len(questions) == 0 {
			segParse()
			return c.upstream.Resolve(ctx, req)
		}
		q = questions[0]

		// Now that we have questions for validation, check the cache again.
		// Another goroutine may have populated it after the fast-path miss.
		cached, cleanup, expires, hits, origTTL, stale, ok := c.getCachedWithMetadataKey(key, reqHeader.ID)
		if ok {
			segParse()
			if c.ObsEnabled {
				c.CacheHits.Add(1)
			}
			c.maybePrefetch(key, req, expires, hits, origTTL, stale)
			if debugEnabled {
				c.logger.Debug("dns cache hit",
					"name", q.Name,
					"type", q.Type,
					"remaining", expires.Sub(c.clock()),
					"duration", time.Since(start))
			}
			return cached, cleanup, nil
		}
	}
	segParse()

	call, leader := c.acquireInflight(key)
	if !leader {
		segInflight := c.tracers.resolveInflight.TraceNested(sampled)
		select {
		case <-ctx.Done():
			segInflight()
			return nil, nil, ctx.Err()
		case <-call.done:
		}
		segInflight()
		if cached, cleanup, _, _, _, _, ok := c.getCachedWithMetadataKey(key, reqHeader.ID); ok {
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
		if call.resp != nil {
			respCopy := make([]byte, len(call.resp))
			copy(respCopy, call.resp)
			setResponseID(respCopy, reqHeader.ID)
			return respCopy, nil, nil
		}
		return c.upstream.Resolve(ctx, req)
	}
	defer c.releaseInflight(key)

	if c.ObsEnabled {
		c.CacheMiss.Add(1)
	}

	segUp := c.tracers.resolveUpstream.TraceNested(sampled)
	resp, cleanupResp, err := c.upstream.Resolve(ctx, req)
	segUp()

	if err != nil {
		// If upstream fails, return a minimal SERVFAIL and cache it briefly.
		// This reduces repeated expensive recursion for persistent failures.
		if cleanupResp != nil {
			cleanupResp()
			cleanupResp = nil
		}
		if sf, ok := servfailFromRequest(req); ok {
			call.err = nil
			if sf != nil {
				sfCopy := make([]byte, len(sf))
				copy(sfCopy, sf)
				call.resp = sfCopy
			} else {
				call.resp = nil
			}
			c.setCache(q, sf, servfailCacheTTL)
			return sf, nil, nil
		}

		if debugEnabled {
			c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start), "error", err)
		}
		call.err = err
		call.resp = nil
		return resp, cleanupResp, err
	}

	segVal := c.tracers.resolveValidate.TraceNested(sampled)
	vErr := dns.ValidateResponseWithRequest(reqHeader, questions, resp)
	segVal()
	if vErr != nil {
		if vErr == dns.ErrIDMismatch || vErr == dns.ErrNotResponse {
			call.err = vErr
			call.resp = nil
			return resp, cleanupResp, vErr
		}
		if debugEnabled {
			c.logger.Debug("dns response validation mismatch; skip cache", "name", q.Name, "type", q.Type, "error", vErr)
		}
		call.err = nil
		setResponseID(resp, reqHeader.ID)
		if resp != nil {
			respCopy := make([]byte, len(resp))
			copy(respCopy, resp)
			call.resp = respCopy
		} else {
			call.resp = nil
		}
		return resp, cleanupResp, nil
	}

	segSet := c.tracers.resolveCacheSet.TraceNested(sampled)
	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := cacheTTLForResponse(resp, *respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
		respMsg.Release()
	}
	segSet()

	setRAFlag(resp)
	setResponseID(resp, reqHeader.ID)
	if resp != nil {
		respCopy := make([]byte, len(resp))
		copy(respCopy, resp)
		call.resp = respCopy
	} else {
		call.resp = nil
	}

	if debugEnabled {
		c.logger.Debug("dns cache miss", "name", q.Name, "type", q.Type, "duration", time.Since(start))
	}
	call.err = nil
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

		var q dns.Question
		if hdr, err := dns.ReadHeader(reqCopy); err == nil && hdr.QDCount > 0 {
			if q0, _, qErr := dns.ReadQuestion(reqCopy, dns.HeaderLen); qErr == nil {
				q = q0
			}
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

func (c *Cached) getCachedWithMetadataKey(key uint64, queryID uint16) ([]byte, func(), time.Time, uint64, time.Duration, bool, bool) {
	defer c.tracers.getCachedWithKey.Trace()()

	cachedData, expires, hits, origTTL, ttlOffs, stale, ok := c.cache.GetWithMetadataKeyStale(key, serveStaleFor)
	if !ok || len(cachedData) < 4 {
		return nil, nil, time.Time{}, 0, 0, false, false
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

	sec := uint32(0)
	if stale {
		sec = 1
	} else {
		remaining := expires.Sub(c.clock())
		if remaining > 0 {
			sec = uint32(remaining / time.Second)
			if sec == 0 {
				sec = 1
			}
		}
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

	return resp, cleanup, expires, hits, origTTL, stale, true
}

func (c *Cached) setCache(q dns.Question, resp []byte, ttl time.Duration) {
	defer c.tracers.setCache.Trace()()

	if c.cache == nil || ttl <= 0 {
		return
	}

	c.cache.Set(q, resp, ttl)
}
