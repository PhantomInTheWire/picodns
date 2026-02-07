package resolver

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/dnsutil"
)

// Resolver is the interface for DNS resolution
type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, func(), error)
}

// Cached wraps a resolver with DNS response caching
type Cached struct {
	cache    *cache.Cache
	upstream Resolver
	respPool sync.Pool
}

func NewCached(cacheStore *cache.Cache, upstream Resolver) *Cached {
	c := &Cached{
		cache:    cacheStore,
		upstream: upstream,
	}
	c.respPool = sync.Pool{
		New: func() any {
			b := make([]byte, dns.MaxMessageSize)
			return &b
		},
	}
	return c
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

	// Try to get from cache and rebuild response with correct ID
	if cached, cleanup, ok := c.getCached(q, reqHeader.ID); ok {
		reqMsg.Release()
		return cached, cleanup, nil
	}
	reqMsg.Release()

	resp, cleanup, err := c.upstream.Resolve(ctx, req)
	if err != nil || dns.ValidateResponseWithRequest(reqHeader, questions, resp) != nil {
		return resp, cleanup, err
	}

	// Parse and cache the response
	if respMsg, err := dns.ReadMessagePooled(resp); err == nil {
		if ttl, ok := extractTTL(*respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
		respMsg.Release()
	}
	return resp, cleanup, nil
}

// getCached retrieves a cached response and rebuilds it with the correct transaction ID
func (c *Cached) getCached(q dns.Question, queryID uint16) ([]byte, func(), bool) {
	if c.cache == nil {
		return nil, nil, false
	}

	cachedData, ok := c.cache.Get(q)
	if !ok || len(cachedData) < 2 {
		return nil, nil, false
	}

	// Use pooled buffer instead of allocating
	bufPtr := c.respPool.Get().(*[]byte)
	if cap(*bufPtr) < len(cachedData) {
		// Buffer too small, allocate new one
		c.respPool.Put(bufPtr)
		newBuf := make([]byte, len(cachedData))
		bufPtr = &newBuf
	}
	resp := (*bufPtr)[:len(cachedData)]
	copy(resp, cachedData)

	// Patch the transaction ID
	binary.BigEndian.PutUint16(resp[0:2], queryID)

	cleanup := func() {
		c.respPool.Put(bufPtr)
	}

	return resp, cleanup, true
}

// setCache stores a raw DNS response in the cache
func (c *Cached) setCache(q dns.Question, resp []byte, ttl time.Duration) {
	if c.cache == nil || ttl <= 0 {
		return
	}

	// Store raw response directly; cache handles expiry internally
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
			if dnsutil.NormalizeName(rr.Name) == q.Name {
				return time.Duration(rr.TTL) * time.Second, true
			}
		}
	}
	return 0, false
}
