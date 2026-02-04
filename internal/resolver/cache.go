package resolver

import (
	"context"
	"encoding/binary"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

// Resolver is the interface for DNS resolution
type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, error)
}

// Cached wraps a resolver with DNS response caching
type Cached struct {
	cache    *cache.Cache
	upstream Resolver
}

func NewCached(cacheStore *cache.Cache, upstream Resolver) *Cached {
	return &Cached{cache: cacheStore, upstream: upstream}
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	reqMsg, err := dns.ReadMessage(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}

	q := reqMsg.Questions[0]

	// Try to get from cache and rebuild response with correct ID
	if cached, ok := c.getCached(q, reqMsg.Header.ID); ok {
		return cached, nil
	}

	resp, err := c.upstream.Resolve(ctx, req)
	if err != nil || dns.ValidateResponse(req, resp) != nil {
		return resp, err
	}

	// Parse and cache the response
	if respMsg, err := dns.ReadMessage(resp); err == nil {
		if ttl, ok := extractTTL(respMsg, q); ok {
			c.setCache(q, resp, ttl)
		}
	}
	return resp, nil
}

// getCached retrieves a cached response and rebuilds it with the correct transaction ID
func (c *Cached) getCached(q dns.Question, queryID uint16) ([]byte, bool) {
	if c.cache == nil {
		return nil, false
	}

	cachedData, ok := c.cache.Get(q)
	if !ok || len(cachedData) < 10 {
		return nil, false
	}

	// Parse expiry time (first 8 bytes) and check if expired
	expires := time.Unix(int64(binary.BigEndian.Uint64(cachedData[0:8])), 0)
	if time.Now().After(expires) {
		return nil, false
	}

	// Copy the cached response data (after expiry header)
	resp := make([]byte, len(cachedData)-8)
	copy(resp, cachedData[8:])

	// Patch the transaction ID
	binary.BigEndian.PutUint16(resp[0:2], queryID)

	return resp, true
}

// setCache stores a raw DNS response in the cache
func (c *Cached) setCache(q dns.Question, resp []byte, ttl time.Duration) {
	if c.cache == nil || ttl <= 0 {
		return
	}

	// Store: [8 bytes expiry][raw response]
	data := make([]byte, 8+len(resp))
	binary.BigEndian.PutUint64(data[0:8], uint64(time.Now().Add(ttl).Unix()))
	copy(data[8:], resp)

	c.cache.Set(q, data, ttl)
}

func extractTTL(msg dns.Message, q dns.Question) (time.Duration, bool) {
	if (msg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
		for _, rr := range msg.Authorities {
			if rr.Type == dns.TypeSOA && len(rr.Data) >= 20 {
				_, nextM, _ := dns.DecodeName(rr.Data, 0)
				_, nextR, _ := dns.DecodeName(rr.Data, nextM)
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
			if rq := (dns.Question{Name: rr.Name, Type: rr.Type, Class: rr.Class}.Normalize()); rq.Name == q.Name {
				return time.Duration(rr.TTL) * time.Second, true
			}
		}
	}
	return 0, false
}
