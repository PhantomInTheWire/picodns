package resolver

import (
	"context"
	"encoding/binary"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, error)
}

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
	if cached, ok := c.cache.Get(q); ok {
		return cached, nil
	}

	resp, err := c.upstream.Resolve(ctx, req)
	if err != nil || dns.ValidateResponse(req, resp) != nil {
		return resp, err
	}

	if respMsg, err := dns.ReadMessage(resp); err == nil {
		if ttl, ok := extractTTL(respMsg, q); ok {
			c.cache.Set(q, resp, ttl)
		}
	}
	return resp, nil
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
