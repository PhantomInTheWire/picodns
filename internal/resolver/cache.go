package resolver

import (
	"context"
	"encoding/binary"
	"errors"
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
	if cacheStore == nil {
		cacheStore = cache.New(0, nil)
	}
	return &Cached{cache: cacheStore, upstream: upstream}
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	if c == nil || c.upstream == nil {
		return nil, errors.New("resolver not configured")
	}

	reqMsg, err := dns.ReadMessage(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}

	q := reqMsg.Questions[0]
	if cached, ok := c.cache.Get(q); ok {
		return cached, nil
	}

	resp, err := c.upstream.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := dns.ValidateResponse(req, resp); err != nil {
		return nil, err
	}

	respMsg, err := dns.ReadMessage(resp)
	if err == nil {
		if ttl, ok := extractTTL(respMsg, q); ok {
			c.cache.Set(q, resp, ttl)
		}
	}

	return resp, nil
}

func extractTTL(msg dns.Message, q dns.Question) (time.Duration, bool) {
	// Handle NXDOMAIN negative caching
	if (msg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
		for _, rr := range msg.Authorities {
			if rr.Type == dns.TypeSOA {
				// Parse SOA minimum TTL
				// SOA RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
				_, nextM, err := dns.DecodeName(rr.Data, 0)
				if err != nil {
					continue
				}
				_, nextR, err := dns.DecodeName(rr.Data, nextM)
				if err != nil {
					continue
				}
				if len(rr.Data) < nextR+20 {
					continue
				}
				// MINIMUM is the last uint32 (20 bytes after MNAME and RNAME)
				minTTL := binary.BigEndian.Uint32(rr.Data[nextR+16 : nextR+20])
				return time.Duration(minTTL) * time.Second, true
			}
		}
		return 0, false
	}

	q = q.Normalize()
	for _, rr := range msg.Answers {
		if rr.Type != q.Type || rr.Class != q.Class {
			continue
		}
		rrQ := dns.Question{Name: rr.Name, Type: rr.Type, Class: rr.Class}.Normalize()
		if rrQ.Name != q.Name {
			continue
		}
		if rr.TTL == 0 {
			continue
		}
		return time.Duration(rr.TTL) * time.Second, true
	}

	return 0, false
}
