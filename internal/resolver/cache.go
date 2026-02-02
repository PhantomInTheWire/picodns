package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

type Cached struct {
	cache    *cache.Cache
	upstream Resolver
}

func NewCached(cacheStore *cache.Cache, upstream Resolver) *Cached {
	return &Cached{cache: cacheStore, upstream: upstream}
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	if c == nil || c.upstream == nil {
		return nil, errors.New("resolver not configured")
	}
	q, err := extractQuestion(req)
	if err != nil {
		return c.upstream.Resolve(ctx, req)
	}
	key := cache.Key{Name: q.Name, Type: q.Type, Class: q.Class}
	if c.cache != nil {
		if cached, ok := c.cache.Get(key); ok {
			return cached, nil
		}
	}

	resp, err := c.upstream.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := dns.ValidateResponse(req, resp); err != nil {
		return nil, err
	}

	if c.cache != nil {
		ttl, ok := extractTTL(resp, q)
		if ok {
			c.cache.Set(key, resp, ttl)
		}
	}

	return resp, nil
}

func extractQuestion(req []byte) (dns.Question, error) {
	header, err := dns.ReadHeader(req)
	if err != nil {
		return dns.Question{}, err
	}
	if header.QDCount == 0 {
		return dns.Question{}, dns.ErrNoQuestion
	}
	q, _, err := dns.ReadQuestion(req, dns.HeaderLen)
	if err != nil {
		return dns.Question{}, err
	}
	q.Name = strings.TrimSuffix(q.Name, ".")
	return q, nil
}

func extractTTL(resp []byte, q dns.Question) (time.Duration, bool) {
	header, err := dns.ReadHeader(resp)
	if err != nil {
		return 0, false
	}

	_, off, err := dns.ReadQuestion(resp, dns.HeaderLen)
	if err != nil {
		return 0, false
	}

	// Handle NXDOMAIN negative caching
	if (header.Flags & 0x000F) == dns.RcodeNXDomain {
		// Skip answers (if any)
		for i := 0; i < int(header.ANCount); i++ {
			_, next, err := dns.ReadResourceRecord(resp, off)
			if err != nil {
				return 0, false
			}
			off = next
		}
		// Look in authority section for SOA
		for i := 0; i < int(header.NSCount); i++ {
			rr, next, err := dns.ReadResourceRecord(resp, off)
			if err != nil {
				return 0, false
			}
			off = next
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

	if header.ANCount == 0 {
		return 0, false
	}

	qName := strings.TrimSuffix(q.Name, ".")
	for i := 0; i < int(header.ANCount); i++ {
		rr, next, err := dns.ReadResourceRecord(resp, off)
		if err != nil {
			return 0, false
		}
		off = next
		if rr.Type != q.Type || rr.Class != q.Class {
			continue
		}
		name := strings.TrimSuffix(rr.Name, ".")
		if !strings.EqualFold(name, qName) {
			continue
		}
		if rr.TTL == 0 {
			continue
		}
		return time.Duration(rr.TTL) * time.Second, true
	}

	return 0, false
}
