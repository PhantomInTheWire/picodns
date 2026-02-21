package resolver

import (
	"strings"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

// delegationCache caches zone to nameserver IP mappings with TTL clamping.
type delegationCache struct {
	*cache.TTL[string, []string]
}

func newDelegationCache() *delegationCache {
	ttl := cache.NewTTL[string, []string](nil)
	ttl.MaxLen = maxDelegationCacheEntries
	return &delegationCache{TTL: ttl}
}

func (c *delegationCache) Set(zone string, servers []string, ttl time.Duration) {
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	c.TTL.Set(zone, servers, ttl)
}

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
