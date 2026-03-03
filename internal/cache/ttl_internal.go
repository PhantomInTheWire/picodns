package cache

import "time"

func (c *TTL[K, V]) now() time.Time {
	return c.clock()
}

func (c *TTL[K, V]) recordGet() {
	if c.ObsEnabled {
		c.gets.Add(1)
	}
}

func (c *TTL[K, V]) recordHit() {
	if c.ObsEnabled {
		c.hits.Add(1)
	}
}

func (c *TTL[K, V]) recordMiss() {
	if c.ObsEnabled {
		c.misses.Add(1)
	}
}

func (c *TTL[K, V]) recordSet() {
	if c.ObsEnabled {
		c.sets.Add(1)
	}
}

func (c *TTL[K, V]) recordDelete() {
	if c.ObsEnabled {
		c.deletes.Add(1)
	}
}

func (c *TTL[K, V]) recordExpired() {
	if c.ObsEnabled {
		c.expired.Add(1)
	}
}

func (c *TTL[K, V]) load(key K) (ttlEntry[V], bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	return entry, ok
}

func (c *TTL[K, V]) zeroValue() V {
	var zero V
	return zero
}

func (c *TTL[K, V]) evictOverflowLocked(skip K) {
	if c.MaxLen <= 0 || len(c.items) <= c.MaxLen {
		return
	}
	for k := range c.items {
		if k == skip {
			continue
		}
		delete(c.items, k)
		return
	}
}

func (c *TTL[K, V]) storeLocked(key K, entry ttlEntry[V]) {
	c.items[key] = entry
	c.evictOverflowLocked(key)
}

func (c *TTL[K, V]) expireIfStale(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok || entry.expires.IsZero() || !c.now().After(entry.expires) {
		return false
	}
	delete(c.items, key)
	c.recordExpired()
	return true
}
