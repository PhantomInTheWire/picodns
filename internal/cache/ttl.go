package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// TTL is a generic cache with TTL-based expiration.
// It provides simple Get/Set/Delete operations with automatic expiration.
type TTL[K comparable, V any] struct {
	mu     sync.RWMutex
	items  map[K]ttlEntry[V]
	clock  func() time.Time
	MaxLen int

	ObsEnabled bool
	gets       atomic.Uint64
	hits       atomic.Uint64
	misses     atomic.Uint64
	expired    atomic.Uint64
	sets       atomic.Uint64
	deletes    atomic.Uint64
}

type TTLStatsSnapshot struct {
	Gets    uint64
	Hits    uint64
	Misses  uint64
	Expired uint64
	Sets    uint64
	Deletes uint64
	Len     int
}

type ttlEntry[V any] struct {
	value   V
	expires time.Time
}

// NewTTL creates a new TTL cache with the given clock function.
// If clock is nil, time.Now is used.
func NewTTL[K comparable, V any](clock func() time.Time) *TTL[K, V] {
	if clock == nil {
		clock = time.Now
	}
	return &TTL[K, V]{
		items: make(map[K]ttlEntry[V]),
		clock: clock,
	}
}

// Get retrieves a value from the cache.
// Returns the value and true if found and not expired.
func (c *TTL[K, V]) Get(key K) (V, bool) {
	c.recordGet()
	entry, ok := c.load(key)

	if !ok {
		c.recordMiss()
		return c.zeroValue(), false
	}

	if !entry.expires.IsZero() && c.now().After(entry.expires) {
		c.expireIfStale(key)
		c.recordMiss()
		return c.zeroValue(), false
	}

	c.recordHit()

	return entry.value, true
}

// Set stores a value in the cache with the given TTL.
// If ttl <= 0, the entry is not stored.
func (c *TTL[K, V]) Set(key K, value V, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.recordSet()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.storeLocked(key, ttlEntry[V]{
		value:   value,
		expires: c.now().Add(ttl),
	})
}

// Delete removes a key from the cache.
func (c *TTL[K, V]) Delete(key K) {
	c.recordDelete()
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// Len returns the number of items in the cache (including expired ones).
func (c *TTL[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *TTL[K, V]) StatsSnapshot() TTLStatsSnapshot {
	return TTLStatsSnapshot{
		Gets:    c.gets.Load(),
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Expired: c.expired.Load(),
		Sets:    c.sets.Load(),
		Deletes: c.deletes.Load(),
		Len:     c.Len(),
	}
}

// Clear removes all items from the cache.
func (c *TTL[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]ttlEntry[V])
}

// PermanentCache is a cache that never expires entries.
// It's a thin wrapper around TTL with a permanent TTL.
type PermanentCache[K comparable, V any] struct {
	*TTL[K, V]
}

// NewPermanentCache creates a new permanent cache.
func NewPermanentCache[K comparable, V any]() *PermanentCache[K, V] {
	return &PermanentCache[K, V]{
		TTL: NewTTL[K, V](nil),
	}
}

// Get retrieves a value (ignores expiration since there is none).
func (c *PermanentCache[K, V]) Get(key K) (V, bool) {
	c.recordGet()
	entry, ok := c.load(key)

	if !ok {
		c.recordMiss()
		return c.zeroValue(), false
	}
	c.recordHit()

	return entry.value, true
}

// Set stores a value permanently (no expiration).
func (c *PermanentCache[K, V]) Set(key K, value V) {
	c.recordSet()
	c.mu.Lock()
	defer c.mu.Unlock()

	c.storeLocked(key, ttlEntry[V]{
		value:   value,
		expires: time.Time{}, // Zero time = never expires
	})
}
