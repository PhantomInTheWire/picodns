package cache

import (
	"sync"
	"time"
)

// TTL is a generic cache with TTL-based expiration.
// It provides simple Get/Set/Delete operations with automatic expiration.
type TTL[K comparable, V any] struct {
	mu    sync.RWMutex
	items map[K]ttlEntry[V]
	clock func() time.Time
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
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		var zero V
		return zero, false
	}

	if !entry.expires.IsZero() && c.clock().After(entry.expires) {
		c.mu.Lock()
		// Double-check after acquiring write lock
		if entry2, ok2 := c.items[key]; ok2 && !entry2.expires.IsZero() && c.clock().After(entry2.expires) {
			delete(c.items, key)
		}
		c.mu.Unlock()
		var zero V
		return zero, false
	}

	return entry.value, true
}

// Set stores a value in the cache with the given TTL.
// If ttl <= 0, the entry is not stored.
func (c *TTL[K, V]) Set(key K, value V, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = ttlEntry[V]{
		value:   value,
		expires: c.clock().Add(ttl),
	}
}

// Delete removes a key from the cache.
func (c *TTL[K, V]) Delete(key K) {
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

// Clear removes all items from the cache.
func (c *TTL[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]ttlEntry[V])
}

// Permanent is a special TTL value that indicates the entry should never expire.
// Use this for addrCache where addresses don't change.
const Permanent = time.Duration(0)

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
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		var zero V
		return zero, false
	}

	return entry.value, true
}

// Set stores a value permanently (no expiration).
func (c *PermanentCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = ttlEntry[V]{
		value:   value,
		expires: time.Time{}, // Zero time = never expires
	}
}
