package cache

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/dns"
)

type Clock func() time.Time

// Cache is a sharded LRU cache for DNS questions.
type Cache struct {
	shards    []*cacheShard
	shardMask uint64
	clock     Clock
}

type cacheShard struct {
	mu    sync.RWMutex
	max   int
	items map[uint64]*list.Element
	lru   *list.List
}

type entry struct {
	key     uint64
	value   []byte
	ttlOffs []uint16
	expires time.Time
	hits    uint64
	origTTL time.Duration
}

// New creates a new sharded Cache with the given maximum total entries.
// Each shard will have a capacity of max/numShards.
// Use single shard for very small caches to maintain predictable eviction
func New(max int, clock Clock) *Cache {
	if clock == nil {
		clock = time.Now
	}

	numShards := 256
	if max > 0 && max < 256 {
		numShards = 1
	}

	shardMax := max / numShards
	if shardMax == 0 && max > 0 {
		shardMax = 1
	}

	c := &Cache{
		shards:    make([]*cacheShard, numShards),
		shardMask: uint64(numShards - 1),
		clock:     clock,
	}

	for i := 0; i < numShards; i++ {
		c.shards[i] = &cacheShard{
			max:   shardMax,
			items: make(map[uint64]*list.Element),
			lru:   list.New(),
		}
	}

	return c
}

func (c *Cache) getShard(key uint64) *cacheShard {
	if len(c.shards) == 1 {
		return c.shards[0]
	}
	return c.shards[key&c.shardMask]
}

func questionKey(q dns.Question) uint64 {
	h := dns.HashNameString(q.Name)
	h ^= uint64(q.Type) << 32
	h ^= uint64(q.Class)
	return h
}

func (c *Cache) Get(key dns.Question) ([]byte, bool) {
	val, _, _, _, _, ok := c.GetWithMetadata(key)
	return val, ok
}

func (c *Cache) GetWithMetadata(key dns.Question) (value []byte, expires time.Time, hits uint64, origTTL time.Duration, ttlOffs []uint16, ok bool) {
	k := questionKey(key)
	return c.GetWithMetadataKey(k)
}

func (c *Cache) GetWithMetadataKey(key uint64) (value []byte, expires time.Time, hits uint64, origTTL time.Duration, ttlOffs []uint16, ok bool) {
	shard := c.getShard(key)

	shard.mu.RLock()
	elem, ok := shard.items[key]
	if !ok {
		shard.mu.RUnlock()
		return nil, time.Time{}, 0, 0, nil, false
	}

	item := elem.Value.(*entry)
	if !item.expires.IsZero() && c.clock().After(item.expires) {
		shard.mu.RUnlock()
		// Expired: upgrade to write lock to remove
		shard.mu.Lock()
		// Double-check after acquiring write lock
		if elem2, ok2 := shard.items[key]; ok2 {
			item2 := elem2.Value.(*entry)
			if !item2.expires.IsZero() && c.clock().After(item2.expires) {
				shard.removeElement(elem2)
			}
		}
		shard.mu.Unlock()
		return nil, time.Time{}, 0, 0, nil, false
	}

	// Update hit count atomically to avoid write lock contention.
	// LRU is updated only on write to keep reads lock-free.
	hits = atomic.AddUint64(&item.hits, 1)
	value = item.value
	expires = item.expires
	origTTL = item.origTTL
	ttlOffs = item.ttlOffs
	shard.mu.RUnlock()
	return value, expires, hits, origTTL, ttlOffs, true
}

func (c *Cache) Set(key dns.Question, value []byte, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	k := questionKey(key)
	return c.SetKey(k, value, ttl)
}

func (c *Cache) SetKey(key uint64, value []byte, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	expires := c.clock().Add(ttl)
	valCopy := append([]byte(nil), value...)
	offs, _ := dns.CollectTTLOffsets(valCopy)

	if elem, ok := shard.items[key]; ok {
		item := elem.Value.(*entry)
		// Do not mutate the existing backing array in-place.
		// GetWithMetadata returns item.value to callers after unlocking;
		// in-place mutation here can race and corrupt readers.
		item.value = valCopy
		item.ttlOffs = offs
		item.expires = expires
		item.origTTL = ttl
		shard.lru.MoveToFront(elem)
		return true
	}

	elem := shard.lru.PushFront(&entry{
		key:     key,
		value:   valCopy,
		ttlOffs: offs,
		expires: expires,
		origTTL: ttl,
		hits:    1,
	})
	shard.items[key] = elem

	if shard.lru.Len() > shard.max {
		shard.removeElement(shard.lru.Back())
	}
	return true
}

func (s *cacheShard) removeElement(elem *list.Element) {
	delete(s.items, elem.Value.(*entry).key)
	s.lru.Remove(elem)
}
