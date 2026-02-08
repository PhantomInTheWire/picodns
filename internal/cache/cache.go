package cache

import (
	"container/list"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
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
	mu    sync.Mutex
	max   int
	items map[dns.Question]*list.Element
	lru   *list.List
}

type entry struct {
	key     dns.Question
	value   []byte
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
			items: make(map[dns.Question]*list.Element),
			lru:   list.New(),
		}
	}

	return c
}

// Use xxhash for fast distribution.
// We hash the normalized name, type, and class to ensure consistent sharding.
// Combine with type and class using simple XOR/shift for speed
func (c *Cache) getShard(key dns.Question) *cacheShard {
	if len(c.shards) == 1 {
		return c.shards[0]
	}

	h := xxhash.Sum64String(key.Name)
	h ^= uint64(key.Type) << 32
	h ^= uint64(key.Class)

	return c.shards[h&c.shardMask]
}

func (c *Cache) Get(key dns.Question) ([]byte, bool) {
	val, _, _, _, ok := c.GetWithMetadata(key)
	return val, ok
}

func (c *Cache) GetWithMetadata(key dns.Question) (value []byte, expires time.Time, hits uint64, origTTL time.Duration, ok bool) {
	key = key.Normalize()
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	elem, ok := shard.items[key]
	if !ok {
		return nil, time.Time{}, 0, 0, false
	}

	item := elem.Value.(*entry)
	if !item.expires.IsZero() && c.clock().After(item.expires) {
		shard.removeElement(elem)
		return nil, time.Time{}, 0, 0, false
	}

	item.hits++
	shard.lru.MoveToFront(elem)
	return item.value, item.expires, item.hits, item.origTTL, true
}

func (c *Cache) Set(key dns.Question, value []byte, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	key = key.Normalize()
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	expires := c.clock().Add(ttl)
	if elem, ok := shard.items[key]; ok {
		item := elem.Value.(*entry)
		// Reuse buffer if possible to reduce allocations
		if cap(item.value) >= len(value) {
			item.value = item.value[:len(value)]
			copy(item.value, value)
		} else {
			item.value = append([]byte(nil), value...)
		}
		item.expires = expires
		item.origTTL = ttl
		shard.lru.MoveToFront(elem)
		return true
	}

	elem := shard.lru.PushFront(&entry{
		key:     key,
		value:   append([]byte(nil), value...),
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
