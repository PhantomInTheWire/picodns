package cache

import (
	"container/list"
	"sync"
	"time"

	"picodns/internal/dns"
)

type Clock func() time.Time

type Cache struct {
	mu    sync.Mutex
	max   int
	clock Clock
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

func New(max int, clock Clock) *Cache {
	if clock == nil {
		clock = time.Now
	}
	c := &Cache{
		max:   max,
		clock: clock,
	}
	if max > 0 {
		c.items = make(map[dns.Question]*list.Element)
		c.lru = list.New()
	}
	return c
}

func (c *Cache) Get(key dns.Question) ([]byte, bool) {
	val, _, _, _, ok := c.GetWithMetadata(key)
	return val, ok
}

func (c *Cache) GetWithMetadata(key dns.Question) (value []byte, expires time.Time, hits uint64, origTTL time.Duration, ok bool) {
	if c.items == nil {
		return nil, time.Time{}, 0, 0, false
	}
	key = key.Normalize()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, time.Time{}, 0, 0, false
	}
	item := elem.Value.(*entry)
	if !item.expires.IsZero() && c.clock().After(item.expires) {
		c.removeElement(elem)
		return nil, time.Time{}, 0, 0, false
	}
	item.hits++
	c.lru.MoveToFront(elem)
	return item.value, item.expires, item.hits, item.origTTL, true
}

func (c *Cache) Set(key dns.Question, value []byte, ttl time.Duration) bool {
	if c.items == nil || ttl <= 0 {
		return false
	}
	key = key.Normalize()

	c.mu.Lock()
	defer c.mu.Unlock()

	expires := c.clock().Add(ttl)
	if elem, ok := c.items[key]; ok {
		item := elem.Value.(*entry)
		item.value = append([]byte(nil), value...)
		item.expires = expires
		item.origTTL = ttl
		c.lru.MoveToFront(elem)
		return true
	}

	elem := c.lru.PushFront(&entry{
		key:     key,
		value:   append([]byte(nil), value...),
		expires: expires,
		origTTL: ttl,
		hits:    1,
	})
	c.items[key] = elem

	if c.lru.Len() > c.max {
		c.removeElement(c.lru.Back())
	}
	return true
}

func (c *Cache) removeElement(elem *list.Element) {
	delete(c.items, elem.Value.(*entry).key)
	c.lru.Remove(elem)
}
