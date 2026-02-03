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
	if c.items == nil {
		return nil, false
	}
	key = key.Normalize()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := elem.Value.(*entry)
	if !item.expires.IsZero() && c.clock().After(item.expires) {
		c.removeElement(elem)
		return nil, false
	}
	c.lru.MoveToFront(elem)
	return item.value, true
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
		c.lru.MoveToFront(elem)
		return true
	}

	elem := c.lru.PushFront(&entry{key: key, value: append([]byte(nil), value...), expires: expires})
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
