package cache

import (
	"container/list"
	"sync"
	"time"

	"picodns/internal/dns"
)

type Clock func() time.Time

type Cache struct {
	mu    sync.RWMutex
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
	if max <= 0 {
		return &Cache{clock: clock}
	}
	return &Cache{
		max:   max,
		clock: clock,
		items: make(map[dns.Question]*list.Element),
		lru:   list.New(),
	}
}

func (c *Cache) Get(key dns.Question) ([]byte, bool) {
	if c == nil || c.items == nil {
		return nil, false
	}
	key = key.Normalize()

	c.mu.RLock()
	defer c.mu.RUnlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := elem.Value.(*entry)
	if !item.expires.IsZero() && c.clock().After(item.expires) {
		c.removeElement(elem)
		return nil, false
	}
	if len(item.value) == 0 {
		return nil, false
	}
	if c.lru != nil {
		c.lru.MoveToFront(elem)
	}
	value := make([]byte, len(item.value))
	copy(value, item.value)
	return value, true
}

func (c *Cache) Set(key dns.Question, value []byte, ttl time.Duration) bool {
	if c == nil || c.items == nil {
		return false
	}
	if ttl <= 0 {
		return false
	}
	key = key.Normalize()

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		item := elem.Value.(*entry)
		item.value = cloneBytes(value)
		item.expires = c.clock().Add(ttl)
		if c.lru != nil {
			c.lru.MoveToFront(elem)
		}
		return true
	}

	item := &entry{
		key:     key,
		value:   cloneBytes(value),
		expires: c.clock().Add(ttl),
	}
	elem := c.lru.PushFront(item)
	c.items[key] = elem

	for c.lru.Len() > c.max {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.removeElement(back)
	}
	return true
}

func (c *Cache) removeElement(elem *list.Element) {
	item := elem.Value.(*entry)
	delete(c.items, item.key)
	c.lru.Remove(elem)
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}
