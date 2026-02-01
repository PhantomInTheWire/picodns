package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

type Clock func() time.Time

type Key struct {
	Name  string
	Type  uint16
	Class uint16
}

type Cache struct {
	mu    sync.Mutex
	max   int
	clock Clock
	items map[Key]*list.Element
	lru   *list.List
}

type entry struct {
	key     Key
	value   []byte
	expires time.Time
}

func New(max int, clock Clock) *Cache {
	if clock == nil {
		clock = time.Now
	}
	return &Cache{
		max:   max,
		clock: clock,
		items: make(map[Key]*list.Element),
		lru:   list.New(),
	}
}

func (c *Cache) Get(key Key) ([]byte, bool) {
	if c == nil || c.max <= 0 {
		return nil, false
	}
	key = normalizeKey(key)

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
	if len(item.value) == 0 {
		return nil, false
	}
	c.lru.MoveToFront(elem)
	value := make([]byte, len(item.value))
	copy(value, item.value)
	return value, true
}

func (c *Cache) Set(key Key, value []byte, ttl time.Duration) {
	if c == nil || c.max <= 0 {
		return
	}
	if ttl <= 0 {
		return
	}
	key = normalizeKey(key)

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		item := elem.Value.(*entry)
		item.value = cloneBytes(value)
		item.expires = c.clock().Add(ttl)
		c.lru.MoveToFront(elem)
		return
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
}

func (c *Cache) removeElement(elem *list.Element) {
	item := elem.Value.(*entry)
	delete(c.items, item.key)
	c.lru.Remove(elem)
}

func normalizeKey(key Key) Key {
	key.Name = strings.ToLower(strings.TrimSuffix(key.Name, "."))
	return key
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}
