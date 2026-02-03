package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
)

func TestCacheHitMiss(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := New(10, clock)
	key := dns.Question{Name: "Example.com", Type: 1, Class: 1}

	_, ok := cache.Get(key)
	require.False(t, ok)

	cache.Set(key, []byte{1, 2, 3}, 5*time.Second)
	value, ok := cache.Get(key)
	require.True(t, ok)
	require.Equal(t, []byte{1, 2, 3}, value)
}

func TestCacheExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := New(10, clock)
	key := dns.Question{Name: "example.com", Type: 1, Class: 1}

	cache.Set(key, []byte{9}, time.Second)
	_, ok := cache.Get(key)
	require.True(t, ok)

	now = now.Add(2 * time.Second)
	_, ok = cache.Get(key)
	require.False(t, ok)
}

func TestCacheEviction(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := New(2, clock)

	cache.Set(dns.Question{Name: "a.com", Type: 1, Class: 1}, []byte{1}, time.Minute)
	cache.Set(dns.Question{Name: "b.com", Type: 1, Class: 1}, []byte{2}, time.Minute)
	cache.Set(dns.Question{Name: "c.com", Type: 1, Class: 1}, []byte{3}, time.Minute)

	_, ok := cache.Get(dns.Question{Name: "a.com", Type: 1, Class: 1})
	require.False(t, ok)
	value, ok := cache.Get(dns.Question{Name: "c.com", Type: 1, Class: 1})
	require.True(t, ok)
	require.Equal(t, []byte{3}, value)
}

func TestCacheStress(t *testing.T) {
	cache := New(100, nil)
	var wg sync.WaitGroup
	numGoroutines := 100
	opsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				keyID := (id*opsPerGoroutine + j) % 200
				key := dns.Question{Name: "key-" + string(rune(keyID)) + ".com", Type: 1, Class: 1}

				if j%2 == 0 {
					cache.Set(key, []byte{byte(keyID)}, time.Minute)
				} else {
					cache.Get(key)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestCacheRaceWithExpiry(t *testing.T) {
	// This test specifically triggers the race condition where Get() tries to
	// remove expired entries while holding only a read lock
	now := time.Now()
	clock := func() time.Time { return now }
	cache := New(100, clock)
	var wg sync.WaitGroup

	// Set some entries that will expire
	for i := 0; i < 50; i++ {
		key := dns.Question{Name: "expire-" + string(rune(i)) + ".com", Type: 1, Class: 1}
		cache.Set(key, []byte{byte(i)}, time.Second)
	}

	// Advance time so entries are expired
	now = now.Add(2 * time.Second)

	// Concurrent reads that trigger expired entry removal
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				keyID := j % 50
				key := dns.Question{Name: "expire-" + string(rune(keyID)) + ".com", Type: 1, Class: 1}
				cache.Get(key)
			}
		}(i)
	}
	wg.Wait()
}

func TestCacheRaceWithLRUPromotion(t *testing.T) {
	// This test triggers race on LRU list manipulation during concurrent reads
	cache := New(100, nil)
	var wg sync.WaitGroup

	// Pre-populate cache
	for i := 0; i < 50; i++ {
		key := dns.Question{Name: "key-" + string(rune(i)) + ".com", Type: 1, Class: 1}
		cache.Set(key, []byte{byte(i)}, time.Hour)
	}

	// Concurrent reads that trigger MoveToFront
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				keyID := j % 50
				key := dns.Question{Name: "key-" + string(rune(keyID)) + ".com", Type: 1, Class: 1}
				cache.Get(key)
			}
		}(i)
	}
	wg.Wait()
}
