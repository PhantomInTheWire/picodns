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
