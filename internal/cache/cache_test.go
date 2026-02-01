package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCacheHitMiss(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := New(10, clock)
	key := Key{Name: "Example.com", Type: 1, Class: 1}

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
	key := Key{Name: "example.com", Type: 1, Class: 1}

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

	cache.Set(Key{Name: "a.com", Type: 1, Class: 1}, []byte{1}, time.Minute)
	cache.Set(Key{Name: "b.com", Type: 1, Class: 1}, []byte{2}, time.Minute)
	cache.Set(Key{Name: "c.com", Type: 1, Class: 1}, []byte{3}, time.Minute)

	_, ok := cache.Get(Key{Name: "a.com", Type: 1, Class: 1})
	require.False(t, ok)
	value, ok := cache.Get(Key{Name: "c.com", Type: 1, Class: 1})
	require.True(t, ok)
	require.Equal(t, []byte{3}, value)
}
