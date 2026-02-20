package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTTLCacheExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	cache := NewTTL[string, int](clock)

	cache.Set("a", 1, 2*time.Second)
	val, ok := cache.Get("a")
	require.True(t, ok)
	require.Equal(t, 1, val)

	now = now.Add(3 * time.Second)
	_, ok = cache.Get("a")
	require.False(t, ok)
}

func TestPermanentCacheDoesNotExpire(t *testing.T) {
	cache := NewPermanentCache[string, int]()

	cache.Set("a", 1)
	val, ok := cache.Get("a")
	require.True(t, ok)
	require.Equal(t, 1, val)
}
