package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDelegationCacheSetAndGet(t *testing.T) {
	dc := newDelegationCache()

	dc.Set("com.", []string{"1.2.3.4:53"}, 5*time.Minute)
	servers, ok := dc.Get("com.")
	require.True(t, ok)
	require.Equal(t, []string{"1.2.3.4:53"}, servers)
}

func TestDelegationCacheTTLClamping(t *testing.T) {
	dc := newDelegationCache()

	// TTL too high should be clamped to 24h
	dc.Set("com.", []string{"1.2.3.4:53"}, 48*time.Hour)
	servers, ok := dc.Get("com.")
	require.True(t, ok)
	require.Equal(t, []string{"1.2.3.4:53"}, servers)

	// TTL too low should be clamped to 5s
	dc.Set("net.", []string{"5.6.7.8:53"}, 1*time.Second)
	servers, ok = dc.Get("net.")
	require.True(t, ok)
	require.Equal(t, []string{"5.6.7.8:53"}, servers)
}

func TestDelegationCacheFindLongestMatchingZone(t *testing.T) {
	dc := newDelegationCache()

	// NormalizeName strips trailing dots, so store keys without them
	dc.Set("com", []string{"1.1.1.1:53"}, 5*time.Minute)
	dc.Set("example.com", []string{"2.2.2.2:53"}, 5*time.Minute)

	// Should match the longest zone
	zone, servers, ok := dc.FindLongestMatchingZone("www.example.com.")
	require.True(t, ok)
	require.Equal(t, "example.com", zone)
	require.Equal(t, []string{"2.2.2.2:53"}, servers)

	// Should fall back to shorter zone
	zone, servers, ok = dc.FindLongestMatchingZone("other.com.")
	require.True(t, ok)
	require.Equal(t, "com", zone)
	require.Equal(t, []string{"1.1.1.1:53"}, servers)

	// No match should return ".", nil, false
	zone, servers, ok = dc.FindLongestMatchingZone("example.org.")
	require.False(t, ok)
	require.Equal(t, ".", zone)
	require.Nil(t, servers)
}

func TestDelegationCacheRootZone(t *testing.T) {
	dc := newDelegationCache()

	dc.Set(".", []string{"root:53"}, 5*time.Minute)

	zone, servers, ok := dc.FindLongestMatchingZone("anything.example.com.")
	require.True(t, ok)
	require.Equal(t, ".", zone)
	require.Equal(t, []string{"root:53"}, servers)
}
