package resolver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

type stubResolver struct {
	mu   sync.Mutex
	resp []byte
	err  error
	call int
}

func (s *stubResolver) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.call++
	return s.resp, nil, s.err
}

func (s *stubResolver) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.call
}

func TestCachedResolverStoresAndHits(t *testing.T) {
	req := makeQuery("example.com")
	resp := makeResponse(req, 30)
	store := cache.New(10, time.Now)
	up := &stubResolver{resp: resp}
	res := NewCached(store, up)

	first, _, err := res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resp, first)

	second, _, err := res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resp, second)
	require.Equal(t, 1, up.CallCount())
}

func TestCachedResolverPrefetch(t *testing.T) {
	var mu sync.Mutex
	currTime := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return currTime
	}

	req := makeQuery("prefetch.com")
	resp := makeResponse(req, 100)
	store := cache.New(10, clock)
	up := &stubResolver{resp: resp}
	res := NewCached(store, up)
	res.clock = clock
	res.Prefetch = true

	// 1st call: Miss, store in cache
	_, _, err := res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, up.CallCount())

	// 2nd call: Hit (hits=2)
	_, _, err = res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, up.CallCount())

	// 3rd call: Hit (hits=3, threshold reached)
	_, _, err = res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, up.CallCount())

	// Advance time to 91s (9s remaining, < 10% of 100s)
	mu.Lock()
	currTime = currTime.Add(91 * time.Second)
	mu.Unlock()

	// 4th call: Hit + Trigger Prefetch
	_, _, err = res.Resolve(context.Background(), req)
	require.NoError(t, err)

	// Wait for background prefetch
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if up.CallCount() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Prefetch should have called upstream
	require.GreaterOrEqual(t, up.CallCount(), 2)
}

func makeQuery(name string) []byte {
	buf := make([]byte, 512)
	_ = dns.WriteHeader(buf, dns.Header{ID: 0xBEEF, Flags: 0x0100, QDCount: 1})
	end, _ := dns.WriteQuestion(buf, dns.HeaderLen, dns.Question{Name: name, Type: dns.TypeA, Class: dns.ClassIN})
	return buf[:end]
}

func makeResponse(req []byte, ttl uint32) []byte {
	resp, _ := dns.BuildResponse(req, []dns.Answer{
		{
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   ttl,
			RData: []byte{127, 0, 0, 1},
		},
	}, 0)
	return resp
}

func TestCachedResolverEarlyReturnWithCachedIPs(t *testing.T) {
	req := makeQuery("example.com")
	resp := makeResponse(req, 300)
	store := cache.New(10, time.Now)
	up := &stubResolver{resp: resp}
	res := NewCached(store, up)

	_, _, err := res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, up.CallCount())

	_, _, err = res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, up.CallCount())
}

func TestCacheMetadataTracking(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	store := cache.New(10, clock)
	up := &stubResolver{resp: makeResponse(makeQuery("test.com"), 60)}
	res := NewCached(store, up)

	_, _, err := res.Resolve(context.Background(), makeQuery("test.com"))
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		_, _, err = res.Resolve(context.Background(), makeQuery("test.com"))
		require.NoError(t, err)
	}

	key := dns.Question{Name: "test.com", Type: 1, Class: 1}
	_, _, hits, origTTL, ok := store.GetWithMetadata(key)
	require.True(t, ok)
	require.GreaterOrEqual(t, hits, uint64(6))
	require.Equal(t, time.Duration(60)*time.Second, origTTL)
}

func TestCachedResolverRewritesIDFromCache(t *testing.T) {
	store := cache.New(10, time.Now)
	up := &stubResolver{resp: makeResponse(makeQuery("example.com"), 60)}
	res := NewCached(store, up)

	firstReq := makeQuery("example.com")
	_, _, err := res.Resolve(context.Background(), firstReq)
	require.NoError(t, err)
	require.Equal(t, 1, up.CallCount())

	secondReq := makeQuery("example.com")
	secondReq[0] = 0x12
	secondReq[1] = 0x34
	resp, cleanup, err := res.Resolve(context.Background(), secondReq)
	require.NoError(t, err)
	if cleanup != nil {
		cleanup()
	}
	require.Equal(t, uint16(0x1234), dnsID(resp))
	require.Equal(t, 1, up.CallCount())
}

func dnsID(resp []byte) uint16 {
	if len(resp) < 2 {
		return 0
	}
	return uint16(resp[0])<<8 | uint16(resp[1])
}
