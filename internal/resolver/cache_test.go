package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

type stubResolver struct {
	resp []byte
	err  error
	call int
}

func (s *stubResolver) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	s.call++
	return s.resp, s.err
}

func TestCachedResolverStoresAndHits(t *testing.T) {
	req := makeQuery("example.com")
	resp := makeResponse(req, 30)
	store := cache.New(10, time.Now)
	up := &stubResolver{resp: resp}
	res := NewCached(store, up)

	first, err := res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resp, first)

	second, err := res.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, resp, second)
	require.Equal(t, 1, up.call)

	require.Equal(t, uint64(1), res.hits.Load())
	require.Equal(t, uint64(1), res.misses.Load())
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
