package resolver

import (
	"context"
	"picodns/internal/cache"
	"testing"
	"time"
)

func BenchmarkResolveFromCache(b *testing.B) {
	store := cache.New(10000, time.Now)
	up := &stubResolver{resp: makeResponse(makeQuery("example.com"), 300)}
	cr := NewCached(store, up)

	req := makeQuery("example.com")
	// Populate cache
	_, _, err := cr.Resolve(context.Background(), req)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, cleanup, ok := cr.ResolveFromCache(ctx, req)
		if !ok {
			b.Fatal("expected cache hit")
		}
		if cleanup != nil {
			cleanup()
		}
		_ = resp
	}
}

func BenchmarkResolveFromCacheMiss(b *testing.B) {
	store := cache.New(10000, nil)
	cr := NewCached(store, nil)

	req := makeQuery("example.com")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cr.ResolveFromCache(ctx, req)
	}
}
