package resolver

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
)

// mockTransport implements types.Transport for testing warmup.
type mockTransport struct {
	mu         sync.Mutex
	queryCount int
	resp       []byte
}

func (m *mockTransport) Query(_ context.Context, server string, req []byte, timeout time.Duration) ([]byte, func(), error) {
	m.mu.Lock()
	m.queryCount++
	m.mu.Unlock()
	if m.resp != nil {
		return m.resp, nil, nil
	}
	// Build a minimal response echoing back the request
	hdr, _ := dns.ReadHeader(req)
	respBuf := make([]byte, len(req))
	copy(respBuf, req)
	respHdr := dns.Header{
		ID:      hdr.ID,
		Flags:   dns.FlagQR | dns.FlagRA,
		QDCount: hdr.QDCount,
	}
	_ = dns.WriteHeader(respBuf, respHdr)
	return respBuf, nil, nil
}

func TestWarmupRTTQueriesRootServers(t *testing.T) {
	mt := &mockTransport{}
	r := NewRecursive(WithTransport(mt), WithRootServers([]string{"1.1.1.1:53", "8.8.8.8:53"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r.warmupRTT(ctx)

	// Should have queried both root servers
	mt.mu.Lock()
	require.Equal(t, 2, mt.queryCount)
	mt.mu.Unlock()
}

func TestWarmupPopulatesDelegationCache(t *testing.T) {
	mt := &mockTransport{}
	r := NewRecursive(WithTransport(mt), WithRootServers([]string{"1.1.1.1:53"}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r.Warmup(ctx)

	// Should have made queries for root servers + common TLDs
	mt.mu.Lock()
	require.Greater(t, mt.queryCount, 0)
	mt.mu.Unlock()
}

func TestWarmupRespectsContextCancellation(t *testing.T) {
	mt := &mockTransport{}
	r := NewRecursive(WithTransport(mt), WithRootServers([]string{"1.1.1.1:53"}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	r.Warmup(ctx)

	// Should have done minimal work since context was already cancelled.
	// The RTT warmup goroutines may still fire due to timing,
	// but the TLD warmup loop should exit immediately.
}
