package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnPoolGetAndRelease(t *testing.T) {
	p := newConnPool()
	ctx := context.Background()

	conn, release, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.NotNil(t, release)

	// Release normally (not bad)
	release(false)

	// Should be able to get the same conn back from pool
	conn2, release2, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn2)
	release2(false)
}

func TestConnPoolBadRelease(t *testing.T) {
	p := newConnPool()
	ctx := context.Background()

	conn1, release1, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn1)
	localAddr1 := conn1.LocalAddr().String()

	// Release as bad - should close and remove from pool
	release1(true)

	// Next get should create a new connection (different local addr)
	conn2, release2, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn2)
	require.NotEqual(t, localAddr1, conn2.LocalAddr().String())
	release2(false)
}

func TestConnPoolMaxConns(t *testing.T) {
	p := newConnPool()
	ctx := context.Background()

	// Acquire ConnPoolMaxConns connections
	type held struct {
		release func(bool)
	}
	var conns []held
	for i := 0; i < ConnPoolMaxConns; i++ {
		_, rel, err := p.get(ctx)
		require.NoError(t, err)
		conns = append(conns, held{release: rel})
	}

	// Next connection should still work (ephemeral)
	conn, rel, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn)
	rel(false) // ephemeral - just closes

	// Release all pooled
	for _, c := range conns {
		c.release(false)
	}
}

func TestConnPoolIdleExpiry(t *testing.T) {
	p := newConnPool()
	ctx := context.Background()

	conn1, release1, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn1)
	release1(false)

	// Manually set lastUsed to long ago to simulate idle timeout
	p.mu.Lock()
	if len(p.conns) > 0 {
		p.conns[0].lastUsed = time.Now().Add(-ConnPoolIdleTimeout - time.Second)
	}
	p.mu.Unlock()

	// Force a prune cycle
	p.mu.Lock()
	p.lastPrune = time.Time{} // Reset to force prune
	p.mu.Unlock()

	// Next get should create new connection since old one is expired
	conn2, release2, err := p.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn2)
	release2(false)
}
