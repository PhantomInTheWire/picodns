package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpstreamResolve(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			return
		}
		if n > 0 {
			_, _ = conn.WriteTo([]byte{1, 2, 3}, addr)
		}
	}()

	r := NewUpstream([]string{conn.LocalAddr().String()}, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := r.Resolve(ctx, []byte{9, 9, 9})
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, resp)

	require.Equal(t, uint64(1), r.queryCount.Load())
	require.Greater(t, r.totalLatency.Load(), uint64(0))

	<-done
}
