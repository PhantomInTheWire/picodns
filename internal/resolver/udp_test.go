package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/pool"
)

func TestTransportQueryHonorsCallerTimeout(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	req := []byte{1, 2, 3, 4}
	resp := []byte{5, 6, 7, 8}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 64)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n > 0 {
			time.Sleep(150 * time.Millisecond)
			_, _ = conn.WriteTo(resp, addr)
		}
	}()

	transport := NewTransport(pool.DefaultPool, newConnPool(), 50*time.Millisecond)
	got, cleanup, err := transport.Query(context.Background(), conn.LocalAddr().String(), req, 300*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, resp, got)
	if cleanup != nil {
		cleanup()
	}
	<-serverDone
}
