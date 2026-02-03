package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpstreamResolve(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

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

	<-done
}

func TestUpstreamTCPSizeLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	// Temporarily reduce maxTCPSize for testing
	oldMax := maxTCPSize
	maxTCPSize = 10
	defer func() { maxTCPSize = oldMax }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the length and request to ensure the client has finished writing
		var reqLen uint16
		if err := binary.Read(conn, binary.BigEndian, &reqLen); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(reqLen)); err != nil {
			return
		}

		_ = binary.Write(conn, binary.BigEndian, uint16(20))
	}()

	u := NewUpstream([]string{ln.Addr().String()}, time.Second)
	_, err = u.queryTCP(context.Background(), ln.Addr().String(), []byte{1, 2, 3})
	require.Error(t, err)
	require.Contains(t, err.Error(), "tcp response too large")
}
