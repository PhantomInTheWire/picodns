package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"picodns/internal/dns"
)

func TestUpstreamResolve(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Create a valid DNS query
	reqBuf := make([]byte, 512)
	_ = dns.WriteHeader(reqBuf, dns.Header{ID: 0x1234, Flags: 0x0100, QDCount: 1})
	end, _ := dns.WriteQuestion(reqBuf, dns.HeaderLen, dns.Question{Name: "test.example.com", Type: dns.TypeA, Class: dns.ClassIN})
	req := reqBuf[:end]

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		n, addr, _ := conn.ReadFrom(buf)
		if n == 0 {
			return
		}

		resp, _ := dns.BuildResponse(buf[:n], []dns.Answer{
			{Name: "", Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: net.ParseIP("192.0.2.1").To4()},
		}, dns.RcodeSuccess)
		_, _ = conn.WriteTo(resp, addr)
	}()

	r, err := NewUpstream([]string{conn.LocalAddr().String()})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, cleanup, err := r.Resolve(ctx, req)
	require.NoError(t, err)
	defer cleanup()

	respMsg, err := dns.ReadMessagePooled(resp)
	require.NoError(t, err)
	defer respMsg.Release()

	require.GreaterOrEqual(t, len(respMsg.Answers), 1)
	require.Equal(t, uint16(0x1234), respMsg.Header.ID)

	<-done
}
