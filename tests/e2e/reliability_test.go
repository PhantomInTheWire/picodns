package e2e

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"picodns/internal/cache"
	"picodns/internal/config"
	"picodns/internal/dns"
	"picodns/internal/resolver"
	"picodns/internal/server"
	"picodns/tests/testutil"

	"github.com/stretchr/testify/require"
)

// TestE2ETCPFallback tests that the server correctly falls back to TCP
// when a UDP response is truncated. It queries a domain that typically
// has large responses (dns.google).
func TestE2ETCPFallback(t *testing.T) {
	requireNetwork(t)

	upstreamServers := []string{"8.8.8.8:53"}
	serverAddr, stopServer := testutil.StartServerWithUpstreams(t, upstreamServers)
	defer stopServer()

	resp := sendQuery(t, serverAddr, "dns.google")
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err, "Failed to parse DNS response")

	require.True(t, msg.Header.Flags&0x8000 != 0, "QR bit should be set (response)")
	require.GreaterOrEqual(t, msg.Header.ANCount, uint16(1), "Should have at least 1 answer")
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F, "Should have NOERROR rcode")

	require.False(t, msg.Header.Flags&0x0200 != 0, "Response should not be truncated (TC bit should not be set)")

	require.GreaterOrEqual(t, len(msg.Answers), 1, "Should have at least 1 answer record")

	for _, answer := range msg.Answers {
		require.True(t, answer.Type == dns.TypeA || answer.Type == dns.TypeAAAA || answer.Type == dns.TypeCNAME,
			"Answer should be a valid record type (A, AAAA, or CNAME)")
	}
}

func TestE2EBackpressure(t *testing.T) {
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = upstreamConn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		buf := make([]byte, 512)
		for {
			_ = upstreamConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, readErr := upstreamConn.ReadFrom(buf)
			if readErr != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			// Artificial delay to fill the queue
			time.Sleep(50 * time.Millisecond)
			resp, _ := dns.BuildResponse(buf[:n], []dns.Answer{
				{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   60,
					RData: []byte{1, 1, 1, 1},
				},
			}, 0)
			_, _ = upstreamConn.WriteTo(resp, addr)
		}
	}()

	upstreamAddr := upstreamConn.LocalAddr().String()

	cfg := config.Default()
	cfg.Upstreams = []string{upstreamAddr}
	cfg.Workers = 1

	listen, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	serverAddr := listen.LocalAddr().String()
	_ = listen.Close()
	cfg.ListenAddrs = []string{serverAddr}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	up, err := resolver.NewUpstream(cfg.Upstreams)
	require.NoError(t, err)
	store := cache.New(cfg.CacheSize, nil)
	res := resolver.NewCached(store, up)

	srv := server.New(cfg, logger, res)
	go func() {
		_ = srv.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	numQueries := 50
	for i := 0; i < numQueries; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = sendQuerySilent(serverAddr, "example.com")
		}(i)
	}
	wg.Wait()

	require.Greater(t, srv.DroppedPackets.Load(), uint64(0), "Should have dropped packets")
	resp := sendQuery(t, serverAddr, "stable.com")
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err, "Failed to parse DNS response")

	require.True(t, msg.Header.Flags&0x8000 != 0, "QR bit should be set (response)")
	require.Equal(t, uint16(1), msg.Header.ANCount, "Should have 1 answer")
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F, "Should have NOERROR rcode")

	require.Len(t, msg.Answers, 1, "Should have exactly 1 answer")
	answer := msg.Answers[0]
	require.Equal(t, dns.TypeA, answer.Type, "Answer should be Type A")
	require.Equal(t, dns.ClassIN, answer.Class, "Answer should be Class IN")
	require.Equal(t, []byte{1, 1, 1, 1}, answer.Data, "Answer RData should be 1.1.1.1")
}

func sendQuerySilent(addr string, name string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	req := makeQuery(name)
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = conn.Write(req)
	if err != nil {
		return err
	}

	buf := make([]byte, 512)
	_, err = conn.Read(buf)
	return err
}
