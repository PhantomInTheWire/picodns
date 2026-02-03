//go:build e2e

package e2e

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/cache"
	"picodns/internal/config"
	"picodns/internal/dns"
	"picodns/internal/resolver"
	"picodns/internal/server"
)

func isValidIPv4(data []byte) bool {
	return len(data) == 4
}

func TestE2EForwardAndCache(t *testing.T) {
	requireNetwork(t)

	upstreamServers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	serverAddr, stopServer := startServerWithUpstreams(t, upstreamServers)
	defer stopServer()

	// First query - should hit upstream
	start1 := time.Now()
	resp1 := sendQuery(t, serverAddr, "example.com")
	duration1 := time.Since(start1)
	msg1, err := dns.ReadMessage(resp1)
	require.NoError(t, err, "Failed to parse first DNS response")

	// Validate response header
	require.True(t, msg1.Header.Flags&0x8000 != 0, "QR bit should be set (response)")
	require.GreaterOrEqual(t, msg1.Header.ANCount, uint16(1), "Should have at least 1 answer")
	require.Equal(t, uint16(dns.RcodeSuccess), msg1.Header.Flags&0x000F, "Should have NOERROR rcode")

	// Validate answer content
	require.GreaterOrEqual(t, len(msg1.Answers), 1, "Should have at least 1 answer")
	answer := msg1.Answers[0]
	require.Equal(t, dns.TypeA, answer.Type, "Answer should be Type A")
	require.Equal(t, dns.ClassIN, answer.Class, "Answer should be Class IN")
	require.True(t, isValidIPv4(answer.Data), "Answer RData should be a valid IPv4 address")

	// Second query - should be cached and faster
	start2 := time.Now()
	resp2 := sendQuery(t, serverAddr, "example.com")
	duration2 := time.Since(start2)
	msg2, err := dns.ReadMessage(resp2)
	require.NoError(t, err, "Failed to parse second DNS response")

	// Validate second response matches first (cached)
	require.Equal(t, msg1.Header.Flags, msg2.Header.Flags)
	require.Equal(t, msg1.Header.ANCount, msg2.Header.ANCount)
	require.GreaterOrEqual(t, len(msg2.Answers), 1)
	require.True(t, isValidIPv4(msg2.Answers[0].Data))

	// Verify caching through timing (second query should be significantly faster)
	require.Less(t, duration2, duration1/2, "Cached query should be significantly faster")
}

func TestE2ENegativeCache(t *testing.T) {
	requireNetwork(t)

	upstreamServers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	serverAddr, stopServer := startServerWithUpstreams(t, upstreamServers)
	defer stopServer()

	// First query - should hit upstream
	start1 := time.Now()
	resp1 := sendQuery(t, serverAddr, "this-definitely-does-not-exist-12345.example")
	duration1 := time.Since(start1)
	msg1, err := dns.ReadMessage(resp1)
	require.NoError(t, err, "Failed to parse first DNS response")

	// Validate NXDOMAIN response header
	require.True(t, msg1.Header.Flags&0x8000 != 0, "QR bit should be set (response)")
	require.Equal(t, uint16(dns.RcodeNXDomain), msg1.Header.Flags&0x000F, "Should have NXDOMAIN rcode")
	require.Equal(t, uint16(0), msg1.Header.ANCount, "Should have 0 answers")

	// Second query - should be cached and faster
	start2 := time.Now()
	resp2 := sendQuery(t, serverAddr, "this-definitely-does-not-exist-12345.example")
	duration2 := time.Since(start2)
	msg2, err := dns.ReadMessage(resp2)
	require.NoError(t, err, "Failed to parse second DNS response")

	// Validate second response matches first (cached)
	require.Equal(t, msg1.Header.Flags, msg2.Header.Flags, "Cached response flags should match")
	require.Equal(t, msg1.Header.ANCount, msg2.Header.ANCount, "Cached ANCount should match")
	require.Equal(t, msg1.Header.NSCount, msg2.Header.NSCount, "Cached NSCount should match")

	// Verify caching through timing (second query should be significantly faster)
	require.Less(t, duration2, duration1/2, "Cached query should be significantly faster")
}

func startServerWithUpstreams(t *testing.T, upstreams []string) (string, func()) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.Default()
	cfg.Upstreams = upstreams
	cfg.Workers = 4
	cfg.Timeout = 5 * time.Second
	cfg.CacheSize = 100

	listen, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listen.LocalAddr().String()
	_ = listen.Close()

	cfg.ListenAddrs = []string{addr}

	up := resolver.NewUpstream(cfg.Upstreams, cfg.Timeout)
	store := cache.New(cfg.CacheSize, nil)
	res := resolver.NewCached(store, up)

	srv := server.New(cfg, logger, res)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	return addr, func() {
		cancel()
	}
}

func sendQuery(t *testing.T, addr string, name string) []byte {
	conn, err := net.Dial("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	req := makeQuery(name)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = conn.Write(req)
	require.NoError(t, err)

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return buf[:n]
}

func makeQuery(name string) []byte {
	buf := make([]byte, 512)
	_ = dns.WriteHeader(buf, dns.Header{ID: 0xBEEF, Flags: 0x0100, QDCount: 1})
	end, _ := dns.WriteQuestion(buf, dns.HeaderLen, dns.Question{Name: name, Type: dns.TypeA, Class: dns.ClassIN})
	return buf[:end]
}
