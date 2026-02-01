//go:build e2e

package e2e

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/cache"
	"picodns/internal/config"
	"picodns/internal/dns"
	"picodns/internal/logging"
	"picodns/internal/resolver"
	"picodns/internal/server"
)

func TestE2EForwardAndCache(t *testing.T) {
	upstreamAddr, hits, stopUpstream := startUpstream(t)
	defer stopUpstream()

	serverAddr, stopServer := startServer(t, upstreamAddr)
	defer stopServer()

	resp1 := sendQuery(t, serverAddr, "example.com")
	require.NotEmpty(t, resp1)

	resp2 := sendQuery(t, serverAddr, "example.com")
	require.Equal(t, resp1, resp2)

	require.Equal(t, int32(1), atomic.LoadInt32(hits))
}

func startUpstream(t *testing.T) (string, *int32, func()) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	var hits int32
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		buf := make([]byte, 512)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				return
			}

			atomic.AddInt32(&hits, 1)
			resp, err := dns.BuildResponse(buf[:n], []dns.Answer{
				{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   60,
					RData: []byte{1, 2, 3, 4},
				},
			}, 0)
			if err == nil {
				_, _ = conn.WriteTo(resp, addr)
			}
		}
	}()

	stop := func() {
		cancel()
		_ = conn.Close()
	}
	return conn.LocalAddr().String(), &hits, stop
}

func startServer(t *testing.T, upstream string) (string, func()) {
	logger := logging.New("error")
	cfg := config.Default()
	cfg.Upstreams = []string{upstream}
	cfg.Workers = 4
	cfg.Timeout = 2 * time.Second
	cfg.CacheSize = 100

	listen, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listen.LocalAddr().String()
	_ = listen.Close()

	cfg.ListenAddr = addr

	up := resolver.NewUpstream(cfg.Upstreams)
	store := cache.New(cfg.CacheSize, nil)
	res := resolver.NewCached(store, up)
	handler := server.NewDNSHandler(res)

	srv := server.New(cfg, logger, handler)
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
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
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
