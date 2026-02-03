//go:build e2e

package e2e

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
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

func TestE2ETCPFallback(t *testing.T) {
	// Start a UDP upstream that returns TC=1
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer udpConn.Close()

	var udpHits int32
	go func() {
		buf := make([]byte, 512)
		for {
			_, addr, readErr := udpConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			atomic.AddInt32(&udpHits, 1)

			// Return TC=1 response
			resp := make([]byte, 512)
			h := dns.Header{
				ID:      binary.BigEndian.Uint16(buf[0:2]),
				Flags:   0x8300, // QR, TC, RA
				QDCount: 1,
			}
			_ = dns.WriteHeader(resp, h)
			q, _, _ := dns.ReadQuestion(buf, dns.HeaderLen)
			_, _ = dns.WriteQuestion(resp, dns.HeaderLen, q)
			_, _ = udpConn.WriteTo(resp[:dns.HeaderLen+len(q.Name)+5], addr) // Approximate length
		}
	}()

	// Start a TCP upstream on the same port (sharing addr)
	// Actually we can't easily share the same port for UDP and TCP in this simple setup without knowing the port.
	// But Upstream.query uses the same address string for both.

	addr := udpConn.LocalAddr().String()
	tcpListen, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	defer tcpListen.Close()

	var tcpHits int32
	go func() {
		for {
			conn, err := tcpListen.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&tcpHits, 1)

			// Read 2-byte length
			lenBuf := make([]byte, 2)
			_, _ = io.ReadFull(conn, lenBuf)
			reqLen := binary.BigEndian.Uint16(lenBuf)
			req := make([]byte, reqLen)
			_, _ = io.ReadFull(conn, req)

			// Send response
			resp, _ := dns.BuildResponse(req, []dns.Answer{
				{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   60,
					RData: []byte{9, 9, 9, 9},
				},
			}, 0)

			respLenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(respLenBuf, uint16(len(resp)))
			_, _ = conn.Write(respLenBuf)
			_, _ = conn.Write(resp)
			conn.Close()
		}
	}()

	serverAddr, stopServer := startServer(t, addr)
	defer stopServer()

	resp := sendQuery(t, serverAddr, "tcp.example.com")
	require.NotEmpty(t, resp)

	header, _ := dns.ReadHeader(resp)
	require.Equal(t, uint16(1), header.ANCount)

	require.Equal(t, int32(1), atomic.LoadInt32(&udpHits))
	require.Equal(t, int32(1), atomic.LoadInt32(&tcpHits))
}

func TestE2EBackpressure(t *testing.T) {
	// Start a slow upstream
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstreamConn.Close()

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

	// Initialize server with small QueueSize and 1 worker
	cfg := config.Default()
	cfg.Upstreams = []string{upstreamAddr}
	cfg.Workers = 1
	cfg.QueueSize = 5
	cfg.Timeout = 1 * time.Second

	listen, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	serverAddr := listen.LocalAddr().String()
	_ = listen.Close()
	cfg.ListenAddrs = []string{serverAddr}

	logger := logging.New("error")
	up := resolver.NewUpstream(cfg.Upstreams, cfg.Timeout)
	store := cache.New(cfg.CacheSize, nil)
	res := resolver.NewCached(store, up)
	handler := server.NewDNSHandler(res)

	srv := server.New(cfg, logger, handler)
	go func() {
		_ = srv.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Send 50 concurrent queries
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

	require.Greater(t, srv.DroppedPackets(), uint64(0), "Should have dropped packets")
	// Server should still be stable (responsive)
	resp := sendQuery(t, serverAddr, "stable.com")
	require.NotEmpty(t, resp)
}

func sendQuerySilent(addr string, name string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

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
