//go:build e2e

package e2e

import (
	"context"
	"encoding/binary"
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

func TestE2ENegativeCache(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	var hits int32
	go func() {
		buf := make([]byte, 512)
		for {
			_, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			atomic.AddInt32(&hits, 1)

			// Build NXDOMAIN response with SOA in authority section
			resp := make([]byte, 512)
			h := dns.Header{
				ID:      binary.BigEndian.Uint16(buf[0:2]),
				Flags:   0x8183, // QR, RD, RA, NXDOMAIN
				QDCount: 1,
				NSCount: 1,
			}
			_ = dns.WriteHeader(resp, h)
			q, _, _ := dns.ReadQuestion(buf, dns.HeaderLen)
			next, _ := dns.WriteQuestion(resp, dns.HeaderLen, q)

			// Add SOA
			soaStart := next
			next, _ = dns.EncodeName(resp, soaStart, "example.com")
			binary.BigEndian.PutUint16(resp[next:next+2], dns.TypeSOA)
			binary.BigEndian.PutUint16(resp[next+2:next+4], dns.ClassIN)
			binary.BigEndian.PutUint32(resp[next+4:next+8], 60) // TTL

			// SOA RDATA
			rdataStart := next + 10
			mnameEnd, _ := dns.EncodeName(resp, rdataStart, "ns1.example.com")
			rnameEnd, _ := dns.EncodeName(resp, mnameEnd, "admin.example.com")
			binary.BigEndian.PutUint32(resp[rnameEnd:rnameEnd+4], 2024020501) // Serial
			binary.BigEndian.PutUint32(resp[rnameEnd+4:rnameEnd+8], 3600)     // Refresh
			binary.BigEndian.PutUint32(resp[rnameEnd+8:rnameEnd+12], 600)     // Retry
			binary.BigEndian.PutUint32(resp[rnameEnd+12:rnameEnd+16], 86400)  // Expire
			binary.BigEndian.PutUint32(resp[rnameEnd+16:rnameEnd+20], 30)     // Minimum TTL = 30s

			binary.BigEndian.PutUint16(resp[next+8:next+10], uint16(rnameEnd+20-rdataStart))
			_, _ = conn.WriteTo(resp[:rnameEnd+20], addr)

		}
	}()

	serverAddr, stopServer := startServer(t, conn.LocalAddr().String())
	defer stopServer()

	resp1 := sendQuery(t, serverAddr, "nonexistent.example.com")
	require.NotEmpty(t, resp1)
	header1, _ := dns.ReadHeader(resp1)
	require.Equal(t, uint16(dns.RcodeNXDomain), header1.Flags&0x000F)

	resp2 := sendQuery(t, serverAddr, "nonexistent.example.com")
	require.Equal(t, resp1, resp2)

	require.Equal(t, int32(1), atomic.LoadInt32(&hits))
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

	up := resolver.NewUpstream(cfg.Upstreams, cfg.Timeout)
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
