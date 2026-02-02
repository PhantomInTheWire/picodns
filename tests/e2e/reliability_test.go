//go:build e2e

package e2e

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"picodns/internal/dns"
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
