package server

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/config"
	"picodns/internal/dns"
)

// mockResolver implements types.Resolver for testing.
type mockResolver struct {
	resp []byte
	err  error
}

func (m *mockResolver) Resolve(_ context.Context, req []byte) ([]byte, func(), error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.resp, nil, nil
}

func newTestServer(resolver *mockResolver) *Server {
	cfg := config.Default()
	cfg.Workers = 1
	logger := slog.Default()
	return New(cfg, logger, resolver)
}

func writeTCPQuery(t *testing.T, conn net.Conn, query []byte) {
	t.Helper()
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	_, err := conn.Write(lenBuf[:])
	require.NoError(t, err)
	_, err = conn.Write(query)
	require.NoError(t, err)
}

func readTCPResponse(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var lenBuf [2]byte
	_, err := io.ReadFull(conn, lenBuf[:])
	require.NoError(t, err)
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	resp := make([]byte, respLen)
	_, err = io.ReadFull(conn, resp)
	require.NoError(t, err)
	return resp
}

func makeTestQuery(name string) []byte {
	buf := make([]byte, 512)
	_ = dns.WriteHeader(buf, dns.Header{ID: 0xBEEF, Flags: dns.FlagRD, QDCount: 1})
	end, _ := dns.WriteQuestion(buf, dns.HeaderLen, dns.Question{Name: name, Type: dns.TypeA, Class: dns.ClassIN})
	return buf[:end]
}

func makeTestResponse(req []byte, ttl uint32) []byte {
	resp, _ := dns.BuildResponse(req, []dns.Answer{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: ttl, RData: []byte{1, 2, 3, 4}},
	}, 0)
	return resp
}

func TestTCPHandlerBasicQuery(t *testing.T) {
	query := makeTestQuery("example.com")
	resp := makeTestResponse(query, 60)
	srv := newTestServer(&mockResolver{resp: resp})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go srv.handleTCPConn(ctx, server)

	writeTCPQuery(t, client, query)
	got := readTCPResponse(t, client)

	hdr, err := dns.ReadHeader(got)
	require.NoError(t, err)
	require.Equal(t, uint16(0xBEEF), hdr.ID)
	require.True(t, hdr.Flags&dns.FlagQR != 0) // is a response
}

func TestTCPHandlerResolverError(t *testing.T) {
	query := makeTestQuery("fail.com")
	srv := newTestServer(&mockResolver{err: io.ErrUnexpectedEOF})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go srv.handleTCPConn(ctx, server)

	writeTCPQuery(t, client, query)
	got := readTCPResponse(t, client)

	// Should get a SERVFAIL response
	hdr, err := dns.ReadHeader(got)
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeServer), hdr.Flags&dns.RcodeMask)
}

func TestTCPHandlerInvalidMessageSize(t *testing.T) {
	srv := newTestServer(&mockResolver{})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		srv.handleTCPConn(ctx, server)
		close(done)
	}()

	// Send a message size of 0
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], 0)
	_, err := client.Write(lenBuf[:])
	require.NoError(t, err)

	// Handler should close the connection
	select {
	case <-done:
		// good - handler returned
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not close connection for invalid size")
	}
}

func TestTCPHandlerMultipleQueries(t *testing.T) {
	query := makeTestQuery("multi.com")
	resp := makeTestResponse(query, 300)
	srv := newTestServer(&mockResolver{resp: resp})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go srv.handleTCPConn(ctx, server)

	// Send 3 queries on the same connection (TCP pipelining)
	for i := 0; i < 3; i++ {
		writeTCPQuery(t, client, query)
		got := readTCPResponse(t, client)
		hdr, err := dns.ReadHeader(got)
		require.NoError(t, err)
		require.Equal(t, uint16(0xBEEF), hdr.ID)
	}
}

func TestTCPHandlerQueryCounting(t *testing.T) {
	query := makeTestQuery("count.com")
	resp := makeTestResponse(query, 60)
	srv := newTestServer(&mockResolver{resp: resp})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go srv.handleTCPConn(ctx, server)

	writeTCPQuery(t, client, query)
	_ = readTCPResponse(t, client)

	writeTCPQuery(t, client, query)
	_ = readTCPResponse(t, client)

	require.Equal(t, uint64(2), srv.TotalQueries.Load())
}
