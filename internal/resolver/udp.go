package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"picodns/internal/dns"
)

// queryUDP performs a UDP DNS query. The caller must call release() when done with resp.
// If cp is nil, a new connection is created for this query.
func queryUDP(ctx context.Context, raddr *net.UDPAddr, req []byte, timeout time.Duration, pool *sync.Pool, cp *connPool, validate bool) (resp []byte, release func(), needsTCP bool, err error) {
	var conn *net.UDPConn
	var connRelease func()

	if cp != nil {
		conn, connRelease, err = cp.get()
		if err != nil {
			return nil, nil, false, err
		}
	} else {
		conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, false, err
		}
	}

	rel := func() {
		if cp != nil {
			connRelease()
		} else {
			_ = conn.Close()
		}
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		rel()
		return nil, nil, false, err
	}

	if _, err := conn.WriteTo(req, raddr); err != nil {
		rel()
		return nil, nil, false, err
	}

	bufPtr := pool.Get().(*[]byte)
	buf := *bufPtr

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		pool.Put(bufPtr)
		rel()
		return nil, nil, false, err
	}

	// Return slice of pooled buffer - caller owns bufPtr now
	resp = buf[:n]

	finalRelease := func() {
		pool.Put(bufPtr)
		rel()
	}

	if validate {
		if err := dns.ValidateResponse(req, resp); err != nil {
			finalRelease()
			return nil, nil, false, err
		}
	}

	header, err := dns.ReadHeader(resp)
	if err == nil && (header.Flags&dns.FlagTC) != 0 {
		return resp, finalRelease, true, nil
	}

	return resp, finalRelease, false, nil
}

// tcpQuery performs a TCP DNS query to the given server.
// If validate is true, it validates the response against the request.
func tcpQuery(ctx context.Context, server string, req []byte, timeout time.Duration, validate bool) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	reqLen := uint16(len(req))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], reqLen)

	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	if validate {
		if err := dns.ValidateResponse(req, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
