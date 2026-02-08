package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/pool"
)

// Transport is the interface for DNS query transports.
type Transport interface {
	Query(ctx context.Context, server string, req []byte) (resp []byte, cleanup func(), err error)
}

// udpTransport implements Transport using UDP with TCP fallback.
type udpTransport struct {
	bufPool   *pool.Bytes
	connPool  *connPool
	timeout   time.Duration
	addrCache *cache.PermanentCache[string, *net.UDPAddr]
}

func NewTransport(bufPool *pool.Bytes, connPool *connPool, timeout time.Duration) Transport {
	return &udpTransport{
		bufPool:   bufPool,
		connPool:  connPool,
		timeout:   timeout,
		addrCache: cache.NewPermanentCache[string, *net.UDPAddr](),
	}
}

func (t *udpTransport) Query(ctx context.Context, server string, req []byte) ([]byte, func(), error) {
	raddr, ok := t.addrCache.Get(server)
	if !ok {
		var err error
		raddr, err = net.ResolveUDPAddr("udp", server)
		if err != nil {
			return nil, nil, err
		}
		t.addrCache.Set(server, raddr)
	}

	resp, release, needsTCP, err := queryUDP(ctx, raddr, req, t.timeout, t.bufPool, t.connPool, false)
	if err != nil {
		return nil, nil, err
	}

	if needsTCP {
		release()
		resp, err := tcpQueryWithValidation(ctx, server, req, t.timeout, false)
		return resp, nil, err
	}

	return resp, release, nil
}

// queryUDP performs a UDP DNS query. The caller must call release() when done with resp.
// If cp is nil, a new connection is created for this query.
// It returns a slice of a pooled buffer; the caller owns the buffer until release is called.
func queryUDP(ctx context.Context, raddr *net.UDPAddr, req []byte, timeout time.Duration, bufPool *pool.Bytes, cp *connPool, validate bool) (resp []byte, release func(), needsTCP bool, err error) {
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

	bufPtr := bufPool.Get()
	buf := *bufPtr

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		bufPool.Put(bufPtr)
		rel()
		return nil, nil, false, err
	}

	resp = buf[:n]

	finalRelease := func() {
		bufPool.Put(bufPtr)
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

// tcpQueryWithValidation performs a TCP DNS query to the given server.
// If validate is true, it validates the response against the request.
func tcpQueryWithValidation(ctx context.Context, server string, req []byte, timeout time.Duration, validate bool) ([]byte, error) {
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
