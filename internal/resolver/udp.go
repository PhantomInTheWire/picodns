package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/obs"
	"picodns/internal/pool"
	"picodns/internal/types"
)

// udpTransport implements types.Transport using UDP with TCP fallback.
type udpTransport struct {
	bufPool   *pool.Bytes
	connPool  *connPool
	timeout   time.Duration
	addrCache *cache.PermanentCache[string, *net.UDPAddr]

	// Function tracers
	tracers struct {
		query       *obs.FuncTracer
		queryUDP    *obs.FuncTracer
		tcpQuery    *obs.FuncTracer
		resolveAddr *obs.FuncTracer
	}
}

func (t *udpTransport) SetObsEnabled(enabled bool) {
	if t == nil || t.addrCache == nil || t.addrCache.TTL == nil {
		return
	}
	t.addrCache.TTL.ObsEnabled = enabled
}

func NewTransport(bufPool *pool.Bytes, connPool *connPool, timeout time.Duration) types.Transport {
	t := &udpTransport{
		bufPool:   bufPool,
		connPool:  connPool,
		timeout:   timeout,
		addrCache: cache.NewPermanentCache[string, *net.UDPAddr](),
	}
	t.addrCache.MaxLen = maxAddrCacheEntries

	// Initialize tracers
	t.tracers.query = obs.NewFuncTracer("udpTransport.Query", nil)
	t.tracers.queryUDP = obs.NewFuncTracer("queryUDP", t.tracers.query)
	t.tracers.tcpQuery = obs.NewFuncTracer("tcpQueryWithValidation", t.tracers.query)
	t.tracers.resolveAddr = obs.NewFuncTracer("udpTransport.resolveAddr", t.tracers.query)

	// Register tracers
	obs.GlobalRegistry.Register(t.tracers.query)
	obs.GlobalRegistry.Register(t.tracers.queryUDP)
	obs.GlobalRegistry.Register(t.tracers.tcpQuery)
	obs.GlobalRegistry.Register(t.tracers.resolveAddr)

	return t
}

func (t *udpTransport) Query(ctx context.Context, server string, req []byte) ([]byte, func(), error) {
	defer t.tracers.query.Trace()()

	raddr, ok := t.addrCache.Get(server)
	if !ok {
		var err error
		raddr, err = t.resolveAddr(ctx, server)
		if err != nil {
			return nil, nil, err
		}
		t.addrCache.Set(server, raddr)
	}

	resp, release, needsTCP, err := t.queryUDP(ctx, raddr, req, t.timeout, t.bufPool, t.connPool, false)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			slog.Debug("dns udp query timeout", "server", server)
		}
		return nil, nil, err
	}

	if needsTCP {
		slog.Debug("dns udp truncated, fallback to tcp", "server", server)
		release()
		resp, err := t.tcpQueryWithValidation(ctx, server, req, t.timeout, false)
		return resp, nil, err
	}

	return resp, release, nil
}

func (t *udpTransport) resolveAddr(ctx context.Context, server string) (*net.UDPAddr, error) {
	defer t.tracers.resolveAddr.Trace()()
	return net.ResolveUDPAddr("udp", server)
}

// queryUDP performs a UDP DNS query. The caller must call release() when done with resp.
// If cp is nil, a new connection is created for this query.
// It returns a slice of a pooled buffer; the caller owns the buffer until release is called.
func (t *udpTransport) queryUDP(ctx context.Context, raddr *net.UDPAddr, req []byte, timeout time.Duration, bufPool *pool.Bytes, cp *connPool, validate bool) (resp []byte, release func(), needsTCP bool, err error) {
	defer t.tracers.queryUDP.Trace()()

	var conn *net.UDPConn
	var connRelease func()

	if cp != nil {
		conn, connRelease, err = cp.get(ctx)
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
	buf = buf[:cap(buf)]

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
func (t *udpTransport) tcpQueryWithValidation(ctx context.Context, server string, req []byte, timeout time.Duration, validate bool) ([]byte, error) {
	defer t.tracers.tcpQuery.Trace()()

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
	if respLen > dns.MaxMessageSize {
		return nil, errors.New("tcp response too large")
	}

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
