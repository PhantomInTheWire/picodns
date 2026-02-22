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

type udpTransport struct {
	bufPool   *pool.Bytes
	connPool  *connPool
	timeout   time.Duration
	addrCache *cache.PermanentCache[string, *net.UDPAddr]

	tracers struct {
		query       *obs.FuncTracer
		queryUDP    *obs.FuncTracer
		udpDeadline *obs.FuncTracer
		udpWrite    *obs.FuncTracer
		udpRead     *obs.FuncTracer
		tcpQuery    *obs.FuncTracer
		tcpDial     *obs.FuncTracer
		tcpWrite    *obs.FuncTracer
		tcpRead     *obs.FuncTracer
		resolveAddr *obs.FuncTracer
	}
}

// timeoutFromContextOrDefault returns an effective timeout for a single upstream exchange.
func timeoutFromContextOrDefault(ctx context.Context, fallback time.Duration) time.Duration {
	if ctx == nil {
		return fallback
	}
	if d, ok := ctx.Deadline(); ok {
		until := time.Until(d)
		if until <= 0 {
			return 0
		}
		if until < fallback {
			return until
		}
		return fallback
	}
	return fallback
}

func (t *udpTransport) SetObsEnabled(enabled bool) {
	if t == nil || t.addrCache == nil || t.addrCache.TTL == nil {
		return
	}
	t.addrCache.ObsEnabled = enabled
}

func NewTransport(bufPool *pool.Bytes, connPool *connPool, timeout time.Duration) types.Transport {
	t := &udpTransport{
		bufPool:   bufPool,
		connPool:  connPool,
		timeout:   timeout,
		addrCache: cache.NewPermanentCache[string, *net.UDPAddr](),
	}
	t.addrCache.MaxLen = maxAddrCacheEntries

	t.tracers.query = obs.NewFuncTracer("udpTransport.Query", nil)
	t.tracers.queryUDP = obs.NewFuncTracer("queryUDP", t.tracers.query)
	t.tracers.udpDeadline = obs.NewFuncTracer("queryUDP.netDeadline", t.tracers.queryUDP)
	t.tracers.udpWrite = obs.NewFuncTracer("queryUDP.netWrite", t.tracers.queryUDP)
	t.tracers.udpRead = obs.NewFuncTracer("queryUDP.netRead", t.tracers.queryUDP)
	t.tracers.tcpQuery = obs.NewFuncTracer("tcpQueryWithValidation", t.tracers.query)
	t.tracers.tcpDial = obs.NewFuncTracer("tcpQueryWithValidation.netDial", t.tracers.tcpQuery)
	t.tracers.tcpWrite = obs.NewFuncTracer("tcpQueryWithValidation.netWrite", t.tracers.tcpQuery)
	t.tracers.tcpRead = obs.NewFuncTracer("tcpQueryWithValidation.netRead", t.tracers.tcpQuery)
	t.tracers.resolveAddr = obs.NewFuncTracer("udpTransport.resolveAddr", t.tracers.query)

	obs.GlobalRegistry.Register(t.tracers.query)
	obs.GlobalRegistry.Register(t.tracers.queryUDP)
	obs.GlobalRegistry.Register(t.tracers.udpDeadline)
	obs.GlobalRegistry.Register(t.tracers.udpWrite)
	obs.GlobalRegistry.Register(t.tracers.udpRead)
	obs.GlobalRegistry.Register(t.tracers.tcpQuery)
	obs.GlobalRegistry.Register(t.tracers.tcpDial)
	obs.GlobalRegistry.Register(t.tracers.tcpWrite)
	obs.GlobalRegistry.Register(t.tracers.tcpRead)
	obs.GlobalRegistry.Register(t.tracers.resolveAddr)

	return t
}

func (t *udpTransport) Query(ctx context.Context, server string, req []byte, timeout time.Duration) ([]byte, func(), error) {
	defer t.tracers.query.Trace()()

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	if timeout <= 0 {
		timeout = timeoutFromContextOrDefault(ctx, t.timeout)
	} else if t.timeout > 0 && timeout > t.timeout {
		// Cap caller-provided timeouts to transport default.
		// This prevents recursive resolution from tying up workers for seconds
		// when RTT is unknown or inflated.
		timeout = t.timeout
	}
	if timeout <= 0 {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, context.DeadlineExceeded
	}

	raddr, ok := t.addrCache.Get(server)
	if !ok {
		var err error
		raddr, err = t.resolveAddr(ctx, server)
		if err != nil {
			return nil, nil, err
		}
		t.addrCache.Set(server, raddr)
	}

	resp, release, needsTCP, err := t.queryUDP(ctx, raddr, req, timeout, t.bufPool, t.connPool, false)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			slog.Debug("dns udp query timeout", "server", server)
		}
		return nil, nil, err
	}

	if needsTCP {
		slog.Debug("dns udp truncated, fallback to tcp", "server", server)
		release()
		resp, err := t.tcpQueryWithValidation(ctx, server, req, timeout, false)
		return resp, nil, err
	}

	return resp, release, nil
}

func (t *udpTransport) resolveAddr(ctx context.Context, server string) (*net.UDPAddr, error) {
	defer t.tracers.resolveAddr.Trace()()
	return resolveUDPAddr(ctx, server)
}

// queryUDP performs a UDP DNS query. The caller must call release() when done with resp.
// If cp is nil, a new connection is created for this query.
// It returns a slice of a pooled buffer; the caller owns the buffer until release is called.
func (t *udpTransport) queryUDP(ctx context.Context, raddr *net.UDPAddr, req []byte, timeout time.Duration, bufPool *pool.Bytes, cp *connPool, validate bool) (resp []byte, release func(), needsTCP bool, err error) {
	sampled := t.tracers.queryUDP.ShouldSample()
	doneQuery := t.tracers.queryUDP.TraceSampled(sampled)
	defer doneQuery()

	var conn *net.UDPConn
	var connRelease func(bad bool)

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

	rel := func(bad bool) {
		if cp != nil {
			connRelease(bad)
		} else {
			_ = conn.Close()
		}
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	doneDeadline := t.tracers.udpDeadline.TraceNested(sampled)
	err = conn.SetDeadline(deadline)
	doneDeadline()
	if err != nil {
		rel(true)
		return nil, nil, false, err
	}

	doneWrite := t.tracers.udpWrite.TraceNested(sampled)
	_, err = conn.WriteTo(req, raddr)
	doneWrite()
	if err != nil {
		rel(true)
		return nil, nil, false, err
	}

	bufPtr := bufPool.Get()
	buf := *bufPtr
	buf = buf[:cap(buf)]

	doneRead := t.tracers.udpRead.TraceNested(sampled)
	n, fromAddr, err := conn.ReadFromUDP(buf)
	doneRead()
	if err != nil {
		bufPool.Put(bufPtr)
		bad := true
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// Close pooled UDP socket on timeout so late replies can't poison
			// subsequent queries when the socket is reused.
			bad = true
		}
		rel(bad)
		return nil, nil, false, err
	}
	// If we got a datagram from a different address, don't risk reusing this socket.
	// This should be extremely rare in normal operation.
	bad := false
	if fromAddr != nil {
		if !fromAddr.IP.Equal(raddr.IP) || fromAddr.Port != raddr.Port {
			bad = true
		}
	}

	resp = buf[:n]

	finalRelease := func() {
		bufPool.Put(bufPtr)
		rel(bad)
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
	sampled := t.tracers.tcpQuery.ShouldSample()
	doneTCP := t.tracers.tcpQuery.TraceSampled(sampled)
	defer doneTCP()

	var d net.Dialer
	doneDial := t.tracers.tcpDial.TraceNested(sampled)
	conn, err := d.DialContext(ctx, "tcp", server)
	doneDial()
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

	doneWrite := t.tracers.tcpWrite.TraceNested(sampled)
	_, err = conn.Write(lenBuf[:])
	if err == nil {
		_, err = conn.Write(req)
	}
	doneWrite()
	if err != nil {
		return nil, err
	}

	doneRead := t.tracers.tcpRead.TraceNested(sampled)
	_, err = io.ReadFull(conn, lenBuf[:])
	if err != nil {
		doneRead()
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen > dns.MaxMessageSize {
		doneRead()
		return nil, errors.New("tcp response too large")
	}

	resp := make([]byte, respLen)
	_, err = io.ReadFull(conn, resp)
	doneRead()
	if err != nil {
		return nil, err
	}

	if validate {
		if err := dns.ValidateResponse(req, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
