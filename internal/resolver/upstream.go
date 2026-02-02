package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"picodns/internal/dns"
)

var (
	ErrNoUpstreams = errors.New("resolver: no upstreams configured")
	maxTCPSize     = 65535
)

type Upstream struct {
	upstreams    []string
	timeout      time.Duration
	totalLatency atomic.Uint64 // nanoseconds
	queryCount   atomic.Uint64
}

func NewUpstream(upstreams []string, timeout time.Duration) *Upstream {
	return &Upstream{
		upstreams: append([]string(nil), upstreams...),
		timeout:   timeout,
	}
}

func (u *Upstream) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	if len(u.upstreams) == 0 {
		return nil, ErrNoUpstreams
	}

	var lastErr error
	for _, upstream := range u.upstreams {
		start := time.Now()
		resp, err := u.query(ctx, upstream, req)
		if err == nil {
			u.totalLatency.Add(uint64(time.Since(start)))
			u.queryCount.Add(1)
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (u *Upstream) query(ctx context.Context, upstream string, req []byte) ([]byte, error) {
	raddr, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		timeout := u.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := buf[:n]

	header, err := dns.ReadHeader(resp)
	if err == nil && (header.Flags&dns.FlagTC) != 0 {
		return u.queryTCP(ctx, upstream, req)
	}

	return resp, nil
}

func (u *Upstream) queryTCP(ctx context.Context, upstream string, req []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		timeout := u.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)

	reqLen := uint16(len(req))
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, reqLen)

	if _, err := conn.Write(lenBuf); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))
	if respLen > maxTCPSize {
		return nil, errors.New("resolver: tcp response too large")
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	return resp, nil
}
