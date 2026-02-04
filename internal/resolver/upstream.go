package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"picodns/internal/dns"
)

var (
	ErrNoUpstreams = errors.New("resolver: no upstreams configured")
)

type Upstream struct {
	upstreams []string
	timeout   time.Duration
	pool      sync.Pool
}

func NewUpstream(upstreams []string, timeout time.Duration) *Upstream {
	u := &Upstream{
		upstreams: append([]string(nil), upstreams...),
		timeout:   timeout,
	}
	u.pool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	return u
}

func (u *Upstream) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	if len(u.upstreams) == 0 {
		return nil, ErrNoUpstreams
	}

	var lastErr error
	for _, upstream := range u.upstreams {
		resp, err := u.query(ctx, upstream, req)
		if err == nil {
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
	defer func() { _ = conn.Close() }()

	deadline := u.getDeadline(ctx)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	bufPtr := u.pool.Get().(*[]byte)
	defer u.pool.Put(bufPtr)
	buf := *bufPtr

	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := make([]byte, n)
	copy(resp, buf[:n])

	header, err := dns.ReadHeader(resp)
	if err == nil && (header.Flags&dns.FlagTC) != 0 {
		return u.queryTCP(ctx, upstream, req)
	}

	return resp, nil
}

func (u *Upstream) queryTCP(ctx context.Context, upstream string, req []byte) ([]byte, error) {
	// Calculate effective timeout from context deadline
	timeout := u.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	return tcpQuery(ctx, upstream, req, timeout, false)
}

func (u *Upstream) getDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	timeout := u.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return time.Now().Add(timeout)
}
