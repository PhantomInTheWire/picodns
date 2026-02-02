package resolver

import (
	"context"
	"errors"
	"net"
	"time"
)

var ErrNoUpstreams = errors.New("resolver: no upstreams configured")

type Upstream struct {
	upstreams []string
	timeout   time.Duration
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
	return buf[:n], nil
}
