package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

var (
	ErrNoUpstreams = errors.New("resolver: no upstreams configured")
)

type Upstream struct {
	upstreams []*net.UDPAddr
	timeout   time.Duration
	pool      sync.Pool
}

func NewUpstream(upstreamAddrs []string, timeout time.Duration) (*Upstream, error) {
	if len(upstreamAddrs) == 0 {
		return nil, ErrNoUpstreams
	}

	resolved := make([]*net.UDPAddr, 0, len(upstreamAddrs))
	for _, addr := range upstreamAddrs {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, raddr)
	}

	u := &Upstream{
		upstreams: resolved,
		timeout:   timeout,
	}
	u.pool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	return u, nil
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

func (u *Upstream) query(ctx context.Context, upstream *net.UDPAddr, req []byte) ([]byte, error) {
	timeout := u.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	resp, bufPtr, needsTCP, err := queryUDP(ctx, upstream, req, timeout, &u.pool, false)
	if err != nil {
		return nil, err
	}
	defer u.pool.Put(bufPtr)

	if needsTCP {
		return u.queryTCP(ctx, upstream, req)
	}

	// Make a copy since the caller expects to own the response
	respCopy := make([]byte, len(resp))
	copy(respCopy, resp)
	return respCopy, nil
}

func (u *Upstream) queryTCP(ctx context.Context, upstream *net.UDPAddr, req []byte) ([]byte, error) {
	timeout := u.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	return tcpQuery(ctx, upstream.String(), req, timeout, false)
}
