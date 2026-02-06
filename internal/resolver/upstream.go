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
	pool      sync.Pool
	connPool  *connPool
}

func NewUpstream(upstreamAddrs []string) (*Upstream, error) {
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
		connPool:  newConnPool(),
	}
	u.pool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	return u, nil
}

func (u *Upstream) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	if len(u.upstreams) == 0 {
		return nil, nil, ErrNoUpstreams
	}

	var lastErr error
	for _, upstream := range u.upstreams {
		resp, cleanup, err := u.query(ctx, upstream, req)
		if err == nil {
			return resp, cleanup, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (u *Upstream) query(ctx context.Context, upstream *net.UDPAddr, req []byte) (resp []byte, cleanup func(), err error) {
	resp, release, needsTCP, err := queryUDP(ctx, upstream, req, defaultTimeout, &u.pool, u.connPool, false)
	if err != nil {
		return nil, nil, err
	}

	if needsTCP {
		release()
		resp, err := u.queryTCP(ctx, upstream, req)
		return resp, nil, err
	}

	return resp, release, nil
}

func (u *Upstream) queryTCP(ctx context.Context, upstream *net.UDPAddr, req []byte) ([]byte, error) {
	timeout := defaultTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	return tcpQuery(ctx, upstream.String(), req, timeout, false)
}
