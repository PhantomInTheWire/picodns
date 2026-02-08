package resolver

import (
	"context"
	"errors"
	"net"

	"picodns/internal/pool"
	"picodns/internal/types"
)

var (
	ErrNoUpstreams = errors.New("resolver: no upstreams configured")
)

type Upstream struct {
	upstreams []string
	transport types.Transport
}

func NewUpstream(upstreamAddrs []string) (*Upstream, error) {
	if len(upstreamAddrs) == 0 {
		return nil, ErrNoUpstreams
	}

	for _, addr := range upstreamAddrs {
		if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
			return nil, err
		}
	}

	return &Upstream{
		upstreams: upstreamAddrs,
		transport: NewTransport(pool.DefaultPool, newConnPool(), defaultTimeout),
	}, nil
}

func (u *Upstream) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	if len(u.upstreams) == 0 {
		return nil, nil, ErrNoUpstreams
	}

	var lastErr error
	for _, upstream := range u.upstreams {
		resp, cleanup, err := u.transport.Query(ctx, upstream, req)
		if err != nil {
			lastErr = err
			continue
		}

		return resp, cleanup, nil
	}
	return nil, nil, lastErr
}
