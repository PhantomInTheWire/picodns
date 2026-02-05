package resolver

import (
	"context"
	"errors"
	"sync"
	"time"
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
	timeout := u.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	resp, needsTCP, err := queryUDP(ctx, upstream, req, timeout, &u.pool, false)
	if err != nil {
		return nil, err
	}
	if needsTCP {
		return u.queryTCP(ctx, upstream, req)
	}
	return resp, nil
}

func (u *Upstream) queryTCP(ctx context.Context, upstream string, req []byte) ([]byte, error) {
	timeout := u.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	return tcpQuery(ctx, upstream, req, timeout, false)
}
