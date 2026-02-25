package resolver

import (
	"context"
	"errors"

	"picodns/internal/cache"
	"picodns/internal/pool"
	"picodns/internal/types"
)

var (
	ErrNoUpstreams = errors.New("resolver: no upstreams configured")
)

// Upstream forwards DNS queries to one or more configured upstream resolvers,
// trying each in order until one succeeds.
type Upstream struct {
	upstreams []string
	transport types.Transport
}

// SetObsEnabled enables or disables observability on the upstream transport.
func (u *Upstream) SetObsEnabled(enabled bool) {
	if t, ok := u.transport.(*udpTransport); ok {
		t.SetObsEnabled(enabled)
	}
}

// TransportAddrCacheStatsSnapshot returns a point-in-time snapshot of the transport address cache statistics.
func (u *Upstream) TransportAddrCacheStatsSnapshot() cache.TTLStatsSnapshot {
	if t, ok := u.transport.(*udpTransport); ok && t.addrCache != nil {
		return t.addrCache.StatsSnapshot()
	}
	return cache.TTLStatsSnapshot{}
}

// NewUpstream creates an Upstream resolver that forwards queries to the given addresses.
func NewUpstream(upstreamAddrs []string) (*Upstream, error) {
	if len(upstreamAddrs) == 0 {
		return nil, ErrNoUpstreams
	}

	for _, addr := range upstreamAddrs {
		if _, err := resolveUDPAddr(context.Background(), addr); err != nil {
			return nil, err
		}
	}

	return &Upstream{
		upstreams: upstreamAddrs,
		transport: NewTransport(pool.DefaultPool, newConnPool(), defaultTimeout),
	}, nil
}

// Resolve forwards the query to each upstream in order, returning the first successful response.
func (u *Upstream) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	if len(u.upstreams) == 0 {
		return nil, nil, ErrNoUpstreams
	}

	var lastErr error
	for _, upstream := range u.upstreams {
		resp, cleanup, err := u.transport.Query(ctx, upstream, req, 0)
		if err != nil {
			lastErr = err
			continue
		}

		return resp, cleanup, nil
	}
	return nil, nil, lastErr
}
