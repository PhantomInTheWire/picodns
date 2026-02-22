// Package types contains shared interface definitions to avoid import cycles.
package types

import (
	"context"
	"time"
)

// Resolver is the interface for DNS resolution.
type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, func(), error)
}

// CacheResolver is an optional interface for resolvers that can serve cache hits
// without performing upstream work.
//
// Used as a fast-path in the UDP server to avoid queueing cache hits behind
// slow misses.
type CacheResolver interface {
	ResolveFromCache(ctx context.Context, req []byte) (resp []byte, cleanup func(), ok bool)
}

// Transport is the interface for DNS query transports.
type Transport interface {
	// Query sends req to server and returns a response.
	//
	// If timeout > 0, it is used as the exchange timeout (independent of any
	// context deadline, which is still respected if sooner).
	// If timeout <= 0, the transport chooses a default timeout.
	Query(ctx context.Context, server string, req []byte, timeout time.Duration) (resp []byte, cleanup func(), err error)
}
