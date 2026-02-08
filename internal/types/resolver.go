// Package types contains shared interface definitions to avoid import cycles.
package types

import "context"

// Resolver is the interface for DNS resolution.
type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, func(), error)
}

// Transport is the interface for DNS query transports.
type Transport interface {
	Query(ctx context.Context, server string, req []byte) (resp []byte, cleanup func(), err error)
}
