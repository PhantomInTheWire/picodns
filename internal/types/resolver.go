// Package types contains shared interface definitions to avoid import cycles.
package types

import "context"

// Resolver is the interface for DNS resolution.
type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, func(), error)
}
