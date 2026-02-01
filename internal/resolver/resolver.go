package resolver

import "context"

type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, error)
}
