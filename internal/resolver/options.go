package resolver

import "picodns/internal/types"

// Option is a functional option for configuring the Recursive resolver.
type Option func(*Recursive)

// WithRootServers sets custom root servers for the recursive resolver.
// If not provided, the resolver uses the default root servers.
func WithRootServers(servers []string) Option {
	return func(r *Recursive) {
		r.rootServers = servers
	}
}

// WithTransport sets a custom transport for the recursive resolver.
// This is primarily used for testing with mock transports.
func WithTransport(transport types.Transport) Option {
	return func(r *Recursive) {
		r.transport = transport
	}
}
