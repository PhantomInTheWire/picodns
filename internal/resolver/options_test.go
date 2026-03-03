package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithRootServers(t *testing.T) {
	r := NewRecursive()
	servers := []string{"192.0.2.1:53", "192.0.2.2:53"}

	WithRootServers(servers)(r)

	require.Equal(t, servers, r.rootServers)
}

func TestWithTransport(t *testing.T) {
	r := NewRecursive()
	transport := &testTransport{}

	WithTransport(transport)(r)

	require.Same(t, transport, r.transport)
}

type testTransport struct{}

func (testTransport) Query(_ context.Context, _ string, _ []byte, _ time.Duration) ([]byte, func(), error) {
	return nil, nil, nil
}
