package resolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveUDPAddrParsesLiteralHosts(t *testing.T) {
	addr, err := resolveUDPAddr(context.Background(), "127.0.0.1:5353")
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", addr.IP.String())
	require.Equal(t, 5353, addr.Port)

	addr, err = resolveUDPAddr(context.Background(), "[fe80::1%en0]:53")
	require.NoError(t, err)
	require.Equal(t, "fe80::1", addr.IP.String())
	require.Equal(t, "en0", addr.Zone)
	require.Equal(t, 53, addr.Port)
}

func TestResolveUDPAddrHandlesServiceNamesAndErrors(t *testing.T) {
	addr, err := resolveUDPAddr(context.Background(), "127.0.0.1:domain")
	require.NoError(t, err)
	require.Equal(t, 53, addr.Port)

	_, err = resolveUDPAddr(context.Background(), "bad-address")
	require.Error(t, err)
}
