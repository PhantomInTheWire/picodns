package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
)

func TestServfailFromRequestInPlace(t *testing.T) {
	req := make([]byte, 128)
	n, err := dns.BuildQueryInto(req, 0x1234, "example.com", dns.TypeA, dns.ClassIN)
	require.NoError(t, err)

	resp, ok := dns.RewriteAsServfail(req[:n])
	require.True(t, ok)

	hdr, err := dns.ReadHeader(resp)
	require.NoError(t, err)
	require.Equal(t, uint16(0x1234), hdr.ID)
	require.Equal(t, uint16(1), hdr.QDCount)
	require.Equal(t, uint16(0), hdr.ANCount)
	require.Equal(t, uint16(dns.RcodeServer), hdr.Flags&dns.RcodeMask)
	require.NotZero(t, hdr.Flags&dns.FlagRA)
}

func TestServfailFromRequestInPlaceRejectsInvalidRequests(t *testing.T) {
	resp, ok := dns.RewriteAsServfail([]byte{1, 2, 3})
	require.False(t, ok)
	require.Nil(t, resp)
}
