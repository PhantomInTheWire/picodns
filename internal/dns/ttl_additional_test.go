package dns

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollectTTLOffsetsAndRewriteTTLs(t *testing.T) {
	req := make([]byte, 128)
	n, err := BuildQueryInto(req, 0x1234, "example.com", TypeA, ClassIN)
	require.NoError(t, err)

	resp, err := BuildResponse(req[:n], []Answer{{
		Type:  TypeA,
		Class: ClassIN,
		TTL:   60,
		RData: []byte{127, 0, 0, 1},
	}}, RcodeSuccess)
	require.NoError(t, err)

	offsets, err := CollectTTLOffsets(resp)
	require.NoError(t, err)
	require.Len(t, offsets, 1)
	require.Equal(t, uint32(60), binary.BigEndian.Uint32(resp[offsets[0]:int(offsets[0])+4]))

	RewriteTTLsAtOffsets(resp, 300, offsets)
	require.Equal(t, uint32(300), binary.BigEndian.Uint32(resp[offsets[0]:int(offsets[0])+4]))
}

func TestCollectTTLOffsetsSkipsOPTAndReportsTruncation(t *testing.T) {
	query := make([]byte, 128)
	n, err := BuildQueryIntoWithEDNS(query, 0x1234, "example.com", TypeA, ClassIN, 1232)
	require.NoError(t, err)

	offsets, err := CollectTTLOffsets(query[:n])
	require.NoError(t, err)
	require.Empty(t, offsets)

	_, err = CollectTTLOffsets(query[:n-1])
	require.ErrorIs(t, err, ErrShortBuffer)
}
