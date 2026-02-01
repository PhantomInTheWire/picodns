package dns

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildResponseARecord(t *testing.T) {
	buf := make([]byte, 512)
	reqHeader := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1}
	require.NoError(t, WriteHeader(buf, reqHeader))
	end, err := WriteQuestion(buf, HeaderLen, Question{Name: "example.com", Type: TypeA, Class: ClassIN})
	require.NoError(t, err)

	resp, err := BuildResponse(buf[:end], []Answer{
		{
			Type:  TypeA,
			Class: ClassIN,
			TTL:   60,
			RData: []byte{127, 0, 0, 1},
		},
	}, 0)
	require.NoError(t, err)

	respHeader, err := ReadHeader(resp)
	require.NoError(t, err)
	require.Equal(t, uint16(1), respHeader.QDCount)
	require.Equal(t, uint16(1), respHeader.ANCount)
	require.True(t, respHeader.Flags&0x8000 != 0)
	require.True(t, respHeader.Flags&0x0100 != 0)

	q, qEnd, err := ReadQuestion(resp, HeaderLen)
	require.NoError(t, err)
	require.Equal(t, "example.com", q.Name)
	require.Equal(t, TypeA, q.Type)
	require.Equal(t, ClassIN, q.Class)

	idx := qEnd
	require.Equal(t, byte(0xC0), resp[idx])
	require.Equal(t, byte(0x0C), resp[idx+1])
	idx += 2
	require.Equal(t, TypeA, binary.BigEndian.Uint16(resp[idx:idx+2]))
	require.Equal(t, ClassIN, binary.BigEndian.Uint16(resp[idx+2:idx+4]))
	require.Equal(t, uint32(60), binary.BigEndian.Uint32(resp[idx+4:idx+8]))
	require.Equal(t, uint16(4), binary.BigEndian.Uint16(resp[idx+8:idx+10]))
}
