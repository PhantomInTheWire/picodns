package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaderRoundTrip(t *testing.T) {
	buf := make([]byte, HeaderLen)
	header := Header{
		ID:      0xBEEF,
		Flags:   0x8180,
		QDCount: 1,
		ANCount: 2,
		NSCount: 3,
		ARCount: 4,
	}

	require.NoError(t, WriteHeader(buf, header))
	decoded, err := ReadHeader(buf)
	require.NoError(t, err)
	require.Equal(t, header, decoded)
}

func TestQuestionRoundTrip(t *testing.T) {
	buf := make([]byte, 512)
	q := Question{Name: "example.com", Type: 1, Class: 1}

	next, err := WriteQuestion(buf, 0, q)
	require.NoError(t, err)

	got, end, err := ReadQuestion(buf, 0)
	require.NoError(t, err)
	require.Equal(t, next, end)
	require.Equal(t, q, got)
}

func TestReadMessage(t *testing.T) {
	buf := make([]byte, 512)
	h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1, ANCount: 1}
	require.NoError(t, WriteHeader(buf, h))

	q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
	qEnd, err := WriteQuestion(buf, HeaderLen, q)
	require.NoError(t, err)

	ans := Answer{Name: "", Type: TypeA, Class: ClassIN, TTL: 60, RData: []byte{1, 2, 3, 4}}
	resp, err := BuildResponse(buf[:qEnd], []Answer{ans}, 0)
	require.NoError(t, err)

	msg, err := ReadMessagePooled(resp)
	require.NoError(t, err)
	defer msg.Release()
	require.Equal(t, h.ID, msg.Header.ID)
	require.Equal(t, uint16(1), msg.Header.QDCount)
	require.Equal(t, uint16(1), msg.Header.ANCount)
	require.Len(t, msg.Questions, 1)
	require.Equal(t, "example.com", msg.Questions[0].Name)
	require.Len(t, msg.Answers, 1)
	require.Equal(t, uint32(60), msg.Answers[0].TTL)
}
