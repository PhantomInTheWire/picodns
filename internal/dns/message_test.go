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
