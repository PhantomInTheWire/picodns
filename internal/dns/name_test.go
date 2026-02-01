package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeName(t *testing.T) {
	buf := make([]byte, 64)
	next, err := EncodeName(buf, 0, "google.com")
	require.NoError(t, err)

	name, end, err := DecodeName(buf, 0)
	require.NoError(t, err)
	require.Equal(t, next, end)
	require.Equal(t, "google.com", name)
}

func TestEncodeNameExactBuffer(t *testing.T) {
	// Test that a name exactly filling the buffer works
	// "x.y" needs: 1 (length) + 1 (x) + 1 (length) + 1 (y) + 1 (null) = 5 bytes
	buf := make([]byte, 5)
	next, err := EncodeName(buf, 0, "x.y")
	require.NoError(t, err)
	require.Equal(t, 5, next)

	// Verify it can be decoded
	name, end, err := DecodeName(buf, 0)
	require.NoError(t, err)
	require.Equal(t, next, end)
	require.Equal(t, "x.y", name)
}

func TestDecodeNameCompressionPointer(t *testing.T) {
	buf := []byte{
		3, 'w', 'w', 'w',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
		4, 'm', 'a', 'i', 'l',
		0xC0, 0x04,
	}

	name1, next, err := DecodeName(buf, 0)
	require.NoError(t, err)
	require.Equal(t, "www.example.com", name1)

	name2, end, err := DecodeName(buf, next)
	require.NoError(t, err)
	require.Equal(t, "mail.example.com", name2)
	require.Equal(t, len(buf), end)
}
