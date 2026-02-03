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

func TestDecodeNameCycle(t *testing.T) {
	// Pointer points to itself
	buf := []byte{
		0xC0, 0x00,
	}
	_, _, err := DecodeName(buf, 0)
	require.ErrorIs(t, err, ErrBadPointer)

	// Cycle: 0 -> 2 -> 0
	buf2 := []byte{
		0xC0, 0x02,
		0xC0, 0x00,
	}
	_, _, err = DecodeName(buf2, 0)
	require.ErrorIs(t, err, ErrBadPointer)
}
