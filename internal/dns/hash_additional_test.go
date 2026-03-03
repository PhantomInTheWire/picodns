package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashNameStringNormalizesInput(t *testing.T) {
	require.Equal(t, HashNameString("Example.COM."), HashNameString("example.com"))
	require.NotEqual(t, HashNameString("example.com"), HashNameString("example.net"))
}

func TestHashQuestionKeyFromWire(t *testing.T) {
	buf := make([]byte, 128)
	n, err := BuildQueryInto(buf, 0xBEEF, "WWW.Example.COM.", TypeA, ClassIN)
	require.NoError(t, err)

	key, qtype, qclass, next, compressed, err := HashQuestionKeyFromWire(buf[:n], HeaderLen)
	require.NoError(t, err)
	require.False(t, compressed)
	require.Equal(t, TypeA, qtype)
	require.Equal(t, ClassIN, qclass)
	require.Equal(t, n, next)
	require.Equal(t, hashQuestionKey("www.example.com", TypeA, ClassIN), key)
}

func TestHashQuestionKeyFromWireCompressedAndShortBuffer(t *testing.T) {
	msg := []byte{CompressionFlag, QuestionNameOffset}
	_, _, _, _, compressed, err := HashQuestionKeyFromWire(msg, 0)
	require.NoError(t, err)
	require.True(t, compressed)

	_, _, _, _, compressed, err = HashQuestionKeyFromWire([]byte{3, 'w', 'w'}, 0)
	require.ErrorIs(t, err, ErrShortBuffer)
	require.False(t, compressed)
}

func hashQuestionKey(name string, qtype, qclass uint16) uint64 {
	key := HashNameString(name)
	key ^= uint64(qtype) << 32
	key ^= uint64(qclass)
	return key
}
