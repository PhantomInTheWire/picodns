package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeNameAndIsSubdomain(t *testing.T) {
	require.Equal(t, "example.com", NormalizeName("Example.COM."))
	require.True(t, IsSubdomain("api.example.com", "example.com"))
	require.True(t, IsSubdomain("example.com", "example.com"))
	require.False(t, IsSubdomain("example.net", "example.com"))
	require.True(t, IsSubdomain("example.net", "."))
}

func TestExtractNameFromData(t *testing.T) {
	buf := make([]byte, 128)
	off, err := EncodeName(buf, 0, "Ns1.Example.COM.")
	require.NoError(t, err)

	require.Equal(t, "ns1.example.com", ExtractNameFromData(buf[:off], 0))
	require.Equal(t, "", ExtractNameFromData(buf[:off], off+1))
}

func TestBuildQueryIntoAndBuildQueryIntoWithEDNS(t *testing.T) {
	buf := make([]byte, 128)
	n, err := BuildQueryInto(buf, 0xBEEF, "Example.COM.", TypeAAAA, ClassIN)
	require.NoError(t, err)

	msg, err := ReadMessagePooled(buf[:n])
	require.NoError(t, err)
	defer msg.Release()
	require.Equal(t, uint16(0xBEEF), msg.Header.ID)
	require.Equal(t, uint16(1), msg.Header.QDCount)
	require.Equal(t, "example.com", NormalizeName(msg.Questions[0].Name))
	require.Equal(t, TypeAAAA, msg.Questions[0].Type)

	ednsBuf := make([]byte, 128)
	n, err = BuildQueryIntoWithEDNS(ednsBuf, 0xCAFE, "example.com", TypeA, ClassIN, 1232)
	require.NoError(t, err)

	msg, err = ReadMessagePooled(ednsBuf[:n])
	require.NoError(t, err)
	defer msg.Release()
	require.Equal(t, uint16(1), msg.Header.ARCount)
	require.Len(t, msg.Additionals, 1)
	require.Equal(t, TypeOPT, msg.Additionals[0].Type)

	_, err = BuildQueryInto(make([]byte, HeaderLen), 1, "example.com", TypeA, ClassIN)
	require.ErrorIs(t, err, ErrShortBuffer)
}
