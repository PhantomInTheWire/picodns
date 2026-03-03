package pool

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBytesPoolResetsLengthOnGet(t *testing.T) {
	p := NewBytes(32)

	bufPtr := p.Get()
	*bufPtr = (*bufPtr)[:8]
	p.Put(bufPtr)

	bufPtr = p.Get()
	require.Len(t, *bufPtr, 32)
	require.Equal(t, 32, cap(*bufPtr))
}

func TestDefaultPoolBufferSize(t *testing.T) {
	bufPtr := DefaultPool.Get()
	defer DefaultPool.Put(bufPtr)

	require.Len(t, *bufPtr, MaxDNSBuffer)
	require.Equal(t, MaxDNSBuffer, cap(*bufPtr))
}
