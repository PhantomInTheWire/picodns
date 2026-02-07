package pool

import "sync"

// Bytes is a pool of reusable byte slices.
type Bytes struct {
	pool *sync.Pool
}

// NewBytes creates a new byte pool with the given buffer size.
func NewBytes(size int) *Bytes {
	return &Bytes{
		pool: &sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

// Get retrieves a byte slice from the pool.
// The returned slice has capacity size but length 0.
func (p *Bytes) Get() *[]byte {
	return p.pool.Get().(*[]byte)
}

// Put returns a byte slice to the pool.
func (p *Bytes) Put(buf *[]byte) {
	p.pool.Put(buf)
}

const (
	// MaxDNSBuffer is the maximum DNS message size (4096 bytes for EDNS0).
	MaxDNSBuffer = 4096
)

// DefaultPool is the default pool for DNS message buffers.
var DefaultPool = NewBytes(MaxDNSBuffer)
