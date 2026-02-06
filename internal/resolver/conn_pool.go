package resolver

import (
	"net"
	"sync"
	"time"
)

// connPool manages a pool of reusable UDP connections
type connPool struct {
	mu    sync.Mutex
	conns []*udpConn
}

// udpConn wraps a UDP connection with its last used time for idle timeout
type udpConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
	inUse    bool
}

// newConnPool creates a new connection pool with default settings
func newConnPool() *connPool {
	return &connPool{
		conns: make([]*udpConn, 0, ConnPoolMaxConns),
	}
}

// get returns a connection from the pool or creates a new one
func (p *connPool) get() (*net.UDPConn, func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	// Try to find an available connection
	for _, uc := range p.conns {
		if !uc.inUse && now.Sub(uc.lastUsed) < ConnPoolIdleTimeout {
			uc.inUse = true
			uc.lastUsed = now
			return uc.conn, func() { p.release(uc) }, nil
		}
	}

	// Create new connection if under limit
	if len(p.conns) < ConnPoolMaxConns {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, err
		}

		uc := &udpConn{
			conn:     conn,
			lastUsed: now,
			inUse:    true,
		}
		p.conns = append(p.conns, uc)
		return conn, func() { p.release(uc) }, nil
	}

	// Pool exhausted - create ephemeral connection (fallback)
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() { _ = conn.Close() }, nil
}

// release marks a connection as available
func (p *connPool) release(uc *udpConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	uc.inUse = false
	uc.lastUsed = time.Now()
}

// close closes all connections in the pool
// nolint:unused // Reserved for future use
func (p *connPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, uc := range p.conns {
		if uc.conn != nil {
			_ = uc.conn.Close()
		}
	}
	p.conns = p.conns[:0]
}
