package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"picodns/internal/obs"
)

type connPool struct {
	mu    sync.Mutex
	conns []*udpConn

	getCount  uint32
	lastPrune time.Time

	tracers struct {
		get     *obs.FuncTracer
		release *obs.FuncTracer
	}
}

type udpConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
	inUse    bool
}

func newConnPool() *connPool {
	p := &connPool{
		conns: make([]*udpConn, 0, ConnPoolMaxConns),
	}

	p.tracers.get = obs.NewFuncTracer("connPool.get", nil)
	p.tracers.release = obs.NewFuncTracer("connPool.release", nil)

	obs.GlobalRegistry.Register(p.tracers.get)
	obs.GlobalRegistry.Register(p.tracers.release)

	return p
}

// get returns a connection from the pool or creates a new one.
// Stale connections (idle longer than ConnPoolIdleTimeout) are closed and removed.
// If the pool is exhausted, it creates an ephemeral connection as a fallback.
//
// The returned release function must be called. If bad is true, the connection is
// closed and removed (so late UDP responses on that local port can't poison future
// queries when sockets are reused).
func (p *connPool) get(ctx context.Context) (*net.UDPConn, func(bad bool), error) {
	defer p.tracers.get.Trace()()

	now := time.Now()
	var toClose []*net.UDPConn

	p.mu.Lock()
	p.getCount++
	prune := p.getCount%64 == 0 || (p.lastPrune.IsZero() || now.Sub(p.lastPrune) >= ConnPoolIdleTimeout)
	if prune {
		p.lastPrune = now
		for i := 0; i < len(p.conns); {
			uc := p.conns[i]
			if uc.inUse {
				i++
				continue
			}
			if now.Sub(uc.lastUsed) < ConnPoolIdleTimeout {
				i++
				continue
			}
			// Stale; remove from pool and close outside lock.
			toClose = append(toClose, uc.conn)
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
		}
	}

	activeIdx := -1
	for i := 0; i < len(p.conns); i++ {
		uc := p.conns[i]
		if uc.inUse {
			continue
		}
		if now.Sub(uc.lastUsed) >= ConnPoolIdleTimeout {
			// If we didn't prune this time, avoid returning a stale conn.
			continue
		}
		activeIdx = i
		break
	}

	if activeIdx != -1 {
		uc := p.conns[activeIdx]
		uc.inUse = true
		uc.lastUsed = now
		p.mu.Unlock()
		for _, c := range toClose {
			_ = c.Close()
		}
		return uc.conn, func(bad bool) { p.releaseOrDiscard(uc, bad) }, nil
	}

	canAddToPool := len(p.conns) < ConnPoolMaxConns
	p.mu.Unlock()
	for _, c := range toClose {
		_ = c.Close()
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}

	if canAddToPool {
		p.mu.Lock()
		if len(p.conns) < ConnPoolMaxConns {
			uc := &udpConn{
				conn:     conn,
				lastUsed: now,
				inUse:    true,
			}
			p.conns = append(p.conns, uc)
			p.mu.Unlock()
			return conn, func(bad bool) { p.releaseOrDiscard(uc, bad) }, nil
		}
		p.mu.Unlock()
	}

	return conn, func(bad bool) { _ = conn.Close() }, nil
}

func (p *connPool) releaseOrDiscard(uc *udpConn, bad bool) {
	defer p.tracers.release.Trace()()

	var toClose *net.UDPConn

	p.mu.Lock()
	uc.inUse = false
	uc.lastUsed = time.Now()
	if bad {
		for i := 0; i < len(p.conns); i++ {
			if p.conns[i] == uc {
				p.conns = append(p.conns[:i], p.conns[i+1:]...)
				break
			}
		}
		toClose = uc.conn
	}
	p.mu.Unlock()

	if toClose != nil {
		_ = toClose.Close()
	}
}
