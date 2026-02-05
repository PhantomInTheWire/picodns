package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"picodns/internal/dns"
)

// queryUDP performs a UDP DNS query. The caller must call pool.Put(bufPtr) when done with resp.
// If cp is nil, a new connection is created for this query.
func queryUDP(ctx context.Context, raddr *net.UDPAddr, req []byte, timeout time.Duration, pool *sync.Pool, cp *connPool, validate bool) (resp []byte, bufPtr *[]byte, needsTCP bool, err error) {
	var conn *net.UDPConn
	var release func()

	if cp != nil {
		conn, release, err = cp.get()
		if err != nil {
			return nil, nil, false, err
		}
		defer release()
	} else {
		conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, false, err
		}
		defer conn.Close()
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, false, err
	}

	if _, err := conn.WriteTo(req, raddr); err != nil {
		return nil, nil, false, err
	}

	bufPtr = pool.Get().(*[]byte)
	buf := *bufPtr

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		pool.Put(bufPtr)
		return nil, nil, false, err
	}

	// Return slice of pooled buffer - caller owns bufPtr now
	resp = buf[:n]

	if validate {
		if err := dns.ValidateResponse(req, resp); err != nil {
			pool.Put(bufPtr)
			return nil, nil, false, err
		}
	}

	header, err := dns.ReadHeader(resp)
	if err == nil && (header.Flags&dns.FlagTC) != 0 {
		return resp, bufPtr, true, nil
	}

	return resp, bufPtr, false, nil
}

// queryUDPString performs a UDP DNS query and returns a copy of the response.
// This is used by the recursive resolver which doesn't need zero-allocation.
func queryUDPString(ctx context.Context, server string, req []byte, timeout time.Duration, pool *sync.Pool, validate bool) ([]byte, bool, error) {
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, false, err
	}
	resp, bufPtr, needsTCP, err := queryUDP(ctx, raddr, req, timeout, pool, nil, validate)
	if err != nil {
		return nil, false, err
	}

	// Make a copy for recursive resolver (it expects to own the response)
	respCopy := make([]byte, len(resp))
	copy(respCopy, resp)
	pool.Put(bufPtr)

	return respCopy, needsTCP, nil
}
