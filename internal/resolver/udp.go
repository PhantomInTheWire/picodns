package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"picodns/internal/dns"
)

func queryUDP(ctx context.Context, server string, req []byte, timeout time.Duration, pool *sync.Pool, validate bool) ([]byte, bool, error) {
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, false, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, false, err
	}

	if _, err := conn.Write(req); err != nil {
		return nil, false, err
	}

	bufPtr := pool.Get().(*[]byte)
	defer pool.Put(bufPtr)
	buf := *bufPtr

	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])

	if validate {
		if err := dns.ValidateResponse(req, resp); err != nil {
			return nil, false, err
		}
	}

	header, err := dns.ReadHeader(resp)
	if err == nil && (header.Flags&dns.FlagTC) != 0 {
		return resp, true, nil
	}

	return resp, false, nil
}
