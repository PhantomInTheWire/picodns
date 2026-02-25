package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"picodns/internal/dns"
)

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Per-connection context so the goroutine exits when handler returns
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-connCtx.Done()
		_ = conn.Close()
	}()

	var lenBuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen <= 0 || msgLen > dns.MaxMessageSize {
			s.logger.Warn("invalid tcp message size", "size", msgLen)
			return
		}

		bufPtr := s.bufPool.Get()
		buf := (*bufPtr)[:msgLen]
		_ = conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
		if _, err := io.ReadFull(conn, buf); err != nil {
			s.bufPool.Put(bufPtr)
			return
		}

		s.TotalQueries.Add(1)

		resp, cleanup, err := s.resolver.Resolve(ctx, buf)
		if err != nil {
			s.HandlerErrors.Add(1)
			s.logger.Error("handler error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			// Best-effort SERVFAIL response.
			if sf, ok := servfailFromRequestInPlace(buf); ok {
				if s.logServfail {
					s.maybeLogServfail(sf, conn.RemoteAddr())
				}
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sf)))
				_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
				if _, werr := conn.Write(lenBuf[:]); werr == nil {
					_, _ = conn.Write(sf)
				}
			}
			s.bufPool.Put(bufPtr)
			return
		}
		if len(resp) == 0 {
			if cleanup != nil {
				cleanup()
			}
			s.bufPool.Put(bufPtr)
			continue
		}
		if len(resp) > int(^uint16(0)) {
			s.HandlerErrors.Add(1)
			s.logger.Error("response too large", "size", len(resp))
			if cleanup != nil {
				cleanup()
			}
			s.bufPool.Put(bufPtr)
			return
		}

		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
		if s.logServfail {
			s.maybeLogServfail(resp, conn.RemoteAddr())
		}
		_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			s.WriteErrors.Add(1)
			s.logger.Error("write error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			s.bufPool.Put(bufPtr)
			return
		}
		if _, err := conn.Write(resp); err != nil {
			s.WriteErrors.Add(1)
			s.logger.Error("write error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			s.bufPool.Put(bufPtr)
			return
		}

		if cleanup != nil {
			cleanup()
		}
		s.bufPool.Put(bufPtr)
	}
}
