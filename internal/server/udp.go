package server

import (
	"context"
	"errors"
	"net"

	"picodns/internal/dns"
	"picodns/internal/types"
)

func (s *Server) maybeLogServfail(resp []byte, addr net.Addr) {
	if s == nil || s.logger == nil {
		return
	}
	if !s.logServfail {
		return
	}
	if len(resp) < dns.HeaderLen {
		return
	}
	hdr, err := dns.ReadHeader(resp)
	if err != nil {
		return
	}
	if (hdr.Flags & 0x000F) != dns.RcodeServer {
		return
	}
	s.logger.Debug("sending SERVFAIL", "id", hdr.ID, "bytes", len(resp), "addr", addr.String())
}

// queryJob represents a single DNS query to be processed.
type queryJob struct {
	dataPtr *[]byte
	n       int
	addr    net.Addr
	writer  *udpWriter
}

type udpWriter struct {
	conn net.PacketConn
	ch   chan udpWrite
}

type udpWrite struct {
	resp    []byte
	addr    net.Addr
	cleanup func()
	bufPtr  *[]byte
}

func (s *Server) udpWriteLoop(writer *udpWriter) {
	// Rate-limit write errors.
	var writeErrCount uint64
	flushItem := func(item udpWrite) {
		if len(item.resp) > 0 {
			if s.logServfail {
				s.maybeLogServfail(item.resp, item.addr)
			}
			if _, writeErr := writer.conn.WriteTo(item.resp, item.addr); writeErr != nil {
				s.WriteErrors.Add(1)
				writeErrCount++
				if writeErrCount == 1 || writeErrCount%1000 == 0 {
					s.logger.Error("write error", "error", writeErr, "count", writeErrCount)
				}
			}
		}
		if item.cleanup != nil {
			item.cleanup()
		}
		if item.bufPtr != nil {
			s.bufPool.Put(item.bufPtr)
		}
	}

	for item := range writer.ch {
		flushItem(item)
	}
}

func (s *Server) udpReadLoop(ctx context.Context, writer *udpWriter, cacheResolver types.CacheResolver) {
	defer func() { _ = writer.conn.Close() }()

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = writer.conn.Close()
		case <-done:
		}
	}()

	// Rate-limit read errors.
	var readErrCount uint64
	for {
		bufPtr := s.bufPool.Get()
		b := *bufPtr
		b = b[:cap(b)]
		n, addr, readErr := writer.conn.ReadFrom(b)
		if readErr != nil {
			s.bufPool.Put(bufPtr)
			if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
				return
			}
			readErrCount++
			if readErrCount == 1 || readErrCount%1000 == 0 {
				s.logger.Error("read error", "error", readErr, "count", readErrCount)
			}
			continue
		}

		s.TotalQueries.Add(1)
		*bufPtr = b[:n]

		if !dns.IsValidRequest(b[:n]) {
			if hdr, err := dns.ReadHeader(b[:n]); err == nil {
				var formerr [dns.HeaderLen]byte
				formerr[0] = byte(hdr.ID >> 8)
				formerr[1] = byte(hdr.ID)
				// 0x80 = QR=1 (response), 0x01 = RD; preserve OPCODE from request
				opcode := byte((hdr.Flags & dns.FlagOpcode) >> 8)
				if hdr.Flags&dns.FlagRD != 0 {
					formerr[2] = 0x80 | 0x01 | opcode
				} else {
					formerr[2] = 0x80 | opcode
				}
				// RCODE=1 (Format Error)
				formerr[3] = 0x01
				formerr[4] = 0x00
				formerr[5] = 0x00
				formerr[6] = 0x00
				formerr[7] = 0x00
				formerr[8] = 0x00
				formerr[9] = 0x00
				formerr[10] = 0x00
				formerr[11] = 0x00
				if _, err := writer.conn.WriteTo(formerr[:], addr); err != nil {
					s.WriteErrors.Add(1)
				}
			}
			s.bufPool.Put(bufPtr)
			continue
		}

		// Cache-hit fast path: serve directly without queueing.
		// Hard separation: hits never queue behind misses.
		if cacheResolver != nil {
			if resp, cleanup, ok := cacheResolver.ResolveFromCache(ctx, b[:n]); ok {
				// Direct write from reader goroutine - fastest path.
				// No channel, no queuing, no blocking.
				if s.logServfail {
					s.maybeLogServfail(resp, addr)
				}
				if _, err := writer.conn.WriteTo(resp, addr); err != nil {
					s.WriteErrors.Add(1)
				}
				if cleanup != nil {
					cleanup()
				}
				s.bufPool.Put(bufPtr)
				continue
			}
		}

		select {
		case s.jobQueue <- queryJob{dataPtr: bufPtr, n: n, addr: addr, writer: writer}:
		default:
			s.bufPool.Put(bufPtr)
			dropped := s.DroppedPackets.Add(1)
			if dropped == 1 || dropped%100 == 0 {
				s.logger.Warn("dropping packet", "reason", "queue full", "dropped_total", dropped)
			}
		}
	}
}

func (s *Server) worker(ctx context.Context) {
	var handlerErrCount uint64
	for job := range s.jobQueue {
		resp, cleanup, err := s.resolver.Resolve(ctx, (*job.dataPtr)[:job.n])
		if err != nil {
			if cleanup != nil {
				cleanup()
			}
			s.HandlerErrors.Add(1)
			handlerErrCount++
			if handlerErrCount == 1 || handlerErrCount%1000 == 0 {
				s.logger.Error("handler error", "error", err, "count", handlerErrCount)
			}
			// Best-effort SERVFAIL so clients don't time out.
			if job.writer != nil {
				if sf, ok := servfailFromRequestInPlace((*job.dataPtr)[:job.n]); ok {
					select {
					case job.writer.ch <- udpWrite{resp: sf, addr: job.addr, cleanup: nil, bufPtr: job.dataPtr}:
						continue
					default:
						// Fall through to release buffer.
					}
				}
			}
			s.bufPool.Put(job.dataPtr)
			continue
		}
		if len(resp) == 0 {
			if cleanup != nil {
				cleanup()
			}
			s.bufPool.Put(job.dataPtr)
			continue
		}
		// Send write to per-socket writer to avoid concurrent writes on the same conn.
		if job.writer != nil {
			select {
			case job.writer.ch <- udpWrite{resp: resp, addr: job.addr, cleanup: cleanup, bufPtr: job.dataPtr}:
			default:
				// Backpressure: drop response but release resources.
				s.DroppedResponses.Add(1)
				if cleanup != nil {
					cleanup()
				}
				s.bufPool.Put(job.dataPtr)
			}
		} else {
			// Fallback (shouldn't happen).
			s.bufPool.Put(job.dataPtr)
			if cleanup != nil {
				cleanup()
			}
		}
	}
}
