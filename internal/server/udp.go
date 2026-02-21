package server

import (
	"context"
	"errors"
	"net"

	"picodns/internal/types"
)

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

func (s *Server) udpWriteLoop(ctx context.Context, writer *udpWriter) {
	// Rate-limit write errors.
	var writeErrCount uint64
	flushItem := func(item udpWrite) {
		if len(item.resp) > 0 {
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

	for {
		var item udpWrite
		var ok bool
		select {
		case <-ctx.Done():
			return
		case item, ok = <-writer.ch:
			if !ok {
				return
			}
		}
		flushItem(item)
	}
}

func (s *Server) udpReadLoop(ctx context.Context, writer *udpWriter, cacheResolver types.CacheResolver) {
	defer func() { _ = writer.conn.Close() }()

	go func() {
		<-ctx.Done()
		_ = writer.conn.Close()
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
		// Cache-hit fast path: serve directly without queueing.
		// Hard separation: hits never queue behind misses.
		if cacheResolver != nil {
			if resp, cleanup, ok := cacheResolver.ResolveFromCache(ctx, b[:n]); ok {
				// Direct write from reader goroutine - fastest path.
				// No channel, no queuing, no blocking.
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
				s.WriteErrors.Add(1)
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
