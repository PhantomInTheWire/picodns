package server

import (
	"context"
	"net"
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

func (s *Server) worker(ctx context.Context) {
	var handlerErrCount uint64
	for job := range s.jobQueue {
		resp, cleanup, err := s.resolver.Resolve(ctx, (*job.dataPtr)[:job.n])
		if err != nil {
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
