package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/config"
	"picodns/internal/dns"
	"picodns/internal/obs"
	"picodns/internal/pool"
	"picodns/internal/types"
)

// queryJob represents a single DNS query to be processed
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

type Server struct {
	cfg            config.Config
	logger         *slog.Logger
	resolver       types.Resolver
	bufPool        *pool.Bytes
	jobQueue       chan queryJob
	TotalQueries   atomic.Uint64
	DroppedPackets atomic.Uint64
	HandlerErrors  atomic.Uint64
	WriteErrors    atomic.Uint64

	cacheCounters func() (hits uint64, miss uint64)
}

// servfailFromRequestInPlace rewrites req in-place into a minimal SERVFAIL response.
// The returned slice references req.
func servfailFromRequestInPlace(req []byte) ([]byte, bool) {
	hdr, err := dns.ReadHeader(req)
	if err != nil || hdr.QDCount == 0 {
		return nil, false
	}
	nameEnd, err := dns.SkipName(req, dns.HeaderLen)
	if err != nil {
		return nil, false
	}
	qEnd := nameEnd + 4 // qtype + qclass
	if qEnd > len(req) {
		return nil, false
	}

	hdr.Flags = dns.FlagQR | (hdr.Flags & dns.FlagOpcode) | (hdr.Flags & dns.FlagRD) | dns.FlagRA | (dns.RcodeServer & 0x000F)
	hdr.QDCount = 1
	hdr.ANCount = 0
	hdr.NSCount = 0
	hdr.ARCount = 0
	_ = dns.WriteHeader(req, hdr)

	return req[:qEnd], true
}

func New(cfg config.Config, logger *slog.Logger, res types.Resolver) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		logger:   logger,
		resolver: res,
		bufPool:  pool.DefaultPool,
		jobQueue: make(chan queryJob, cfg.Workers),
	}
}

// SetCacheCounters wires cache hit/miss counters into periodic stats logs.
// It is safe to call before Start.
func (s *Server) SetCacheCounters(fn func() (hits uint64, miss uint64)) {
	s.cacheCounters = fn
}

func (s *Server) Start(ctx context.Context) error {
	if len(s.cfg.ListenAddrs) == 0 {
		return errors.New("no listen addresses configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var workersWg sync.WaitGroup
	var readersWg sync.WaitGroup
	var writersWg sync.WaitGroup
	startTime := time.Now()
	obsEnabled := s.cfg.Stats

	shutdown := func() {
		cancel()
		readersWg.Wait()
		close(s.jobQueue)
		workersWg.Wait()
		writersWg.Wait()
	}

	for i := 0; i < s.cfg.Workers; i++ {
		workersWg.Add(1)
		go func() {
			defer workersWg.Done()
			s.worker(ctx)
		}()
	}

	udpSockets := s.cfg.UDPSockets
	if udpSockets <= 0 {
		udpSockets = 1
	}
	cacheResolver, _ := s.resolver.(types.CacheResolver)

	for _, addr := range s.cfg.ListenAddrs {
		for i := 0; i < udpSockets; i++ {
			conn, err := listenUDPPacket(addr, udpSockets > 1)
			if err != nil {
				shutdown()
				return err
			}
			w := &udpWriter{conn: conn, ch: make(chan udpWrite, s.cfg.Workers)}
			writersWg.Add(1)
			go func(writer *udpWriter) {
				defer writersWg.Done()
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
			}(w)
			if i == 0 {
				s.logger.Info("dns server listening", "listen", addr, "udp_sockets", udpSockets)
			}

			readersWg.Add(1)
			go func(writer *udpWriter) {
				defer readersWg.Done()
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
			}(w)
		}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			shutdown()
			return err
		}
		s.logger.Info("dns tcp server listening", "listen", addr)

		readersWg.Add(1)
		go func(l net.Listener) {
			defer readersWg.Done()
			defer func() { _ = l.Close() }()

			go func() {
				<-ctx.Done()
				_ = l.Close()
			}()

			for {
				conn, err := l.Accept()
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					s.logger.Error("tcp accept error", "error", err)
					continue
				}
				go s.handleTCPConn(ctx, conn)
			}
		}(ln)
	}

	<-ctx.Done()
	s.logger.Info("shutting down")
	shutdown()

	if !obsEnabled {
		s.logger.Info("server shutdown complete",
			"total_queries", s.TotalQueries.Load(),
			"dropped_packets", s.DroppedPackets.Load(),
			"handler_errors", s.HandlerErrors.Load(),
			"write_errors", s.WriteErrors.Load(),
		)
		return ctx.Err()
	}

	uptime := time.Since(startTime)
	avgQPS := 0.0
	total := s.TotalQueries.Load()
	if uptime > 0 {
		avgQPS = float64(total) / uptime.Seconds()
	}

	hits, miss := uint64(0), uint64(0)
	cacheHitRate := 0.0
	if s.cacheCounters != nil {
		hits, miss = s.cacheCounters()
		if hits+miss > 0 {
			cacheHitRate = float64(hits) / float64(hits+miss)
		}
	}

	s.logger.Info("server shutdown complete",
		"uptime", uptime,
		"avg_qps", avgQPS,
		"queue_len", len(s.jobQueue),
		"queue_cap", cap(s.jobQueue),
		"total_queries", total,
		"dropped_packets", s.DroppedPackets.Load(),
		"handler_errors", s.HandlerErrors.Load(),
		"write_errors", s.WriteErrors.Load(),
		"cache_hits", hits,
		"cache_miss", miss,
		"cache_hit_rate", cacheHitRate,
	)
	if obsEnabled {
		s.writePerfReport()
	}

	return ctx.Err()
}

func (s *Server) writePerfReport() {
	if !obs.Enabled() {
		return
	}
	path := s.cfg.PerfReport
	if path == "" {
		return
	}
	data, err := obs.GlobalRegistry.ReportJSON()
	if err != nil {
		s.logger.Error("failed to build perf report", "error", err)
		return
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			s.logger.Error("failed to create perf report dir", "dir", dir, "error", mkErr)
			return
		}
	}
	if wErr := os.WriteFile(path, data, 0o644); wErr != nil {
		s.logger.Error("failed to write perf report", "path", path, "error", wErr)
		return
	}
	s.logger.Info("perf report written", "path", path, "bytes", len(data))
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var lenBuf [2]byte
	for {
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
		if _, err := io.ReadFull(conn, buf); err != nil {
			s.bufPool.Put(bufPtr)
			return
		}

		resp, cleanup, err := s.resolver.Resolve(ctx, buf)
		if err != nil {
			s.HandlerErrors.Add(1)
			s.logger.Error("handler error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			// Best-effort SERVFAIL response.
			if sf, ok := servfailFromRequestInPlace(buf); ok {
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(sf)))
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
