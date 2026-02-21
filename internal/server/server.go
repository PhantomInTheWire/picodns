package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"picodns/internal/config"
	"picodns/internal/dns"
	"picodns/internal/obs"
	"picodns/internal/pool"
	"picodns/internal/types"
)

// queryJob represents a single DNS query to be processed
type queryJob struct {
	dataPtr    *[]byte
	n          int
	addr       net.Addr
	writer     *udpWriter
	enqueuedNs int64
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
	sample         atomic.Uint64

	queueWait obs.DurationStat
	resolve   obs.DurationStat
	write     obs.DurationStat

	cacheCounters func() (hits uint64, miss uint64)
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
					var enqNs int64
					if obsEnabled {
						// Sample timings (1/256) to minimize overhead during benchmarks.
						if (s.sample.Add(1) & 0xFF) == 0 {
							enqNs = time.Now().UnixNano()
						}
					}

					*bufPtr = b[:n]
					// Cache-hit fast path: serve directly without queueing.
					// Hard separation: hits never queue behind misses.
					if cacheResolver != nil {
						if resp, cleanup, ok := cacheResolver.ResolveFromCache(b[:n]); ok {
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
					case s.jobQueue <- queryJob{dataPtr: bufPtr, n: n, addr: addr, writer: writer, enqueuedNs: enqNs}:
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
	qs := s.queueWait.Snapshot()
	rs := s.resolve.Snapshot()
	ws := s.write.Snapshot()

	bottleneck := "resolve"
	bottleneckAvg := rs.Avg
	if qs.Avg > bottleneckAvg {
		bottleneck = "queue_wait"
		bottleneckAvg = qs.Avg
	}
	if ws.Avg > bottleneckAvg {
		bottleneck = "write"
		bottleneckAvg = ws.Avg
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
		"queue_wait_avg", qs.Avg,
		"queue_wait_max", qs.Max,
		"resolve_avg", rs.Avg,
		"resolve_max", rs.Max,
		"write_avg", ws.Avg,
		"write_max", ws.Max,
		"bottleneck_stage", bottleneck,
		"bottleneck_avg", bottleneckAvg,
		"cache_hits", hits,
		"cache_miss", miss,
		"cache_hit_rate", cacheHitRate,
	)
	return ctx.Err()
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
		s.bufPool.Put(bufPtr)
		if err != nil {
			s.HandlerErrors.Add(1)
			s.logger.Error("handler error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			return
		}
		if len(resp) == 0 {
			if cleanup != nil {
				cleanup()
			}
			continue
		}
		if len(resp) > int(^uint16(0)) {
			s.HandlerErrors.Add(1)
			s.logger.Error("response too large", "size", len(resp))
			if cleanup != nil {
				cleanup()
			}
			return
		}

		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			s.WriteErrors.Add(1)
			s.logger.Error("write error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			return
		}
		if _, err := conn.Write(resp); err != nil {
			s.WriteErrors.Add(1)
			s.logger.Error("write error", "error", err)
			if cleanup != nil {
				cleanup()
			}
			return
		}

		if cleanup != nil {
			cleanup()
		}
	}
}

func (s *Server) worker(ctx context.Context) {
	var handlerErrCount uint64
	for job := range s.jobQueue {
		timed := job.enqueuedNs != 0
		var resStart time.Time
		if timed {
			now := time.Now().UnixNano()
			wait := time.Duration(now - job.enqueuedNs)
			s.queueWait.Observe(wait)
			resStart = time.Unix(0, now)
		}
		resp, cleanup, err := s.resolver.Resolve(ctx, (*job.dataPtr)[:job.n])
		if timed {
			s.resolve.Observe(time.Since(resStart))
		}
		if err != nil {
			s.HandlerErrors.Add(1)
			handlerErrCount++
			if handlerErrCount == 1 || handlerErrCount%1000 == 0 {
				s.logger.Error("handler error", "error", err, "count", handlerErrCount)
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
		var wStart time.Time
		if timed {
			wStart = time.Now()
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
		if timed {
			s.write.Observe(time.Since(wStart))
		}
	}
}

func listenUDPPacket(addr string, reusePort bool) (net.PacketConn, error) {
	if !reusePort {
		return net.ListenPacket("udp", addr)
	}
	var lc net.ListenConfig
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
				ctrlErr = e
				return
			}
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); e != nil {
				ctrlErr = e
				return
			}
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
	return lc.ListenPacket(context.Background(), "udp", addr)
}
