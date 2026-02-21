package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/config"
	"picodns/internal/pool"
	"picodns/internal/types"
)

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
				s.udpWriteLoop(ctx, writer)
			}(w)
			if i == 0 {
				s.logger.Info("dns server listening", "listen", addr, "udp_sockets", udpSockets)
			}

			readersWg.Add(1)
			go func(writer *udpWriter) {
				defer readersWg.Done()
				s.udpReadLoop(ctx, writer, cacheResolver)
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
