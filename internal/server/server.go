package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"picodns/internal/config"
	"picodns/internal/pool"
	"picodns/internal/types"
)

// queryJob represents a single DNS query to be processed
type queryJob struct {
	dataPtr *[]byte
	n       int
	addr    net.Addr
	conn    net.PacketConn
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

func (s *Server) Start(ctx context.Context) error {
	if len(s.cfg.ListenAddrs) == 0 {
		return errors.New("no listen addresses configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var workersWg sync.WaitGroup
	var readersWg sync.WaitGroup

	shutdown := func() {
		cancel()
		readersWg.Wait()
		close(s.jobQueue)
		workersWg.Wait()
	}

	for i := 0; i < s.cfg.Workers; i++ {
		workersWg.Add(1)
		go func() {
			defer workersWg.Done()
			s.worker(ctx)
		}()
	}

	for _, addr := range s.cfg.ListenAddrs {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			shutdown()
			return err
		}
		s.logger.Info("dns server listening", "listen", addr)

		readersWg.Add(1)
		go func(c net.PacketConn) {
			defer readersWg.Done()
			defer func() { _ = c.Close() }()

			go func() {
				<-ctx.Done()
				_ = c.Close()
			}()

			for {
				bufPtr := s.bufPool.Get()
				buf := *bufPtr
				n, addr, readErr := c.ReadFrom(buf)
				if readErr != nil {
					s.bufPool.Put(bufPtr)
					if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
						return
					}
					s.logger.Error("read error", "error", readErr)
					continue
				}

				s.TotalQueries.Add(1)

				select {
				case s.jobQueue <- queryJob{dataPtr: bufPtr, n: n, addr: addr, conn: c}:
				default:
					s.bufPool.Put(bufPtr)
					dropped := s.DroppedPackets.Add(1)
					if dropped == 1 || dropped%100 == 0 {
						s.logger.Warn("dropping packet", "reason", "queue full", "dropped_total", dropped)
					}
				}
			}
		}(conn)
	}

	<-ctx.Done()
	s.logger.Info("shutting down")
	shutdown()
	s.logger.Info("server shutdown complete",
		"total_queries", s.TotalQueries.Load(),
		"dropped_packets", s.DroppedPackets.Load(),
		"handler_errors", s.HandlerErrors.Load(),
		"write_errors", s.WriteErrors.Load())
	return ctx.Err()
}

func (s *Server) worker(ctx context.Context) {
	for job := range s.jobQueue {
		resp, cleanup, err := s.resolver.Resolve(ctx, (*job.dataPtr)[:job.n])
		if err != nil {
			s.HandlerErrors.Add(1)
			s.logger.Error("handler error", "error", err)
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
		if _, writeErr := job.conn.WriteTo(resp, job.addr); writeErr != nil {
			s.WriteErrors.Add(1)
			s.logger.Error("write error", "error", writeErr)
		}
		if cleanup != nil {
			cleanup()
		}
		s.bufPool.Put(job.dataPtr)
	}
}
