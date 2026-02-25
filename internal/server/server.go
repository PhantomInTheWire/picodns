package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/config"
	"picodns/internal/pool"
	"picodns/internal/types"
)

const (
	tcpReadTimeout  = 5 * time.Second // Max time to read a complete DNS message
	tcpWriteTimeout = 5 * time.Second // Max time to write a complete DNS response
	maxTCPConns     = 256             // Maximum concurrent TCP connections
)

type Server struct {
	cfg              config.Config
	logger           *slog.Logger
	resolver         types.Resolver
	bufPool          *pool.Bytes
	jobQueue         chan queryJob
	TotalQueries     atomic.Uint64
	DroppedPackets   atomic.Uint64
	DroppedResponses atomic.Uint64
	HandlerErrors    atomic.Uint64
	WriteErrors      atomic.Uint64
	tcpSem           chan struct{}
	logServfail      bool

	cacheCounters func() (hits uint64, miss uint64)
}

func New(cfg config.Config, logger *slog.Logger, res types.Resolver) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		cfg:      cfg,
		logger:   logger,
		resolver: res,
		bufPool:  pool.DefaultPool,
		jobQueue: make(chan queryJob, cfg.Workers),
		tcpSem:   make(chan struct{}, maxTCPConns),
	}
	// Cache this once; slog's Enabled check is not free at very high QPS.
	s.logServfail = logger.Enabled(context.Background(), slog.LevelDebug)
	return s
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
	udpWriters := make([]*udpWriter, 0, len(s.cfg.ListenAddrs))
	startTime := time.Now()
	obsEnabled := s.cfg.Stats

	shutdown := func() {
		cancel()
		readersWg.Wait()
		close(s.jobQueue)
		workersWg.Wait()
		for _, w := range udpWriters {
			if w != nil {
				close(w.ch)
				close(w.slowCh)
			}
		}
		writersWg.Wait()
	}

	s.startWorkers(ctx, &workersWg)

	if err := s.startListeners(ctx, &readersWg, &writersWg, &udpWriters); err != nil {
		shutdown()
		return err
	}

	<-ctx.Done()
	s.logger.Info("shutting down")
	shutdown()
	s.logShutdown(startTime, obsEnabled)
	return ctx.Err()
}
