package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"picodns/internal/config"
	"picodns/internal/dns"
	"picodns/internal/resolver"
)

type Server struct {
	cfg            config.Config
	logger         *slog.Logger
	resolver       resolver.Resolver
	pool           sync.Pool
	TotalQueries   atomic.Uint64
	DroppedPackets atomic.Uint64
	HandlerErrors  atomic.Uint64
	WriteErrors    atomic.Uint64
}

func New(cfg config.Config, logger *slog.Logger, res resolver.Resolver) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		logger:   logger,
		resolver: res,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, dns.MaxMessageSize)
				return &b
			},
		},
	}
}

func (s *Server) Start(ctx context.Context) error {
	if len(s.cfg.ListenAddrs) == 0 {
		return errors.New("no listen addresses configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	sema := make(chan struct{}, s.cfg.Workers)

	for _, addr := range s.cfg.ListenAddrs {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		s.logger.Info("dns server listening", "listen", addr)

		wg.Add(1)
		go func(c net.PacketConn) {
			defer wg.Done()
			defer func() { _ = c.Close() }()

			go func() {
				<-ctx.Done()
				_ = c.Close()
			}()

			for {
				bufPtr := s.pool.Get().(*[]byte)
				buf := *bufPtr
				n, addr, readErr := c.ReadFrom(buf)
				if readErr != nil {
					s.pool.Put(bufPtr)
					if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
						return
					}
					s.logger.Error("read error", "error", readErr)
					continue
				}

				s.TotalQueries.Add(1)

				select {
				case sema <- struct{}{}:
					wg.Add(1)
					go func(dataPtr *[]byte, n int, addr net.Addr, pc net.PacketConn) {
						defer wg.Done()
						defer func() {
							<-sema
							s.pool.Put(dataPtr)
						}()

						resp, err := s.resolver.Resolve(ctx, (*dataPtr)[:n])
						if err != nil {
							s.HandlerErrors.Add(1)
							s.logger.Error("handler error", "error", err)
							return
						}
						if len(resp) == 0 {
							return
						}
						if _, writeErr := pc.WriteTo(resp, addr); writeErr != nil {
							s.WriteErrors.Add(1)
							s.logger.Error("write error", "error", writeErr)
						}
					}(bufPtr, n, addr, c)
				default:
					s.pool.Put(bufPtr)
					s.DroppedPackets.Add(1)
					s.logger.Warn("dropping packet", "reason", "queue full", "dropped_total", s.DroppedPackets.Load())
				}
			}
		}(conn)
	}

	<-ctx.Done()
	s.logger.Info("shutting down")
	wg.Wait()
	s.logger.Info("server shutdown complete",
		"total_queries", s.TotalQueries.Load(),
		"dropped_packets", s.DroppedPackets.Load(),
		"handler_errors", s.HandlerErrors.Load(),
		"write_errors", s.WriteErrors.Load())
	return ctx.Err()
}
