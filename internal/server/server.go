package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"picodns/internal/config"
)

type Server struct {
	cfg            config.Config
	logger         *slog.Logger
	handler        Handler
	totalQueries   atomic.Uint64
	droppedPackets atomic.Uint64
	handlerErrors  atomic.Uint64
	writeErrors    atomic.Uint64
}

const maxPacketSize = 4096

func New(cfg config.Config, logger *slog.Logger, handler Handler) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if handler == nil {
		handler = NoopHandler{}
	}
	return &Server{cfg: cfg, logger: logger, handler: handler}
}

func (s *Server) Start(ctx context.Context) error {
	if len(s.cfg.ListenAddrs) == 0 {
		return errors.New("no listen addresses configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	packetCh := make(chan packet, s.cfg.QueueSize)
	var wg sync.WaitGroup

	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go s.runWorker(ctx, packetCh, &wg)
	}

	pool := sync.Pool{New: func() any {
		return make([]byte, maxPacketSize)
	}}

	errCh := make(chan error, len(s.cfg.ListenAddrs))
	for _, addr := range s.cfg.ListenAddrs {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		s.logger.Info("dns server listening", "listen", addr)

		wg.Add(1)
		go func(c net.PacketConn) {
			defer wg.Done()
			defer c.Close()

			go func() {
				<-ctx.Done()
				_ = c.Close()
			}()

			for {
				buf := pool.Get().([]byte)
				n, addr, readErr := c.ReadFrom(buf)
				if readErr != nil {
					pool.Put(buf)
					if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
						return
					}
					s.logger.Error("read error", "error", readErr)
					continue
				}

				data := make([]byte, n)
				copy(data, buf[:n])
				pool.Put(buf)

				s.totalQueries.Add(1)
				select {
				case packetCh <- packet{data: data, addr: addr, conn: c}:
				default:
					s.droppedPackets.Add(1)
					s.logger.Warn("dropping packet", "reason", "queue full", "dropped_total", s.droppedPackets.Load())
				}
			}
		}(conn)
	}

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down")
		close(packetCh)
		wg.Wait()
		s.logger.Info("server shutdown complete",
			"total_queries", s.totalQueries.Load(),
			"dropped_packets", s.droppedPackets.Load(),
			"handler_errors", s.handlerErrors.Load(),
			"write_errors", s.writeErrors.Load())
		return ctx.Err()
	case err := <-errCh:
		s.logger.Error("critical error, shutting down", "error", err)
		cancel()
		close(packetCh)
		wg.Wait()
		return err
	}
}

type packet struct {
	data []byte
	addr net.Addr
	conn net.PacketConn
}

func (s *Server) DroppedPackets() uint64 {
	return s.droppedPackets.Load()
}

func (s *Server) runWorker(ctx context.Context, packets <-chan packet, wg *sync.WaitGroup) {
	defer wg.Done()

	for pkt := range packets {
		reqCtx := ctx
		var cancel context.CancelFunc
		if s.cfg.Timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		}

		resp, err := s.handler.HandlePacket(reqCtx, pkt.data, pkt.addr)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			s.handlerErrors.Add(1)
			s.logger.Error("handler error", "error", err)
			continue
		}
		if len(resp) == 0 {
			continue
		}
		if _, writeErr := pkt.conn.WriteTo(resp, pkt.addr); writeErr != nil {
			s.writeErrors.Add(1)
			s.logger.Error("write error", "error", writeErr)
		}
	}
}
