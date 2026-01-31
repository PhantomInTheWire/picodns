package server

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"picodns/internal/config"
)

type Server struct {
	cfg     config.Config
	logger  *slog.Logger
	handler Handler
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
	conn, err := net.ListenPacket("udp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s.logger.Info("dns server listening", "listen", s.cfg.ListenAddr)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	packetCh := make(chan packet, s.cfg.Workers*2)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go s.runWorker(ctx, conn, packetCh, &wg)
	}

	pool := sync.Pool{New: func() any {
		return make([]byte, maxPacketSize)
	}}

	for {
		buf := pool.Get().([]byte)
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			pool.Put(buf)
			if ctx.Err() != nil {
				close(packetCh)
				wg.Wait()
				return ctx.Err()
			}
			s.logger.Error("read error", "error", readErr)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		pool.Put(buf)

		select {
		case packetCh <- packet{data: data, addr: addr}:
		default:
			s.logger.Warn("dropping packet", "reason", "queue full")
		}
	}
}

type packet struct {
	data []byte
	addr net.Addr
}

func (s *Server) runWorker(ctx context.Context, conn net.PacketConn, packets <-chan packet, wg *sync.WaitGroup) {
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
			s.logger.Error("handler error", "error", err)
			continue
		}
		if len(resp) == 0 {
			continue
		}
		if _, writeErr := conn.WriteTo(resp, pkt.addr); writeErr != nil {
			s.logger.Error("write error", "error", writeErr)
		}
	}
}
