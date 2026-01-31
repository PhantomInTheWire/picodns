package server

import (
	"context"
	"log/slog"

	"picodns/internal/config"
)

type Server struct {
	cfg    config.Config
	logger *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger}
}

func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("dns server scaffold", "listen", s.cfg.ListenAddr)
	<-ctx.Done()
	return ctx.Err()
}
