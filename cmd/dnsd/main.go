package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"picodns/internal/config"
	"picodns/internal/logging"
	"picodns/internal/resolver"
	"picodns/internal/server"
)

func main() {
	cfg := config.Default()
	config.BindFlags(&cfg)

	logger := logging.New(cfg.LogLevel)
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	upstream := resolver.NewUpstream(cfg.Upstreams)
	resolverHandler := server.NewDNSHandler(upstream)

	srv := server.New(cfg, logger, resolverHandler)
	if err := srv.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}
