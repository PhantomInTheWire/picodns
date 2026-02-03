package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"picodns/internal/cache"
	"picodns/internal/config"
	"picodns/internal/resolver"
	"picodns/internal/server"
)

func main() {
	cfg := config.Default()
	config.BindFlags(&cfg)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	upstream := resolver.NewUpstream(cfg.Upstreams, cfg.Timeout)
	cacheStore := cache.New(cfg.CacheSize, nil)
	res := resolver.NewCached(cacheStore, upstream)

	srv := server.New(cfg, logger, res)
	if err := srv.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
