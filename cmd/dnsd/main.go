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
	"picodns/internal/types"
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

	cacheStore := cache.New(cfg.CacheSize, nil)

	var res types.Resolver
	if cfg.Recursive || len(cfg.Upstreams) == 0 {
		logger.Info("using recursive resolver")
		res = resolver.NewCached(cacheStore, resolver.NewRecursive())
	} else {
		logger.Info("using upstream resolver", "upstreams", cfg.Upstreams)
		upstream, err := resolver.NewUpstream(cfg.Upstreams)
		if err != nil {
			logger.Error("failed to create upstream resolver", "error", err)
			os.Exit(1)
		}
		res = resolver.NewCached(cacheStore, upstream)
	}

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
