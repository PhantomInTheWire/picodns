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
	var cached *resolver.Cached
	var rec *resolver.Recursive
	var upstream *resolver.Upstream
	if cfg.Recursive || len(cfg.Upstreams) == 0 {
		logger.Info("using recursive resolver")
		rec = resolver.NewRecursive()
		rec.SetObsEnabled(cfg.Stats)
		cached = resolver.NewCached(cacheStore, rec)
		cached.Prefetch = cfg.Prefetch
		cached.ObsEnabled = cfg.Stats
		res = cached

		if cfg.Prewarm {
			logger.Info("starting recursive resolver pre-warm")
			go rec.Warmup(ctx)
		}
	} else {
		logger.Info("using upstream resolver", "upstreams", cfg.Upstreams)
		var err error
		upstream, err = resolver.NewUpstream(cfg.Upstreams)
		if err != nil {
			logger.Error("failed to create upstream resolver", "error", err)
			os.Exit(1)
		}
		upstream.SetObsEnabled(cfg.Stats)
		cached = resolver.NewCached(cacheStore, upstream)
		cached.Prefetch = cfg.Prefetch
		cached.ObsEnabled = cfg.Stats
		res = cached
	}

	srv := server.New(cfg, logger, res)
	if cached != nil && cfg.Stats {
		srv.SetCacheCounters(func() (uint64, uint64) {
			return cached.CacheHits.Load(), cached.CacheMiss.Load()
		})
	}

	err := srv.Start(ctx)
	if cfg.Stats {
		if rec != nil {
			logger.Info("recursive internal cache stats",
				"ns_cache", rec.NSCacheStatsSnapshot(),
				"delegation_cache", rec.DelegationCacheStatsSnapshot(),
			)
			addr := rec.TransportAddrCacheStatsSnapshot()
			addrHitRate := 0.0
			if addr.Gets > 0 {
				addrHitRate = float64(addr.Hits) / float64(addr.Gets)
			}
			logger.Info("transport addr cache stats",
				"gets", addr.Gets,
				"hits", addr.Hits,
				"misses", addr.Misses,
				"sets", addr.Sets,
				"deletes", addr.Deletes,
				"len", addr.Len,
				"hit_rate", addrHitRate,
			)
		}
		if upstream != nil {
			addr := upstream.TransportAddrCacheStatsSnapshot()
			addrHitRate := 0.0
			if addr.Gets > 0 {
				addrHitRate = float64(addr.Hits) / float64(addr.Gets)
			}
			logger.Info("transport addr cache stats",
				"gets", addr.Gets,
				"hits", addr.Hits,
				"misses", addr.Misses,
				"sets", addr.Sets,
				"deletes", addr.Deletes,
				"len", addr.Len,
				"hit_rate", addrHitRate,
			)
		}

		if cached != nil {
			snap := cached.StatsSnapshot()
			hitRate := 0.0
			if snap.Hits+snap.Miss > 0 {
				hitRate = float64(snap.Hits) / float64(snap.Hits+snap.Miss)
			}

			logger.Info("resolver cache stats",
				"cache_hits", snap.Hits,
				"cache_miss", snap.Miss,
				"cache_hit_rate", hitRate,
			)
		}
	}

	if err != nil && !errors.Is(err, context.Canceled) {
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
