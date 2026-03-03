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
	"picodns/internal/obs"
	"picodns/internal/resolver"
	"picodns/internal/server"
	"picodns/internal/types"
)

type resolverRuntime struct {
	resolver         types.Resolver
	warmup           func(context.Context)
	configureServer  func(*server.Server, config.Config)
	logShutdownStats func(*slog.Logger)
}

func main() {
	cfg, err := config.ParseArgs(os.Args[1:])
	if err != nil {
		slog.Error("failed to parse config", "error", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cacheStore := cache.New(cfg.CacheSize, nil)
	perfRegistry := obs.NewRegistry()

	runtime, err := buildResolver(cfg, logger, cacheStore, perfRegistry)
	if err != nil {
		logger.Error("failed to build resolver", "error", err)
		os.Exit(1)
	}
	if cfg.Prewarm && runtime.warmup != nil {
		logger.Info("starting recursive resolver pre-warm")
		go runtime.warmup(ctx)
	}

	srv := server.New(cfg, logger, runtime.resolver, perfRegistry)
	if runtime.configureServer != nil {
		runtime.configureServer(srv, cfg)
	}

	err = srv.Start(ctx)
	if cfg.Stats && runtime.logShutdownStats != nil {
		runtime.logShutdownStats(logger)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func buildResolver(cfg config.Config, logger *slog.Logger, cacheStore *cache.Cache, perfRegistry *obs.Registry) (*resolverRuntime, error) {
	if cfg.Recursive || len(cfg.Upstreams) == 0 {
		logger.Info("using recursive resolver")
		rec := resolver.NewRecursive(perfRegistry)
		rec.SetObsEnabled(cfg.Stats)
		cached := resolver.NewCached(cacheStore, rec, perfRegistry)
		cached.Prefetch = cfg.Prefetch
		cached.ObsEnabled = cfg.Stats
		return &resolverRuntime{
			resolver: cached,
			warmup:   rec.Warmup,
			configureServer: func(srv *server.Server, cfg config.Config) {
				if cfg.Stats {
					srv.SetCacheCounters(func() (uint64, uint64) {
						return cached.CacheHits.Load(), cached.CacheMiss.Load()
					})
				}
			},
			logShutdownStats: func(logger *slog.Logger) {
				printRecursiveStats(logger, rec)
				printCachedStats(logger, cached)
			},
		}, nil
	}

	logger.Info("using upstream resolver", "upstreams", cfg.Upstreams)
	upstream, err := resolver.NewUpstream(cfg.Upstreams, perfRegistry)
	if err != nil {
		return nil, err
	}
	upstream.SetObsEnabled(cfg.Stats)
	cached := resolver.NewCached(cacheStore, upstream, perfRegistry)
	cached.Prefetch = cfg.Prefetch
	cached.ObsEnabled = cfg.Stats
	return &resolverRuntime{
		resolver: cached,
		configureServer: func(srv *server.Server, cfg config.Config) {
			if cfg.Stats {
				srv.SetCacheCounters(func() (uint64, uint64) {
					return cached.CacheHits.Load(), cached.CacheMiss.Load()
				})
			}
		},
		logShutdownStats: func(logger *slog.Logger) {
			printTransportStats(logger, upstream.TransportAddrCacheStatsSnapshot())
			printCachedStats(logger, cached)
		},
	}, nil
}

func printRecursiveStats(logger *slog.Logger, rec *resolver.Recursive) {
	logger.Info("recursive internal cache stats",
		"ns_cache", rec.NSCacheStatsSnapshot(),
		"delegation_cache", rec.DelegationCacheStatsSnapshot(),
	)
	printTransportStats(logger, rec.TransportAddrCacheStatsSnapshot())
}

func printTransportStats(logger *slog.Logger, addr cache.TTLStatsSnapshot) {
	addrHitRate := 0.0
	if addr.Gets > 0 {
		addrHitRate = float64(addr.Hits) / float64(addr.Gets)
	}
	logger.Info("transport addr cache stats",
		"gets", addr.Gets, "hits", addr.Hits, "misses", addr.Misses,
		"sets", addr.Sets, "deletes", addr.Deletes, "len", addr.Len,
		"hit_rate", addrHitRate,
	)
}

func printCachedStats(logger *slog.Logger, cached *resolver.Cached) {
	snap := cached.StatsSnapshot()
	hitRate := 0.0
	if snap.Hits+snap.Miss > 0 {
		hitRate = float64(snap.Hits) / float64(snap.Hits+snap.Miss)
	}
	logger.Info("resolver cache stats",
		"cache_hits", snap.Hits, "cache_miss", snap.Miss,
		"cache_hit_rate", hitRate,
	)
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
