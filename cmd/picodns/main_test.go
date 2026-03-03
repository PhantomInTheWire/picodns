package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"picodns/internal/cache"
	"picodns/internal/config"
	"picodns/internal/obs"
)

func TestParseLevel(t *testing.T) {
	require.Equal(t, slog.LevelDebug, parseLevel("DEBUG"))
	require.Equal(t, slog.LevelWarn, parseLevel(" warning "))
	require.Equal(t, slog.LevelError, parseLevel("error"))
	require.Equal(t, slog.LevelInfo, parseLevel("unknown"))
}

func TestBuildResolverRecursive(t *testing.T) {
	cfg := config.Default()
	cfg.Recursive = true
	cfg.Upstreams = nil

	runtime, err := buildResolver(cfg, slog.Default(), cache.New(cfg.CacheSize, nil), obs.NewRegistry())
	require.NoError(t, err)

	require.NotNil(t, runtime)
	require.NotNil(t, runtime.resolver)
	require.NotNil(t, runtime.warmup)
	require.NotNil(t, runtime.configureServer)
	require.NotNil(t, runtime.logShutdownStats)
}

func TestBuildResolverUpstream(t *testing.T) {
	cfg := config.Default()
	cfg.Recursive = false
	cfg.Upstreams = []string{"127.0.0.1:53"}

	runtime, err := buildResolver(cfg, slog.Default(), cache.New(cfg.CacheSize, nil), obs.NewRegistry())
	require.NoError(t, err)

	require.NotNil(t, runtime)
	require.NotNil(t, runtime.resolver)
	require.Nil(t, runtime.warmup)
	require.NotNil(t, runtime.configureServer)
	require.NotNil(t, runtime.logShutdownStats)
}
