package testutil

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/config"
	"picodns/internal/resolver"
	"picodns/internal/server"
)

// ServerOption configures the test server
type ServerOption func(*serverOptions)

type serverOptions struct {
	workers      int
	cacheSize    int
	startupDelay time.Duration
	listenAddr   string
}

// WithWorkers sets the number of workers for the server
func WithWorkers(n int) ServerOption {
	return func(o *serverOptions) {
		o.workers = n
	}
}

// WithCacheSize sets the cache size for the server
func WithCacheSize(size int) ServerOption {
	return func(o *serverOptions) {
		o.cacheSize = size
	}
}

// WithStartupDelay sets the delay after starting the server before returning
func WithStartupDelay(d time.Duration) ServerOption {
	return func(o *serverOptions) {
		o.startupDelay = d
	}
}

// WithListenAddr sets a specific listen address (useful for port 0 to get random port)
func WithListenAddr(addr string) ServerOption {
	return func(o *serverOptions) {
		o.listenAddr = addr
	}
}

// StartTestServer starts a picodns server with the given resolver and options
// Returns the server address and a cleanup function
func StartTestServer(t *testing.T, res resolver.Resolver, opts ...ServerOption) (string, func()) {
	options := &serverOptions{
		workers:      4,
		cacheSize:    100,
		startupDelay: 100 * time.Millisecond,
	}

	for _, opt := range opts {
		opt(options)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.Default()
	cfg.Workers = options.workers
	cfg.CacheSize = options.cacheSize

	addr := options.listenAddr
	if addr == "" {
		listen, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		addr = listen.LocalAddr().String()
		_ = listen.Close()
	}

	cfg.ListenAddrs = []string{addr}

	srv := server.New(cfg, logger, res)
	ctx, cancel := context.WithCancel(context.Background())
	var srvWg sync.WaitGroup
	startErr := make(chan error, 1)
	srvWg.Add(1)
	go func() {
		defer srvWg.Done()
		if err := srv.Start(ctx); err != nil && err != context.Canceled {
			startErr <- err
		}
	}()

	time.Sleep(options.startupDelay)

	select {
	case err := <-startErr:
		cancel()
		srvWg.Wait()
		t.Fatalf("server failed to start: %v", err)
	default:
	}

	return addr, func() {
		cancel()
		srvWg.Wait()
	}
}

// StartServerWithResolver starts a picodns server with the given resolver and 200ms startup delay
// This is a convenience wrapper for tests that need a longer startup delay
func StartServerWithResolver(t *testing.T, res resolver.Resolver) (string, func()) {
	return StartTestServer(t, res, WithStartupDelay(200*time.Millisecond))
}
