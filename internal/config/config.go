package config

import (
	"flag"
	"strings"
	"time"
)

type Config struct {
	ListenAddrs []string
	Upstreams   []string
	Workers     int
	QueueSize   int
	Timeout     time.Duration
	CacheSize   int
	LogLevel    string
	Recursive   bool
}

func Default() Config {
	return Config{
		ListenAddrs: []string{":53"},
		Upstreams:   []string{"1.1.1.1:53"},
		Workers:     128,
		QueueSize:   256,
		Timeout:     5 * time.Second,
		CacheSize:   10000,
		LogLevel:    "info",
	}
}

func BindFlags(cfg *Config) {
	if cfg == nil {
		return
	}

	var upstreams string
	var listen string
	flag.StringVar(&listen, "listen", strings.Join(cfg.ListenAddrs, ","), "comma-separated listen addresses")
	flag.StringVar(&upstreams, "upstreams", strings.Join(cfg.Upstreams, ","), "comma-separated upstreams")
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "worker pool size")
	flag.IntVar(&cfg.QueueSize, "queue-size", cfg.QueueSize, "worker pool queue size")
	flag.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "upstream timeout")
	flag.IntVar(&cfg.CacheSize, "cache-size", cfg.CacheSize, "max cache entries")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")
	flag.BoolVar(&cfg.Recursive, "recursive", cfg.Recursive, "use recursive resolution instead of forwarding to upstreams")

	flag.Parse()

	if listen != "" {
		cfg.ListenAddrs = splitComma(listen)
	}
	if upstreams != "" {
		cfg.Upstreams = splitComma(upstreams)
	}
}

func splitComma(value string) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}
