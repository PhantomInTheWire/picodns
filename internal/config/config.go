package config

import (
	"flag"
	"strings"
)

type Config struct {
	ListenAddrs []string
	Upstreams   []string
	Workers     int
	CacheSize   int
	LogLevel    string
	Recursive   bool
	Prewarm     bool
	Prefetch    bool
}

func Default() Config {
	return Config{
		ListenAddrs: []string{":53"},
		Upstreams:   []string{"1.1.1.1:53"},
		Workers:     128,
		CacheSize:   10000,
		LogLevel:    "info",
		Prewarm:     true,
		Prefetch:    true,
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
	flag.IntVar(&cfg.CacheSize, "cache-size", cfg.CacheSize, "max cache entries")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")
	flag.BoolVar(&cfg.Recursive, "recursive", cfg.Recursive, "use recursive resolution instead of forwarding to upstreams")
	flag.BoolVar(&cfg.Prewarm, "prewarm", cfg.Prewarm, "pre-warm recursive resolver cache on startup")
	flag.BoolVar(&cfg.Prefetch, "prefetch", cfg.Prefetch, "proactively refresh hot cache entries")

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
