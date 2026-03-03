package config

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ListenAddrs   []string
	Upstreams     []string
	Workers       int
	CacheSize     int
	LogLevel      string
	Recursive     bool
	Prewarm       bool
	Prefetch      bool
	Stats         bool
	StatsInterval time.Duration
	PerfReport    string
}

func Default() Config {
	return Config{
		ListenAddrs: []string{":53"},
		Upstreams:   []string{"1.1.1.1:53"},
		Workers:     128,

		CacheSize:     10000,
		LogLevel:      "info",
		Prewarm:       true,
		Prefetch:      true,
		Stats:         false,
		StatsInterval: 0,
		// Default to a repo-visible path when running locally.
		PerfReport: filepath.Join("perf", "picodns-perf.json"),
	}
}

type flagBindings struct {
	listen        string
	upstreams     string
	statsInterval string
}

func bindFlags(fs *flag.FlagSet, cfg *Config, fb *flagBindings) {
	if fs == nil || cfg == nil || fb == nil {
		return
	}

	fs.StringVar(&fb.listen, "listen", strings.Join(cfg.ListenAddrs, ","), "comma-separated listen addresses")
	fs.StringVar(&fb.upstreams, "upstreams", strings.Join(cfg.Upstreams, ","), "comma-separated upstreams")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "worker pool size")
	fs.IntVar(&cfg.CacheSize, "cache-size", cfg.CacheSize, "max cache entries")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")
	fs.BoolVar(&cfg.Recursive, "recursive", cfg.Recursive, "use recursive resolution instead of forwarding to upstreams")
	fs.BoolVar(&cfg.Prewarm, "prewarm", cfg.Prewarm, "pre-warm recursive resolver cache on startup")
	fs.BoolVar(&cfg.Prefetch, "prefetch", cfg.Prefetch, "proactively refresh hot cache entries")
	fs.BoolVar(&cfg.Stats, "stats", cfg.Stats, "emit one-time stats summary on shutdown")
	fs.StringVar(&cfg.PerfReport, "perf-report", cfg.PerfReport, "write perf JSON report to this path (perf builds only)")
	fs.StringVar(&fb.statsInterval, "stats-interval", cfg.StatsInterval.String(), "DEPRECATED: enables -stats when >0")
}

func applyBindings(cfg *Config, fb flagBindings) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if fb.listen != "" {
		cfg.ListenAddrs = splitComma(fb.listen)
	}
	if fb.upstreams != "" {
		cfg.Upstreams = splitComma(fb.upstreams)
	}
	if strings.TrimSpace(fb.statsInterval) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(fb.statsInterval))
		if err != nil {
			return fmt.Errorf("parse stats-interval: %w", err)
		}
		cfg.StatsInterval = d
		if d > 0 {
			cfg.Stats = true
		}
	}
	return nil
}

func ParseArgs(args []string) (Config, error) {
	cfg := Default()
	fs := flag.NewFlagSet("picodns", flag.ContinueOnError)
	var fb flagBindings
	bindFlags(fs, &cfg, &fb)
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if err := applyBindings(&cfg, fb); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
