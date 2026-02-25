package config

import (
	"flag"
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

// flagBindings holds the intermediate string values that bridge flag registration
// and post-parse processing.
type flagBindings struct {
	listen        string
	upstreams     string
	statsInterval string
}

var bindings flagBindings

// BindFlags registers command-line flags on the default flag set,
// binding them to the fields of cfg. Call ParseFlags after to parse os.Args.
func BindFlags(cfg *Config) {
	if cfg == nil {
		return
	}

	flag.StringVar(&bindings.listen, "listen", strings.Join(cfg.ListenAddrs, ","), "comma-separated listen addresses")
	flag.StringVar(&bindings.upstreams, "upstreams", strings.Join(cfg.Upstreams, ","), "comma-separated upstreams")
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "worker pool size")
	flag.IntVar(&cfg.CacheSize, "cache-size", cfg.CacheSize, "max cache entries")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (debug, info, warn, error)")
	flag.BoolVar(&cfg.Recursive, "recursive", cfg.Recursive, "use recursive resolution instead of forwarding to upstreams")
	flag.BoolVar(&cfg.Prewarm, "prewarm", cfg.Prewarm, "pre-warm recursive resolver cache on startup")
	flag.BoolVar(&cfg.Prefetch, "prefetch", cfg.Prefetch, "proactively refresh hot cache entries")
	flag.BoolVar(&cfg.Stats, "stats", cfg.Stats, "emit one-time stats summary on shutdown")
	flag.StringVar(&cfg.PerfReport, "perf-report", cfg.PerfReport, "write perf JSON report to this path (perf builds only)")
	flag.StringVar(&bindings.statsInterval, "stats-interval", cfg.StatsInterval.String(), "DEPRECATED: enables -stats when >0")
}

// ParseFlags calls flag.Parse and applies post-processing to cfg.
// Must be called after BindFlags.
func ParseFlags(cfg *Config) {
	flag.Parse()

	if bindings.listen != "" {
		cfg.ListenAddrs = splitComma(bindings.listen)
	}
	if bindings.upstreams != "" {
		cfg.Upstreams = splitComma(bindings.upstreams)
	}
	if strings.TrimSpace(bindings.statsInterval) != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(bindings.statsInterval)); err == nil {
			cfg.StatsInterval = d
			if d > 0 {
				cfg.Stats = true
			}
		}
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
