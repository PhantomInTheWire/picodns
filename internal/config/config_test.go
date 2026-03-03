package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	require.Equal(t, []string{":53"}, cfg.ListenAddrs)
	require.Equal(t, []string{"1.1.1.1:53"}, cfg.Upstreams)
	require.Equal(t, 128, cfg.Workers)
	require.Equal(t, 10000, cfg.CacheSize)
	require.Equal(t, "info", cfg.LogLevel)
	require.True(t, cfg.Prewarm)
	require.True(t, cfg.Prefetch)
	require.False(t, cfg.Stats)
}

func TestParseArgsUsesIsolatedFlagSet(t *testing.T) {
	first, err := ParseArgs([]string{"-listen", ":5300", "-upstreams", "8.8.8.8:53,1.1.1.1:53", "-stats-interval", "5s"})
	require.NoError(t, err)
	require.Equal(t, []string{":5300"}, first.ListenAddrs)
	require.Equal(t, []string{"8.8.8.8:53", "1.1.1.1:53"}, first.Upstreams)
	require.True(t, first.Stats)
	require.Equal(t, 5*time.Second, first.StatsInterval)

	second, err := ParseArgs([]string{"-listen", ":5400"})
	require.NoError(t, err)
	require.Equal(t, []string{":5400"}, second.ListenAddrs)
	require.Equal(t, Default().Upstreams, second.Upstreams)
}

func TestParseArgsRejectsInvalidStatsInterval(t *testing.T) {
	_, err := ParseArgs([]string{"-stats-interval", "not-a-duration"})
	require.Error(t, err)
}

func TestSplitComma(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{"", []string{}},
		{"single", []string{"single"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, tt := range tests {
		got := splitComma(tt.input)
		require.Equal(t, tt.want, got, "splitComma(%q)", tt.input)
	}
}
