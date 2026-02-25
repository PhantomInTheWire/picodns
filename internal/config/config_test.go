package config

import (
	"testing"

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

func TestBindFlagsDoesNotParse(t *testing.T) {
	// BindFlags should only register flags, not call flag.Parse()
	// We can verify this by checking that calling BindFlags alone
	// doesn't panic or modify the config from defaults.
	cfg := Default()
	BindFlags(&cfg)
	// Config should still have defaults since Parse wasn't called
	require.Equal(t, []string{":53"}, cfg.ListenAddrs)
	require.Equal(t, 128, cfg.Workers)
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
