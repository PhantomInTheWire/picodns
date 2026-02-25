package resolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRTTTrackerUpdateAndGet(t *testing.T) {
	tracker := newRTTTracker(nil)
	ctx := context.Background()

	// Unknown server returns unknownRTT
	rtt, ok := tracker.Get(ctx, "1.2.3.4:53")
	require.False(t, ok)
	require.Equal(t, unknownRTT, rtt)

	// Update with a measurement
	tracker.Update(ctx, "1.2.3.4:53", 100*time.Millisecond)
	rtt, ok = tracker.Get(ctx, "1.2.3.4:53")
	require.True(t, ok)
	require.Equal(t, 100*time.Millisecond, rtt)

	// EWMA: (100*4 + 200) / 5 = 120ms
	tracker.Update(ctx, "1.2.3.4:53", 200*time.Millisecond)
	rtt, ok = tracker.Get(ctx, "1.2.3.4:53")
	require.True(t, ok)
	require.Equal(t, 120*time.Millisecond, rtt)
}

func TestRTTTrackerFailureAndCooldown(t *testing.T) {
	tracker := newRTTTracker(nil)
	ctx := context.Background()

	tracker.Failure(ctx, "bad.server:53")

	// Server should be on cooldown
	tracker.mu.Lock()
	_, hasCooldown := tracker.cooldown["bad.server:53"]
	count := tracker.timeouts["bad.server:53"]
	tracker.mu.Unlock()
	require.True(t, hasCooldown)
	require.Equal(t, uint32(1), count)

	// After successful Update, cooldown and timeout should be cleared
	tracker.Update(ctx, "bad.server:53", 50*time.Millisecond)
	tracker.mu.Lock()
	_, hasCooldown = tracker.cooldown["bad.server:53"]
	_, hasTimeout := tracker.timeouts["bad.server:53"]
	tracker.mu.Unlock()
	require.False(t, hasCooldown)
	require.False(t, hasTimeout)
}

func TestRTTTrackerSortBest(t *testing.T) {
	tracker := newRTTTracker(nil)
	ctx := context.Background()

	tracker.Update(ctx, "slow:53", 500*time.Millisecond)
	tracker.Update(ctx, "fast:53", 10*time.Millisecond)
	tracker.Update(ctx, "medium:53", 100*time.Millisecond)

	sorted := tracker.SortBest(ctx, []string{"slow:53", "fast:53", "medium:53"}, 3)
	require.Equal(t, []string{"fast:53", "medium:53", "slow:53"}, sorted)

	// With n=1, should return only the fastest
	top := tracker.SortBest(ctx, []string{"slow:53", "fast:53", "medium:53"}, 1)
	require.Equal(t, []string{"fast:53"}, top)
}

func TestRTTTrackerSortBestSkipsCooldown(t *testing.T) {
	tracker := newRTTTracker(nil)
	ctx := context.Background()

	tracker.Update(ctx, "good:53", 100*time.Millisecond)
	tracker.Failure(ctx, "bad:53")

	// bad:53 should be skipped because it's on cooldown
	sorted := tracker.SortBest(ctx, []string{"bad:53", "good:53"}, 2)
	require.Equal(t, []string{"good:53"}, sorted)
}

func TestRTTTrackerEviction(t *testing.T) {
	tracker := newRTTTracker(nil)
	ctx := context.Background()

	// Fill beyond maxRTTTrackerEntries
	for i := 0; i < maxRTTTrackerEntries+10; i++ {
		tracker.Update(ctx, fmt.Sprintf("server%d:53", i), time.Duration(i)*time.Millisecond)
	}

	// Should have evicted some entries
	tracker.mu.Lock()
	count := len(tracker.rtts)
	tracker.mu.Unlock()
	require.LessOrEqual(t, count, maxRTTTrackerEntries+1)
}
