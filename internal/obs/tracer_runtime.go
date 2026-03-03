//go:build perf

package obs

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// samplingMask implements power-of-two sampling: sample when (calls & mask) == 0.
	// mask=0 samples every call. Default is 1/256 (mask=255).
	samplingMask atomic.Uint64

	// warmupSampleCalls samples the first N calls of each tracer.
	// This improves coverage for low-frequency functions.
	warmupSampleCalls atomic.Uint32

	registryStart = time.Now()
)

func init() {
	mask := uint64(0xFF)
	warm := uint32(64)

	if v := strings.TrimSpace(os.Getenv("PICODNS_PERF_SAMPLE_RATE")); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			if n <= 1 {
				mask = 0
			} else if (n & (n - 1)) == 0 {
				mask = n - 1
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("PICODNS_PERF_WARMUP_SAMPLES")); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			warm = uint32(n)
		}
	}

	samplingMask.Store(mask)
	warmupSampleCalls.Store(warm)
}

// Registry collects all function tracers and generates reports.
type Registry struct {
	mu      sync.RWMutex
	tracers []*FuncTracer
	enabled bool
}

func NewRegistry() *Registry {
	return &Registry{enabled: true}
}

// GlobalRegistry is the global registry instance.
var GlobalRegistry = NewRegistry()

// Register adds a tracer to the registry.
func (r *Registry) Register(t *FuncTracer) {
	if r == nil || !r.enabled || t == nil {
		return
	}
	if warm := warmupSampleCalls.Load(); warm > 0 {
		t.warmupRemaining.Store(warm)
	}
	r.mu.Lock()
	r.tracers = append(r.tracers, t)
	r.mu.Unlock()
}

func (r *Registry) RegisterAll(tracers ...*FuncTracer) {
	for _, tracer := range tracers {
		r.Register(tracer)
	}
}

func (r *Registry) snapshotTracers() []*FuncTracer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tracers := make([]*FuncTracer, len(r.tracers))
	copy(tracers, r.tracers)
	return tracers
}

// Enabled returns true if performance tracing is enabled.
func Enabled() bool {
	return true
}
