//go:build perf

package obs

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"sort"
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
	// Defaults: 1/256 sampling, sample first 64 calls per tracer.
	mask := uint64(0xFF)
	warm := uint32(64)

	if v := strings.TrimSpace(os.Getenv("PICODNS_PERF_SAMPLE_RATE")); v != "" {
		// sample rate is N (sample 1/N). Must be power of two.
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

// FuncTracer tracks performance metrics for a single function.
type FuncTracer struct {
	name   string
	depth  int // depth in call stack (0 = root)
	parent *FuncTracer

	warmupRemaining atomic.Uint32

	// Metrics (all atomic)
	calls   atomic.Uint64
	sampled atomic.Uint64 // number of sampled calls
	totalNs atomic.Uint64
	maxNs   atomic.Uint64
}

// NewFuncTracer creates a new function tracer.
// parent is the immediate caller (nil for root functions).
func NewFuncTracer(name string, parent *FuncTracer) *FuncTracer {
	depth := 0
	if parent != nil {
		depth = parent.depth + 1
	}
	return &FuncTracer{
		name:   name,
		depth:  depth,
		parent: parent,
	}
}

// Name returns the tracer name.
func (t *FuncTracer) Name() string {
	return t.name
}

// ShouldSample increments the call counter and reports whether this call should
// be sampled.
func (t *FuncTracer) ShouldSample() bool {
	callN := t.calls.Add(1)
	for {
		rem := t.warmupRemaining.Load()
		if rem == 0 {
			break
		}
		if t.warmupRemaining.CompareAndSwap(rem, rem-1) {
			return true
		}
	}

	mask := samplingMask.Load()
	if mask == 0 {
		return true
	}
	return (callN & mask) == 0
}

// TraceSampled records timing only when sampled is true.
//
// This exists so callers can share a single sampling decision across nested
// measurements (e.g. a function and its internal network segments).
func (t *FuncTracer) TraceSampled(sampled bool) func() {
	if !sampled {
		return func() {}
	}

	t.sampled.Add(1)
	start := time.Now()
	return func() {
		dt := time.Since(start)
		ns := uint64(dt)
		t.totalNs.Add(ns)
		for {
			prev := t.maxNs.Load()
			if ns <= prev {
				break
			}
			if t.maxNs.CompareAndSwap(prev, ns) {
				break
			}
		}
	}
}

// TraceNested records timing only when sampled is true and increments both the
// call counter and sampled counter.
//
// This is intended for nested segments where you want consistent sampling with
// a parent function without paying per-call overhead when not sampled.
func (t *FuncTracer) TraceNested(sampled bool) func() {
	// Always count invocations, even when we don't time them.
	t.calls.Add(1)
	if !sampled {
		return func() {}
	}

	t.sampled.Add(1)
	start := time.Now()
	return func() {
		dt := time.Since(start)
		ns := uint64(dt)
		t.totalNs.Add(ns)
		for {
			prev := t.maxNs.Load()
			if ns <= prev {
				break
			}
			if t.maxNs.CompareAndSwap(prev, ns) {
				break
			}
		}
	}
}

// Trace starts tracing a function call. Returns a function to call on exit.
// Usage: defer tracer.Trace()()
// Note: This is goroutine-safe and uses 1/256 sampling.
func (t *FuncTracer) Trace() func() {
	sampled := t.ShouldSample()
	return t.TraceSampled(sampled)
}

// Snapshot returns a point-in-time snapshot of the tracer.
func (t *FuncTracer) Snapshot() TracerSnapshot {
	c := t.calls.Load()
	s := t.sampled.Load()
	total := time.Duration(t.totalNs.Load())

	var avg time.Duration
	if s > 0 {
		avg = time.Duration(uint64(total) / s)
	}

	parentName := ""
	if t.parent != nil {
		parentName = t.parent.name
	}

	return TracerSnapshot{
		Name:       t.name,
		Parent:     parentName,
		Calls:      c,
		Sampled:    s,
		Total:      total,
		Avg:        avg,
		Max:        time.Duration(t.maxNs.Load()),
		Depth:      t.depth,
		ChildNames: nil,
	}
}

// TracerSnapshot is a point-in-time snapshot of tracer metrics.
type TracerSnapshot struct {
	Name       string        `json:"name"`
	Parent     string        `json:"parent,omitempty"`
	Calls      uint64        `json:"calls"`
	Sampled    uint64        `json:"sampled"`
	Total      time.Duration `json:"total"`
	Avg        time.Duration `json:"avg"`
	Max        time.Duration `json:"max"`
	Depth      int           `json:"depth"`
	ChildNames []string      `json:"child_names,omitempty"`
}

// Registry collects all function tracers and generates reports.
type Registry struct {
	mu      sync.RWMutex
	tracers []*FuncTracer
	enabled bool
}

// GlobalRegistry is the global registry instance.
var GlobalRegistry = &Registry{
	enabled: true,
}

// Register adds a tracer to the registry.
func (r *Registry) Register(t *FuncTracer) {
	if !r.enabled {
		return
	}
	if warm := warmupSampleCalls.Load(); warm > 0 {
		t.warmupRemaining.Store(warm)
	}
	r.mu.Lock()
	r.tracers = append(r.tracers, t)
	r.mu.Unlock()
}

// Report generates and outputs a performance report.
func (r *Registry) Report(w io.Writer) {
	r.mu.RLock()
	tracers := make([]*FuncTracer, len(r.tracers))
	copy(tracers, r.tracers)
	r.mu.RUnlock()

	if len(tracers) == 0 {
		return
	}

	// Collect snapshots
	snapshots := make([]TracerSnapshot, len(tracers))
	var totalCalls, totalSampled uint64

	for i, t := range tracers {
		snap := t.Snapshot()
		snapshots[i] = snap
		totalCalls += snap.Calls
		totalSampled += snap.Sampled
	}

	// Sort by total time (descending)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Total > snapshots[j].Total
	})

	// Print header
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== Function Performance Report ===")
	wall := time.Since(registryStart)
	rate := samplingRateFromMask(samplingMask.Load())
	warm := warmupSampleCalls.Load()
	fmt.Fprintf(w, "Wall Time: %s | Sample Rate: 1/%d | Warmup Samples: %d | Total Calls: %d | Sampled Calls: %d\n",
		wall, rate, warm, totalCalls, totalSampled)
	fmt.Fprintln(w, "")

	// Print table header
	fmt.Fprintf(w, "%-45s %12s %10s %12s %12s %12s\n",
		"Function", "Calls", "Sampled", "SampledTotal", "EstTotal", "Max")
	fmt.Fprintln(w, strings.Repeat("-", 115))

	// Print rows
	for _, s := range snapshots {
		name := s.Name
		if len(name) > 43 {
			name = "..." + name[len(name)-40:]
		}

		est := estimateTotal(uint64(s.Total), s.Calls, s.Sampled)

		fmt.Fprintf(w, "%-45s %12d %10d %12s %12s %12s\n",
			name,
			s.Calls,
			s.Sampled,
			formatDuration(s.Total),
			formatDuration(time.Duration(est)),
			formatDuration(s.Max),
		)
	}

	fmt.Fprintln(w, "")
}

// ReportJSON returns the report as JSON.
func (r *Registry) ReportJSON() ([]byte, error) {
	r.mu.RLock()
	tracers := make([]*FuncTracer, len(r.tracers))
	copy(tracers, r.tracers)
	r.mu.RUnlock()

	snapshots := make([]TracerSnapshot, len(tracers))
	var totalCalls, totalSampled uint64

	for i, t := range tracers {
		snap := t.Snapshot()
		snapshots[i] = snap
		totalCalls += snap.Calls
		totalSampled += snap.Sampled
	}

	// Sort by total time
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Total > snapshots[j].Total
	})

	type tracerSnapshotJSON struct {
		Name           string   `json:"name"`
		Parent         string   `json:"parent,omitempty"`
		Calls          uint64   `json:"calls"`
		Sampled        uint64   `json:"sampled"`
		SampledTotalNs uint64   `json:"sampled_total_ns"`
		AvgNs          uint64   `json:"avg_ns"`
		MaxNs          uint64   `json:"max_ns"`
		EstTotalNs     uint64   `json:"est_total_ns"`
		Depth          int      `json:"depth"`
		Children       []string `json:"child_names,omitempty"`
	}
	funcs := make([]tracerSnapshotJSON, 0, len(snapshots))
	for _, s := range snapshots {
		est := estimateTotal(uint64(s.Total), s.Calls, s.Sampled)
		funcs = append(funcs, tracerSnapshotJSON{
			Name:           s.Name,
			Parent:         s.Parent,
			Calls:          s.Calls,
			Sampled:        s.Sampled,
			SampledTotalNs: uint64(s.Total),
			AvgNs:          uint64(s.Avg),
			MaxNs:          uint64(s.Max),
			EstTotalNs:     est,
			Depth:          s.Depth,
			Children:       s.ChildNames,
		})
	}

	report := struct {
		Msg            string               `json:"msg"`
		Version        int                  `json:"version"`
		WallTimeNs     uint64               `json:"wall_time_ns"`
		TotalRuntimeNs uint64               `json:"total_runtime_ns"`
		SampleRate     uint64               `json:"sample_rate"`
		WarmupSamples  uint32               `json:"warmup_samples"`
		TotalCalls     uint64               `json:"total_calls"`
		SampledCalls   uint64               `json:"sampled_calls"`
		Functions      []tracerSnapshotJSON `json:"functions"`
		Notes          []string             `json:"notes,omitempty"`
	}{
		Msg:            "function performance report",
		Version:        2,
		WallTimeNs:     uint64(time.Since(registryStart)),
		TotalRuntimeNs: uint64(time.Since(registryStart)),
		SampleRate:     samplingRateFromMask(samplingMask.Load()),
		WarmupSamples:  warmupSampleCalls.Load(),
		TotalCalls:     totalCalls,
		SampledCalls:   totalSampled,
		Functions:      funcs,
		Notes: []string{
			"sampled_total_ns/avg_ns/max_ns are measured on sampled calls only",
			"est_total_ns extrapolates sampled_total_ns to all calls (calls/sample); best-effort",
			"do not sum times across different functions; instrumentation trees can overlap",
		},
	}

	return json.Marshal(report)
}

// Enabled returns true if performance tracing is enabled.
func Enabled() bool {
	return true
}

func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	} else if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1000)
	} else if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func samplingRateFromMask(mask uint64) uint64 {
	// mask = rate-1 for a power-of-two rate.
	if mask == 0 {
		return 1
	}
	// mask is 2^k - 1
	return 1 << uint(bits.Len64(mask+1)-1)
}

func estimateTotal(sampledTotalNs uint64, calls, sampled uint64) uint64 {
	if sampled == 0 || calls == 0 || sampledTotalNs == 0 {
		return 0
	}
	// Use float math to avoid 128-bit division corner cases.
	// This is a best-effort estimate for reporting only.
	est := (float64(sampledTotalNs) * float64(calls)) / float64(sampled)
	if est <= 0 {
		return 0
	}
	if est > float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(math.Round(est))
}
