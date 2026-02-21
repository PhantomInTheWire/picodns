//go:build perf

package obs

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// sampleMask for 1/256 sampling
const sampleMask = 0xFF

// FuncTracer tracks performance metrics for a single function.
type FuncTracer struct {
	name   string
	parent *FuncTracer // immediate caller (for call graph)
	depth  int         // depth in call stack (0 = root)

	// Metrics (all atomic)
	calls   atomic.Uint64
	sampled atomic.Uint64 // number of sampled calls
	totalNs atomic.Uint64
	maxNs   atomic.Uint64

	// Children (functions called by this one)
	childrenMu sync.RWMutex
	children   map[string]*FuncTracer
}

// NewFuncTracer creates a new function tracer.
// parent is the immediate caller (nil for root functions).
func NewFuncTracer(name string, parent *FuncTracer) *FuncTracer {
	depth := 0
	if parent != nil {
		depth = parent.depth + 1
	}
	return &FuncTracer{
		name:     name,
		parent:   parent,
		depth:    depth,
		children: make(map[string]*FuncTracer),
	}
}

// Name returns the tracer name.
func (t *FuncTracer) Name() string {
	return t.name
}

// Trace starts tracing a function call. Returns a function to call on exit.
// Usage: defer tracer.Trace()()
// Note: This is goroutine-safe and uses 1/256 sampling.
func (t *FuncTracer) Trace() func() {
	// Sample at 1/256
	if t.calls.Add(1)&sampleMask != 0 {
		return func() {}
	}

	t.sampled.Add(1)
	start := time.Now()

	return func() {
		dt := time.Since(start)
		ns := uint64(dt)
		t.totalNs.Add(ns)

		// Update max with CAS loop
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

// addChild registers a child tracer.
func (t *FuncTracer) addChild(child *FuncTracer) {
	t.childrenMu.Lock()
	if _, ok := t.children[child.name]; !ok {
		t.children[child.name] = child
	}
	t.childrenMu.Unlock()
}

// Snapshot returns a point-in-time snapshot of the tracer.
func (t *FuncTracer) Snapshot() TracerSnapshot {
	t.childrenMu.RLock()
	childNames := make([]string, 0, len(t.children))
	for name := range t.children {
		childNames = append(childNames, name)
	}
	t.childrenMu.RUnlock()

	c := t.calls.Load()
	s := t.sampled.Load()
	total := time.Duration(t.totalNs.Load())

	var avg time.Duration
	if s > 0 {
		avg = time.Duration(uint64(total) / s)
	}

	return TracerSnapshot{
		Name:       t.name,
		Calls:      c,
		Sampled:    s,
		Total:      total,
		Avg:        avg,
		Max:        time.Duration(t.maxNs.Load()),
		Depth:      t.depth,
		ChildNames: childNames,
	}
}

// TracerSnapshot is a point-in-time snapshot of tracer metrics.
type TracerSnapshot struct {
	Name       string        `json:"name"`
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
	var totalRuntime time.Duration
	var totalCalls, totalSampled uint64

	for i, t := range tracers {
		snap := t.Snapshot()
		snapshots[i] = snap
		totalRuntime += snap.Total
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
	fmt.Fprintf(w, "Total Runtime: %s | Total Calls: %d | Sampled Calls: %d\n",
		totalRuntime, totalCalls, totalSampled)
	fmt.Fprintln(w, "")

	// Print table header
	fmt.Fprintf(w, "%-45s %12s %12s %12s %12s %10s\n",
		"Function", "Calls", "Total", "Avg", "Max", "%Runtime")
	fmt.Fprintln(w, strings.Repeat("-", 115))

	// Print rows
	for _, s := range snapshots {
		pct := 0.0
		if totalRuntime > 0 {
			pct = float64(s.Total) / float64(totalRuntime) * 100
		}

		name := s.Name
		if len(name) > 43 {
			name = "..." + name[len(name)-40:]
		}

		fmt.Fprintf(w, "%-45s %12d %12s %12s %12s %9.1f%%\n",
			name,
			s.Calls,
			formatDuration(s.Total),
			formatDuration(s.Avg),
			formatDuration(s.Max),
			pct,
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
	var totalRuntime time.Duration
	var totalCalls, totalSampled uint64

	for i, t := range tracers {
		snap := t.Snapshot()
		snapshots[i] = snap
		totalRuntime += snap.Total
		totalCalls += snap.Calls
		totalSampled += snap.Sampled
	}

	// Sort by total time
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Total > snapshots[j].Total
	})

	type tracerSnapshotJSON struct {
		Name     string   `json:"name"`
		Calls    uint64   `json:"calls"`
		Sampled  uint64   `json:"sampled"`
		TotalNs  uint64   `json:"total_ns"`
		AvgNs    uint64   `json:"avg_ns"`
		MaxNs    uint64   `json:"max_ns"`
		Depth    int      `json:"depth"`
		Children []string `json:"child_names,omitempty"`
	}
	funcs := make([]tracerSnapshotJSON, 0, len(snapshots))
	for _, s := range snapshots {
		funcs = append(funcs, tracerSnapshotJSON{
			Name:     s.Name,
			Calls:    s.Calls,
			Sampled:  s.Sampled,
			TotalNs:  uint64(s.Total),
			AvgNs:    uint64(s.Avg),
			MaxNs:    uint64(s.Max),
			Depth:    s.Depth,
			Children: s.ChildNames,
		})
	}

	report := struct {
		Msg            string               `json:"msg"`
		TotalRuntimeNs uint64               `json:"total_runtime_ns"`
		TotalCalls     uint64               `json:"total_calls"`
		SampledCalls   uint64               `json:"sampled_calls"`
		Functions      []tracerSnapshotJSON `json:"functions"`
	}{
		Msg:            "function performance report",
		TotalRuntimeNs: uint64(totalRuntime),
		TotalCalls:     totalCalls,
		SampledCalls:   totalSampled,
		Functions:      funcs,
	}

	return json.Marshal(report)
}

// Enabled returns true if performance tracing is enabled.
func Enabled() bool {
	return true
}

// GoVersion returns the Go version for build info.
func GoVersion() string {
	return runtime.Version()
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
