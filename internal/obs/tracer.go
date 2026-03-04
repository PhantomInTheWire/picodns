//go:build perf

package obs

import (
	"sync/atomic"
	"time"
)

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
	return t.trace(sampled, false)
}

// TraceNested records timing only when sampled is true and increments both the
// call counter and sampled counter.
//
// This is intended for nested segments where you want consistent sampling with
// a parent function without paying per-call overhead when not sampled.
func (t *FuncTracer) TraceNested(sampled bool) func() {
	return t.trace(sampled, true)
}

// Trace starts tracing a function call. Returns a function to call on exit.
// Usage: defer tracer.Trace()()
// Note: This is goroutine-safe and uses 1/256 sampling.
func (t *FuncTracer) Trace() func() {
	sampled := t.ShouldSample()
	return t.TraceSampled(sampled)
}

func (t *FuncTracer) trace(sampled bool, countCall bool) func() {
	if countCall {
		t.calls.Add(1)
	}
	if !sampled {
		return func() {}
	}

	t.sampled.Add(1)
	start := time.Now()
	return func() {
		t.recordDuration(time.Since(start))
	}
}

func (t *FuncTracer) recordDuration(dt time.Duration) {
	ns := uint64(dt)
	t.totalNs.Add(ns)
	for {
		prev := t.maxNs.Load()
		if ns <= prev {
			return
		}
		if t.maxNs.CompareAndSwap(prev, ns) {
			return
		}
	}
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
