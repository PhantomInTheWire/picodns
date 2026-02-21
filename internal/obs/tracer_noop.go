//go:build !perf

package obs

import (
	"io"
	"time"
)

// FuncTracer is a no-op implementation when perf build tag is not set.
type FuncTracer struct{}

// NewFuncTracer creates a no-op tracer.
func NewFuncTracer(name string, parent *FuncTracer) *FuncTracer {
	return &FuncTracer{}
}

// Name returns empty string for no-op tracer.
func (t *FuncTracer) Name() string {
	return ""
}

// Trace is a no-op. Returns a no-op function.
func (t *FuncTracer) Trace() func() {
	return func() {}
}

// Snapshot returns empty snapshot.
func (t *FuncTracer) Snapshot() TracerSnapshot {
	return TracerSnapshot{}
}

// TracerSnapshot is a no-op structure for non-perf builds.
type TracerSnapshot struct {
	Name       string
	Calls      uint64
	Sampled    uint64
	Total      time.Duration
	Avg        time.Duration
	Max        time.Duration
	Depth      int
	ChildNames []string
}

// Registry is a no-op implementation when perf build tag is not set.
type Registry struct{}

// GlobalRegistry is a no-op global registry.
var GlobalRegistry = &Registry{}

// Register is a no-op.
func (r *Registry) Register(t *FuncTracer) {}

// Report is a no-op.
func (r *Registry) Report(w io.Writer) {}

// ReportJSON returns empty JSON.
func (r *Registry) ReportJSON() ([]byte, error) {
	return []byte("{}"), nil
}

// Enabled returns false when perf build tag is not set.
func Enabled() bool {
	return false
}

// GoVersion returns empty string for non-perf builds.
func GoVersion() string {
	return ""
}
