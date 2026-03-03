//go:build perf

package obs

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strings"
	"time"
)

// Report generates and outputs a performance report.
func (r *Registry) Report(w io.Writer) {
	snapshots, totalCalls, totalSampled := r.sortedSnapshots()
	if len(snapshots) == 0 {
		return
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "=== Function Performance Report ===")
	wall := time.Since(registryStart)
	rate := samplingRateFromMask(samplingMask.Load())
	warm := warmupSampleCalls.Load()
	fmt.Fprintf(w, "Wall Time: %s | Sample Rate: 1/%d | Warmup Samples: %d | Total Calls: %d | Sampled Calls: %d\n",
		wall, rate, warm, totalCalls, totalSampled)
	fmt.Fprintln(w, "")

	fmt.Fprintf(w, "%-45s %12s %10s %12s %12s %12s\n",
		"Function", "Calls", "Sampled", "SampledTotal", "EstTotal", "Max")
	fmt.Fprintln(w, strings.Repeat("-", 115))

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
	snapshots, totalCalls, totalSampled := r.sortedSnapshots()

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

func (r *Registry) sortedSnapshots() ([]TracerSnapshot, uint64, uint64) {
	tracers := r.snapshotTracers()
	if len(tracers) == 0 {
		return nil, 0, 0
	}

	snapshots := make([]TracerSnapshot, len(tracers))
	var totalCalls, totalSampled uint64
	for i, t := range tracers {
		snap := t.Snapshot()
		snapshots[i] = snap
		totalCalls += snap.Calls
		totalSampled += snap.Sampled
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Total > snapshots[j].Total
	})

	return snapshots, totalCalls, totalSampled
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
	if mask == 0 {
		return 1
	}
	return 1 << uint(bits.Len64(mask+1)-1)
}

func estimateTotal(sampledTotalNs uint64, calls, sampled uint64) uint64 {
	if sampled == 0 || calls == 0 || sampledTotalNs == 0 {
		return 0
	}
	est := (float64(sampledTotalNs) * float64(calls)) / float64(sampled)
	if est <= 0 {
		return 0
	}
	if est > float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(math.Round(est))
}
