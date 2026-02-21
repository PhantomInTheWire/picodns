package obs

import (
	"sync/atomic"
	"time"
)

// DurationStat tracks count/total/max for observed durations.
// All operations are lock-free and safe for concurrent use.
type DurationStat struct {
	count   atomic.Uint64
	totalNs atomic.Uint64
	maxNs   atomic.Uint64
}

type DurationSnapshot struct {
	Count uint64
	Total time.Duration
	Avg   time.Duration
	Max   time.Duration
}

func (d *DurationStat) Observe(dt time.Duration) {
	if dt <= 0 {
		return
	}
	ns := uint64(dt)
	d.count.Add(1)
	d.totalNs.Add(ns)

	for {
		prev := d.maxNs.Load()
		if ns <= prev {
			return
		}
		if d.maxNs.CompareAndSwap(prev, ns) {
			return
		}
	}
}

func (d *DurationStat) Snapshot() DurationSnapshot {
	c := d.count.Load()
	total := time.Duration(d.totalNs.Load())
	var avg time.Duration
	if c > 0 {
		avg = time.Duration(uint64(total) / c)
	}
	return DurationSnapshot{
		Count: c,
		Total: total,
		Avg:   avg,
		Max:   time.Duration(d.maxNs.Load()),
	}
}
