package server

import "time"

func (s *Server) logShutdown(startTime time.Time, obsEnabled bool) {
	if !obsEnabled {
		s.logger.Info("server shutdown complete",
			"total_queries", s.TotalQueries.Load(),
			"dropped_packets", s.DroppedPackets.Load(),
			"handler_errors", s.HandlerErrors.Load(),
			"write_errors", s.WriteErrors.Load(),
		)
		return
	}

	uptime := time.Since(startTime)
	avgQPS := 0.0
	total := s.TotalQueries.Load()
	if uptime > 0 {
		avgQPS = float64(total) / uptime.Seconds()
	}

	hits, miss := uint64(0), uint64(0)
	cacheHitRate := 0.0
	if s.cacheCounters != nil {
		hits, miss = s.cacheCounters()
		if hits+miss > 0 {
			cacheHitRate = float64(hits) / float64(hits+miss)
		}
	}

	s.logger.Info("server shutdown complete",
		"uptime", uptime,
		"avg_qps", avgQPS,
		"queue_len", len(s.jobQueue),
		"queue_cap", cap(s.jobQueue),
		"total_queries", total,
		"dropped_packets", s.DroppedPackets.Load(),
		"handler_errors", s.HandlerErrors.Load(),
		"write_errors", s.WriteErrors.Load(),
		"cache_hits", hits,
		"cache_miss", miss,
		"cache_hit_rate", cacheHitRate,
	)

	s.writePerfReport()
}
