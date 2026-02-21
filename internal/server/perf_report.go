package server

import (
	"os"
	"path/filepath"

	"picodns/internal/obs"
)

func (s *Server) writePerfReport() {
	if !obs.Enabled() {
		return
	}
	path := s.cfg.PerfReport
	if path == "" {
		return
	}
	data, err := obs.GlobalRegistry.ReportJSON()
	if err != nil {
		s.logger.Error("failed to build perf report", "error", err)
		return
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			s.logger.Error("failed to create perf report dir", "dir", dir, "error", mkErr)
			return
		}
	}
	if wErr := os.WriteFile(path, data, 0o644); wErr != nil {
		s.logger.Error("failed to write perf report", "path", path, "error", wErr)
		return
	}
	s.logger.Info("perf report written", "path", path, "bytes", len(data))
}
