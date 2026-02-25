package server

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"picodns/internal/dns"
	"picodns/internal/obs"
	"picodns/internal/types"
)

// servfailFromRequestInPlace rewrites req in-place into a minimal SERVFAIL response.
// The returned slice references req.
func servfailFromRequestInPlace(req []byte) ([]byte, bool) {
	hdr, err := dns.ReadHeader(req)
	if err != nil || hdr.QDCount == 0 {
		return nil, false
	}
	nameEnd, err := dns.SkipName(req, dns.HeaderLen)
	if err != nil {
		return nil, false
	}
	qEnd := nameEnd + 4 // qtype + qclass
	if qEnd > len(req) {
		return nil, false
	}

	hdr.Flags = dns.FlagQR | (hdr.Flags & dns.FlagOpcode) | (hdr.Flags & dns.FlagRD) | dns.FlagRA | (dns.RcodeServer & 0x000F)
	hdr.QDCount = 1
	hdr.ANCount = 0
	hdr.NSCount = 0
	hdr.ARCount = 0
	_ = dns.WriteHeader(req, hdr)

	return req[:qEnd], true
}

func (s *Server) startWorkers(ctx context.Context, wg *sync.WaitGroup) {
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx)
		}()
	}
}

func (s *Server) startUDPListener(ctx context.Context, addr string, cacheResolver types.CacheResolver, readersWg, writersWg *sync.WaitGroup, udpWriters *[]*udpWriter) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	w := &udpWriter{
		conn:   conn,
		ch:     make(chan udpWrite, s.cfg.Workers),
		slowCh: make(chan udpWrite, s.cfg.Workers),
	}
	if udpWriters != nil {
		*udpWriters = append(*udpWriters, w)
	}
	writersWg.Add(1)
	go func(writer *udpWriter) {
		defer writersWg.Done()
		s.udpWriteLoop(writer)
	}(w)
	s.logger.Info("dns server listening", "listen", addr)

	readersWg.Add(1)
	go func(writer *udpWriter) {
		defer readersWg.Done()
		s.udpReadLoop(ctx, writer, cacheResolver)
	}(w)
	return nil
}

func (s *Server) startListeners(ctx context.Context, readersWg, writersWg *sync.WaitGroup, udpWriters *[]*udpWriter) error {
	cacheResolver, _ := s.resolver.(types.CacheResolver)

	for _, addr := range s.cfg.ListenAddrs {
		if err := s.startUDPListener(ctx, addr, cacheResolver, readersWg, writersWg, udpWriters); err != nil {
			return err
		}
		if err := s.startTCPListener(ctx, addr, readersWg); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) startTCPListener(ctx context.Context, addr string, readersWg *sync.WaitGroup) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.logger.Info("dns tcp server listening", "listen", addr)

	readersWg.Add(1)
	go func(l net.Listener) {
		defer readersWg.Done()
		defer func() { _ = l.Close() }()

		go func() {
			<-ctx.Done()
			_ = l.Close()
		}()

		for {
			conn, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Error("tcp accept error", "error", err)
				continue
			}
			select {
			case s.tcpSem <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-s.tcpSem }()
					s.handleTCPConn(ctx, c)
				}(conn)
			default:
				// At capacity, reject connection
				_ = conn.Close()
			}
		}
	}(ln)

	return nil
}

func (s *Server) logShutdown(startTime time.Time, obsEnabled bool) {
	if !obsEnabled {
		s.logger.Info("server shutdown complete",
			"total_queries", s.TotalQueries.Load(),
			"dropped_packets", s.DroppedPackets.Load(),
			"dropped_responses", s.DroppedResponses.Load(),
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
		"dropped_responses", s.DroppedResponses.Load(),
		"handler_errors", s.HandlerErrors.Load(),
		"write_errors", s.WriteErrors.Load(),
		"cache_hits", hits,
		"cache_miss", miss,
		"cache_hit_rate", cacheHitRate,
	)

	s.writePerfReport()
}

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
