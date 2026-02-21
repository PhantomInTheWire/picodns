package server

import (
	"context"
	"sync"

	"picodns/internal/types"
)

func (s *Server) startUDPListeners(ctx context.Context, addr string, udpSockets int, cacheResolver types.CacheResolver, readersWg, writersWg *sync.WaitGroup) error {
	for i := 0; i < udpSockets; i++ {
		conn, err := listenUDPPacket(addr, udpSockets > 1)
		if err != nil {
			return err
		}
		w := &udpWriter{conn: conn, ch: make(chan udpWrite, s.cfg.Workers)}
		writersWg.Add(1)
		go func(writer *udpWriter) {
			defer writersWg.Done()
			s.udpWriteLoop(ctx, writer)
		}(w)
		if i == 0 {
			s.logger.Info("dns server listening", "listen", addr, "udp_sockets", udpSockets)
		}

		readersWg.Add(1)
		go func(writer *udpWriter) {
			defer readersWg.Done()
			s.udpReadLoop(ctx, writer, cacheResolver)
		}(w)
	}
	return nil
}
