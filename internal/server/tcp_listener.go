package server

import (
	"context"
	"errors"
	"net"
	"sync"
)

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
			go s.handleTCPConn(ctx, conn)
		}
	}(ln)

	return nil
}
