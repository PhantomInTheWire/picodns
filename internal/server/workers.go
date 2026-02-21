package server

import (
	"context"
	"sync"
)

func (s *Server) startWorkers(ctx context.Context, wg *sync.WaitGroup) {
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx)
		}()
	}
}
