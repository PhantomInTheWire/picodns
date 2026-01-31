package server

import (
	"context"
	"net"
)

type Handler interface {
	HandlePacket(ctx context.Context, packet []byte, addr net.Addr) ([]byte, error)
}

type NoopHandler struct{}

func (NoopHandler) HandlePacket(ctx context.Context, packet []byte, addr net.Addr) ([]byte, error) {
	return nil, nil
}
