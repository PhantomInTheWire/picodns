package server

import (
	"context"
	"net"

	"picodns/internal/resolver"
)

type DNSHandler struct {
	resolver resolver.Resolver
}

func NewDNSHandler(res resolver.Resolver) *DNSHandler {
	return &DNSHandler{resolver: res}
}

func (h *DNSHandler) HandlePacket(ctx context.Context, packet []byte, addr net.Addr) ([]byte, error) {
	if h == nil || h.resolver == nil {
		return nil, nil
	}
	return h.resolver.Resolve(ctx, packet)
}
