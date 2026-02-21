package server

import "net"

func listenUDPPacket(addr string, reusePort bool) (net.PacketConn, error) {
	if !reusePort {
		return net.ListenPacket("udp", addr)
	}
	return listenUDPPacketReusePort(addr)
}
