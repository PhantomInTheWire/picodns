//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package server

import "net"

func listenUDPPacketReusePort(addr string) (net.PacketConn, error) {
	// Platform does not support SO_REUSEPORT via x/sys/unix.
	return net.ListenPacket("udp", addr)
}
