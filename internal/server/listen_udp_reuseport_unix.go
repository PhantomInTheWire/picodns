//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package server

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenUDPPacketReusePort(addr string) (net.PacketConn, error) {
	var lc net.ListenConfig
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
				ctrlErr = e
				return
			}
			if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
				ctrlErr = e
				return
			}
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
	return lc.ListenPacket(context.Background(), "udp", addr)
}
