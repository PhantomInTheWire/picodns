package testutil

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// MockNameserver represents a mock DNS server for testing
type MockNameserver struct {
	conn     net.PacketConn
	Addr     string
	handler  func(req []byte, addr net.Addr)
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// StartMockNameserver starts a mock DNS server with the given handler
func StartMockNameserver(t *testing.T, handler func(req []byte, addr net.Addr)) *MockNameserver {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	ns := &MockNameserver{
		conn:     conn,
		Addr:     conn.LocalAddr().String(),
		handler:  handler,
		stopChan: make(chan struct{}),
	}

	ns.wg.Add(1)
	go func() {
		defer ns.wg.Done()
		buf := make([]byte, 512)
		for {
			select {
			case <-ns.stopChan:
				return
			default:
			}

			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			req := make([]byte, n)
			copy(req, buf[:n])
			go handler(req, addr)
		}
	}()

	t.Cleanup(func() {
		close(ns.stopChan)
		_ = conn.Close()
		ns.wg.Wait()
	})

	return ns
}

// Conn returns the underlying UDP connection for sending responses
func (ns *MockNameserver) Conn() *net.UDPConn {
	return ns.conn.(*net.UDPConn)
}

// Host returns just the IP address (without port) of the server
func (ns *MockNameserver) Host() string {
	host, _, _ := net.SplitHostPort(ns.Addr)
	return host
}
