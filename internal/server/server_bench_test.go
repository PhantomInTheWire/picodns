package server

import (
	"net"
	"testing"
)

func BenchmarkUDPWriteTo(b *testing.B) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	resp := make([]byte, 100)
	b.SetBytes(int64(len(resp)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(resp, addr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPReadFrom(b *testing.B) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()

	listenerAddr := listener.LocalAddr().(*net.UDPAddr)
	sender, err := net.DialUDP("udp", nil, listenerAddr)
	if err != nil {
		b.Fatal(err)
	}
	defer sender.Close()

	payload := make([]byte, 100)
	b.SetBytes(int64(len(payload)))

	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func(n int) {
		defer close(done)
		for i := 0; i < n; i++ {
			if _, werr := sender.Write(payload); werr != nil {
				select {
				case errCh <- werr:
				default:
				}
				return
			}
		}
	}(b.N)

	recvBuf := make([]byte, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, rerr := listener.ReadFrom(recvBuf); rerr != nil {
			b.Fatal(rerr)
		}
	}
	b.StopTimer()
	<-done
	select {
	case werr := <-errCh:
		b.Fatal(werr)
	default:
	}
}
