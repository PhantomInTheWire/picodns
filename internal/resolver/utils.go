package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"picodns/internal/dns"
)

type inflightCall struct {
	done chan struct{}
	resp []byte
	err  error
}

// hashQuestion returns a cache key for a DNS question.
func hashQuestion(name string, qType, qClass uint16) uint64 {
	h := dns.HashNameString(name)
	h ^= uint64(qType) << 32
	h ^= uint64(qClass)
	return h
}

// secureRandUint16 generates a cryptographically secure random uint16.
func secureRandUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// formatIPPort formats an IP address as "ip:port" string.
// IPv6 addresses are bracketed per RFC 3986: [::1]:53.
func formatIPPort(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
}

// cleanupBoth releases a pooled message and executes a cleanup function.
func cleanupBoth(msg *dns.Message, cleanup func()) {
	if msg != nil {
		msg.Release()
	}
	if cleanup != nil {
		cleanup()
	}
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
