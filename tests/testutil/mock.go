package testutil

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
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

// MockHierarchy manages a hierarchy of mock DNS servers (root, TLD, authority)
type MockHierarchy struct {
	t           *testing.T
	root        *MockNameserver
	tlds        map[string]*MockNameserver
	authorities map[string]*MockNameserver
}

// NewMockHierarchy creates a new mock DNS hierarchy builder
func NewMockHierarchy(t *testing.T) *MockHierarchy {
	return &MockHierarchy{
		t:           t,
		tlds:        make(map[string]*MockNameserver),
		authorities: make(map[string]*MockNameserver),
	}
}

// WithRoot configures the root server with a referral to a TLD nameserver
func (h *MockHierarchy) WithRoot(tldZone, tldNSName, tldNSIP string) *MockHierarchy {
	h.root = StartMockNameserver(h.t, func(req []byte, addr net.Addr) {
		resp := BuildReferralResponse(h.t, req,
			[]dns.Answer{NSRecord(tldZone, tldNSName, 86400)},
			[]dns.Answer{ARecord(tldNSName, net.ParseIP(tldNSIP), 86400)},
		)
		if _, err := h.root.Conn().WriteTo(resp, addr); err != nil {
			h.t.Logf("WithRoot: failed to write response: %v", err)
		}
	})
	return h
}

// WithTLD configures a TLD server with a referral to an authoritative nameserver
func (h *MockHierarchy) WithTLD(zone, authNSName, authNSIP string) *MockHierarchy {
	var server *MockNameserver
	server = StartMockNameserver(h.t, func(req []byte, addr net.Addr) {
		resp := BuildReferralResponse(h.t, req,
			[]dns.Answer{NSRecord(zone, authNSName, 86400)},
			[]dns.Answer{ARecord(authNSName, net.ParseIP(authNSIP), 86400)},
		)
		if _, err := server.Conn().WriteTo(resp, addr); err != nil {
			h.t.Logf("WithTLD: failed to write response: %v", err)
		}
	})
	h.tlds[zone] = server
	return h
}

// WithAuthority configures an authoritative server for a domain
func (h *MockHierarchy) WithAuthority(domain string, answers []dns.Answer) *MockHierarchy {
	var server *MockNameserver
	server = StartMockNameserver(h.t, func(req []byte, addr net.Addr) {
		msg, err := dns.ReadMessagePooled(req)
		if err != nil {
			h.t.Logf("WithAuthority: failed to read message: %v", err)
			// Send SERVFAIL for malformed request
			resp, buildErr := dns.BuildResponse(req, nil, dns.RcodeServer)
			if buildErr != nil {
				h.t.Logf("WithAuthority: failed to build error response: %v", buildErr)
				return
			}
			if _, writeErr := server.Conn().WriteTo(resp, addr); writeErr != nil {
				h.t.Logf("WithAuthority: failed to write error response: %v", writeErr)
			}
			return
		}
		defer msg.Release()
		if len(msg.Questions) == 0 {
			// Return SERVFAIL for malformed request with no questions
			resp, err := dns.BuildResponse(req, nil, dns.RcodeServer)
			if err != nil {
				h.t.Logf("WithAuthority: failed to build error response: %v", err)
				return
			}
			if _, err := server.Conn().WriteTo(resp, addr); err != nil {
				h.t.Logf("WithAuthority: failed to write error response: %v", err)
			}
			return
		}

		q := msg.Questions[0]
		if q.Name == domain {
			resp, err := dns.BuildResponse(req, answers, dns.RcodeSuccess)
			if err != nil {
				h.t.Logf("WithAuthority: failed to build response: %v", err)
				return
			}
			if _, err := server.Conn().WriteTo(resp, addr); err != nil {
				h.t.Logf("WithAuthority: failed to write response: %v", err)
			}
		}
	})
	h.authorities[domain] = server
	return h
}

// Root returns the root mock server
func (h *MockHierarchy) Root() *MockNameserver {
	return h.root
}

// TLD returns a TLD mock server by zone
func (h *MockHierarchy) TLD(zone string) *MockNameserver {
	return h.tlds[zone]
}

// Authority returns an authority mock server by domain
func (h *MockHierarchy) Authority(domain string) *MockNameserver {
	return h.authorities[domain]
}
