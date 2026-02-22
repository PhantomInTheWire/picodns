package testutil

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"picodns/internal/dns"
	"picodns/tests/testutil/dnstest"
)

// MockTransport is a mock DNS transport for testing.
// It allows tests to intercept DNS queries and return custom responses.
type MockTransport struct {
	mu       sync.RWMutex
	handlers map[string]MockHandler // server address -> handler
	queryLog *sync.Map              // tracks which servers were queried
}

// MockHandler is a function that handles DNS queries to a specific server.
// It receives the request bytes and should return the response bytes.
type MockHandler func(req []byte) ([]byte, error)

// NewMockTransport creates a new mock transport.
func NewMockTransport() *MockTransport {
	return &MockTransport{
		handlers: make(map[string]MockHandler),
		queryLog: &sync.Map{},
	}
}

// RegisterHandler registers a handler for a specific server address.
func (m *MockTransport) RegisterHandler(server string, handler MockHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[server] = handler
}

// Query implements the types.Transport interface.
func (m *MockTransport) Query(ctx context.Context, server string, req []byte, timeout time.Duration) ([]byte, func(), error) {
	// Log that this server was queried
	if m.queryLog != nil {
		m.queryLog.Store(server, true)
	}

	m.mu.RLock()
	handler, ok := m.handlers[server]
	m.mu.RUnlock()

	if !ok {
		// No handler registered for this server
		return nil, nil, context.DeadlineExceeded
	}

	resp, err := handler(req)
	if err != nil {
		return nil, nil, err
	}

	// Return response with no-op cleanup
	return resp, func() {}, nil
}

// WasQueried returns true if the given server was queried.
func (m *MockTransport) WasQueried(server string) bool {
	if m.queryLog == nil {
		return false
	}
	_, ok := m.queryLog.Load(server)
	return ok
}

// Reset clears all handlers and query logs.
func (m *MockTransport) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = make(map[string]MockHandler)
	m.queryLog = &sync.Map{}
}

// TransportMockHierarchy is a fluent builder for creating mock DNS hierarchies using MockTransport
type TransportMockHierarchy struct {
	t         *testing.T
	transport *MockTransport
	rootAddr  string
	tldAddrs  map[string]string
	authAddrs map[string]string
}

// NewTransportMockHierarchy creates a new mock DNS hierarchy builder for transport-based tests
func NewTransportMockHierarchy(t *testing.T, transport *MockTransport) *TransportMockHierarchy {
	return &TransportMockHierarchy{
		t:         t,
		transport: transport,
		tldAddrs:  make(map[string]string),
		authAddrs: make(map[string]string),
	}
}

// referralHandler creates a handler that returns a referral response
func (h *TransportMockHierarchy) referralHandler(zone, nsName, nsIP string) func([]byte) ([]byte, error) {
	return func(req []byte) ([]byte, error) {
		return dnstest.BuildReferralResponse(h.t, req,
			[]dns.Answer{dnstest.NSRecord(zone, nsName, 86400)},
			[]dns.Answer{dnstest.ARecord(nsName, net.ParseIP(nsIP), 86400)},
		), nil
	}
}

// WithRoot configures the root server with a referral to a TLD nameserver
func (h *TransportMockHierarchy) WithRoot(tldZone, tldNSName, tldNSIP string) *TransportMockHierarchy {
	h.rootAddr = "192.0.2.1:53"
	h.transport.RegisterHandler(h.rootAddr, h.referralHandler(tldZone, tldNSName, tldNSIP))
	return h
}

// WithTLD configures a TLD server with a referral to an authoritative nameserver
func (h *TransportMockHierarchy) WithTLD(zone, authNSName, authNSIP string) *TransportMockHierarchy {
	// Use a deterministic address based on the auth NS IP
	tldAddr := "192.0.2.5:53"
	if len(h.tldAddrs) > 0 {
		tldAddr = "192.0.2.6:53"
	}
	h.tldAddrs[zone] = tldAddr
	h.transport.RegisterHandler(tldAddr, h.referralHandler(zone, authNSName, authNSIP))
	return h
}

// WithAuthority configures an authoritative server that returns answers for specific domains
func (h *TransportMockHierarchy) WithAuthority(domain string, answers []dns.Answer) *TransportMockHierarchy {
	// Extract IP from the last glue record registered or use default
	authIP := "192.0.2.10"
	authAddr := authIP + ":53"
	h.authAddrs[domain] = authAddr

	h.transport.RegisterHandler(authAddr, func(req []byte) ([]byte, error) {
		msg, err := dns.ReadMessagePooled(req)
		if err != nil {
			return dns.BuildResponse(req, nil, dns.RcodeServer)
		}
		defer msg.Release()
		if len(msg.Questions) == 0 {
			return dns.BuildResponse(req, nil, dns.RcodeServer)
		}
		return dns.BuildResponse(req, answers, dns.RcodeSuccess)
	})
	return h
}

// RootAddr returns the root server address
func (h *TransportMockHierarchy) RootAddr() string {
	return h.rootAddr
}

// TLDAddr returns the TLD server address for a zone
func (h *TransportMockHierarchy) TLDAddr(zone string) string {
	return h.tldAddrs[zone]
}

// AuthAddr returns the authority server address for a domain
func (h *TransportMockHierarchy) AuthAddr(domain string) string {
	return h.authAddrs[domain]
}
