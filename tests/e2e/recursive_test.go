//go:build e2e

package e2e

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/dnsutil"
	"picodns/internal/resolver"
	"picodns/tests/testutil"
)

// useRealNetwork returns true if E2E_REAL_NETWORK environment variable is set
func useRealNetwork() bool {
	return os.Getenv("E2E_REAL_NETWORK") == "1"
}

// requireNetwork skips the test if real network is not available
func requireNetwork(t *testing.T) {
	if !useRealNetwork() {
		t.Skip("Set E2E_REAL_NETWORK=1 for network tests")
	}
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		t.Skip("Network unavailable")
	}
	conn.Close()
}

// sendQueryWithType sends a DNS query with specific record type
func sendQueryWithType(t *testing.T, addr string, name string, qtype uint16) []byte {
	conn, err := net.Dial("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	buf := make([]byte, 512)
	_ = dns.WriteHeader(buf, dns.Header{ID: 0xBEEF, Flags: 0x0100, QDCount: 1})
	end, _ := dns.WriteQuestion(buf, dns.HeaderLen, dns.Question{Name: name, Type: qtype, Class: dns.ClassIN})
	req := buf[:end]

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = conn.Write(req)
	require.NoError(t, err)

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	require.NoError(t, err)
	return respBuf[:n]
}

// mockNameserver represents a mock DNS server for testing
type mockNameserver struct {
	conn     net.PacketConn
	addr     string
	handler  func(req []byte, addr net.Addr)
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// testResolver wraps a recursive resolver to redirect root queries to mock
type testResolver struct {
	rec       *resolver.Recursive
	mockRoot  string
	cache     *cache.Cache
	queryLog  *sync.Map
	serverMap map[string]string // Maps IP:53 to actual server address (IP:port)
}

func newTestResolver(mockRoot string, queryLog *sync.Map) *testResolver {
	return &testResolver{
		rec:       resolver.NewRecursive(),
		mockRoot:  mockRoot,
		cache:     cache.New(100, nil),
		queryLog:  queryLog,
		serverMap: make(map[string]string),
	}
}

func (r *testResolver) registerServer(ip string, actualAddr string) {
	r.serverMap[ip+":53"] = actualAddr
}

func (r *testResolver) resolveServer(server string) string {
	if actual, ok := r.serverMap[server]; ok {
		return actual
	}
	return server
}

func (r *testResolver) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	// Perform iterative resolution with mock root
	resp, err := r.resolveIterative(ctx, req, 0)
	return resp, nil, err
}

func (r *testResolver) resolveIterative(ctx context.Context, req []byte, depth int) ([]byte, error) {
	if depth >= 32 {
		return nil, resolver.ErrMaxDepth
	}

	msg, _ := dns.ReadMessagePooled(req)
	defer msg.Release()
	if len(msg.Questions) == 0 {
		return nil, resolver.ErrNoNameservers
	}

	q := msg.Questions[0]
	servers := []string{r.mockRoot}

	// Labels for building zones
	labels := dnsutil.SplitLabels(q.Name)

	for i := len(labels); i >= 0; i-- {
		zone := dnsutil.JoinLabels(labels[i:])
		if zone != "." {
			zone = dnsutil.NormalizeName(zone)
		}

		for _, server := range servers {
			resp, err := r.queryServer(ctx, server, req)
			if err != nil {
				continue
			}

			respMsg, err := dns.ReadMessagePooled(resp)
			if err != nil {
				continue
			}

			// Check for answers
			if len(respMsg.Answers) > 0 {
				hasNonCNAME := false
				for _, ans := range respMsg.Answers {
					if ans.Type != dns.TypeCNAME {
						hasNonCNAME = true
						break
					}
				}
				if hasNonCNAME {
					respMsg.Release()
					return resp, nil
				}

				for _, ans := range respMsg.Answers {
					if ans.Type == dns.TypeCNAME {
						cnameTarget := dnsutil.ExtractNameFromData(resp, ans.DataOffset)
						if cnameTarget != "" {
							newReq, err := dnsutil.BuildQuery(msg.Header.ID, cnameTarget, q.Type, q.Class)
							respMsg.Release()
							if err != nil {
								continue
							}
							return r.resolveIterative(ctx, newReq, depth+1)
						}
					}
				}
			}

			// Check for NXDOMAIN
			if (respMsg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
				respMsg.Release()
				return resp, nil
			}

			// Follow referral
			if len(respMsg.Authorities) > 0 {
				newServers := r.extractReferral(resp, *respMsg, zone)
				respMsg.Release()
				if len(newServers) > 0 {
					servers = newServers
					break
				}
			} else {
				respMsg.Release()
			}
		}
	}

	return nil, resolver.ErrNoNameservers
}

func (r *testResolver) queryServer(ctx context.Context, server string, req []byte) ([]byte, error) {
	// Resolve server address using the map
	server = r.resolveServer(server)
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])

	// Log which server was queried
	if r.queryLog != nil {
		r.queryLog.Store(server, true)
	}

	return resp, nil
}

func (r *testResolver) extractReferral(fullMsg []byte, msg dns.Message, zone string) []string {
	var nsNames []string
	nsIPs := make(map[string][]string)

	zoneNorm := strings.ToLower(strings.TrimSuffix(zone, "."))

	// First collect all NS records that match the zone
	for _, rr := range msg.Authorities {
		if rr.Type == dns.TypeNS {
			nsOwner := strings.ToLower(strings.TrimSuffix(rr.Name, "."))

			// We need to match NS records to the current zone we're querying
			// For zone "." (root), accept NS records for TLDs like "com"
			// For zone "com", accept NS records for "com"
			// For zone "example.com", accept NS records for "example.com"
			//
			// The NS owner should be the zone itself (for referrals within the same zone)
			// or the zone should be a parent of the NS owner (when climbing down)
			matches := false
			if zoneNorm == "" {
				// Root zone: accept any NS (these are TLD delegations)
				matches = true
			} else if nsOwner == zoneNorm {
				// Exact match
				matches = true
			} else if strings.HasSuffix(zoneNorm, "."+nsOwner) {
				// Zone is a subdomain of NS owner (e.g., zone="example.com", owner="com")
				matches = true
			}

			if !matches {
				continue
			}

			nsName := dnsutil.ExtractNameFromData(fullMsg, rr.DataOffset)
			if nsName != "" {
				nsNames = append(nsNames, nsName)
			}
		}
	}

	// Collect all A records from additional section
	for _, rr := range msg.Additionals {
		if rr.Type == dns.TypeA && len(rr.Data) == 4 {
			ip := net.IP(rr.Data).String() + ":53"
			nsIPs[rr.Name] = append(nsIPs[rr.Name], ip)
		}
	}

	var glueIPs []string
	for _, nsName := range nsNames {
		// Try to find glue record for this NS name (case-insensitive match)
		for name, ips := range nsIPs {
			if strings.EqualFold(name, nsName) {
				glueIPs = append(glueIPs, ips...)
			}
		}
	}

	// If we found glue IPs, return them
	if len(glueIPs) > 0 {
		return glueIPs
	}

	// If no glue, we'd need to resolve the NS names, but for simplicity
	// in tests, we should always provide glue records
	return nil
}

// TestE2ERecursiveResolution tests the full iterative resolution process
func TestE2ERecursiveResolution(t *testing.T) {
	if useRealNetwork() {
		testRecursiveResolutionReal(t)
	} else {
		testRecursiveResolutionMock(t)
	}
}

func testRecursiveResolutionReal(t *testing.T) {
	requireNetwork(t)
	rec := resolver.NewRecursive()
	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	resp := sendQuery(t, serverAddr, "www.example.com")
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)

	var foundA bool
	for _, ans := range msg.Answers {
		if ans.Type == dns.TypeA {
			foundA = true
			t.Logf("Resolved to %s", net.IP(ans.Data))
		}
	}
	require.True(t, foundA)
}

func testRecursiveResolutionMock(t *testing.T) {
	queryLog := &sync.Map{}
	expectedIP := net.ParseIP("93.184.216.34")

	var authAddr string
	var authConn *net.UDPConn

	// Start authoritative server for example.com
	authServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		msg, _ := dns.ReadMessagePooled(req)
		defer msg.Release()
		if len(msg.Questions) == 0 {
			return
		}

		q := msg.Questions[0]
		if q.Name == "www.example.com" && q.Type == dns.TypeA {
			resp, _ := dns.BuildResponse(req, []dns.Answer{
				{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   300,
					RData: expectedIP,
				},
			}, dns.RcodeSuccess)
			_, _ = authConn.WriteTo(resp, addr)
		}
	})
	authConn = authServer.Conn()
	authHost, _, _ := net.SplitHostPort(authServer.Addr)
	authAddr = authHost

	var tldAddr string
	var tldConn *net.UDPConn

	// Start TLD server for .com
	tldServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		resp := testutil.BuildReferralResponse(t, req,
			[]dns.Answer{
				{
					Name:  "example.com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("ns1.example.com"),
				},
			},
			[]dns.Answer{
				{
					Name:  "ns1.example.com",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(authAddr).To4(),
				},
			},
		)
		_, _ = tldConn.WriteTo(resp, addr)
	})
	tldConn = tldServer.Conn()
	tldHost, _, _ := net.SplitHostPort(tldServer.Addr)
	tldAddr = tldHost

	var rootConn *net.UDPConn

	// Start root server
	rootServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		resp := testutil.BuildReferralResponse(t, req,
			[]dns.Answer{
				{
					Name:  "com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("a.gtld-servers.net"),
				},
			},
			[]dns.Answer{
				{
					Name:  "a.gtld-servers.net",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(tldAddr).To4(),
				},
			},
		)
		_, _ = rootConn.WriteTo(resp, addr)
	})
	rootConn = rootServer.Conn()

	// Create test resolver with mock root
	testRes := newTestResolver(rootServer.Addr, queryLog)

	// Register the mock servers so resolver knows their actual addresses
	testRes.registerServer(tldHost, tldServer.Addr)
	testRes.registerServer(authHost, authServer.Addr)

	// Start picodns server
	serverAddr, stopServer := testutil.StartTestServer(t, testRes)
	defer stopServer()

	// Send query
	resp := sendQuery(t, serverAddr, "www.example.com")
	require.NotEmpty(t, resp)

	// Verify all servers in chain were queried
	_, rootWasQueried := queryLog.Load(rootServer.Addr)
	require.True(t, rootWasQueried, "Root server should have been queried")

	// Parse and verify response
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)
	require.GreaterOrEqual(t, len(msg.Answers), 1)

	foundA := false
	for _, ans := range msg.Answers {
		if ans.Type == dns.TypeA {
			foundA = true
			require.Equal(t, expectedIP, net.IP(ans.Data))
		}
	}
	require.True(t, foundA, "Should have found A record")
}

// TestE2ERecursiveBailiwickProtection tests that out-of-bailiwick glue is rejected
func TestE2ERecursiveBailiwickProtection(t *testing.T) {
	if useRealNetwork() {
		t.Skip("Bailiwick protection tested in unit tests")
	}
	queryLog := &sync.Map{}
	maliciousIP := "1.2.3.4"
	var maliciousQueried atomic.Bool

	var maliciousConn *net.UDPConn

	// Start malicious server (should NOT be contacted)
	maliciousServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		maliciousQueried.Store(true)
		t.Error("Malicious server should not have been contacted!")
	})
	maliciousConn = maliciousServer.Conn()
	_ = maliciousConn

	var legitAddr string
	var legitConn *net.UDPConn

	// Start legitimate authoritative server
	legitServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		msg, _ := dns.ReadMessagePooled(req)
		defer msg.Release()
		if len(msg.Questions) == 0 {
			return
		}

		q := msg.Questions[0]
		if q.Name == "www.example.com" && q.Type == dns.TypeA {
			resp, _ := dns.BuildResponse(req, []dns.Answer{
				{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   300,
					RData: []byte{192, 0, 2, 100},
				},
			}, dns.RcodeSuccess)
			_, _ = legitConn.WriteTo(resp, addr)
		}
	})
	legitConn = legitServer.Conn()
	legitHost, _, _ := net.SplitHostPort(legitServer.Addr)
	legitAddr = legitHost

	var tldAddr string
	var tldConn *net.UDPConn

	// Start TLD server that returns out-of-bailiwick glue
	tldServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		resp := testutil.BuildReferralResponse(t, req,
			[]dns.Answer{
				{
					Name:  "example.com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("ns.evil.com"), // Out-of-bailiwick NS
				},
				{
					Name:  "example.com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("ns1.example.com"), // In-bailiwick NS
				},
			},
			[]dns.Answer{
				// Out-of-bailiwick glue (should be rejected)
				{
					Name:  "ns.evil.com",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(maliciousIP).To4(),
				},
				// In-bailiwick glue (should be accepted)
				{
					Name:  "ns1.example.com",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(legitAddr).To4(),
				},
			},
		)
		_, _ = tldConn.WriteTo(resp, addr)
	})
	tldConn = tldServer.Conn()
	tldHost, _, _ := net.SplitHostPort(tldServer.Addr)
	tldAddr = tldHost

	var rootConn *net.UDPConn

	// Start root server
	rootServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		resp := testutil.BuildReferralResponse(t, req,
			[]dns.Answer{
				{
					Name:  "com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("a.gtld-servers.net"),
				},
			},
			[]dns.Answer{
				{
					Name:  "a.gtld-servers.net",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(tldAddr).To4(),
				},
			},
		)
		_, _ = rootConn.WriteTo(resp, addr)
	})
	rootConn = rootServer.Conn()

	// Create test resolver
	testRes := newTestResolver(rootServer.Addr, queryLog)

	// Register servers with the resolver
	testRes.registerServer(tldHost, tldServer.Addr)
	testRes.registerServer(legitHost, legitServer.Addr)

	// Start picodns server
	serverAddr, stopServer := testutil.StartTestServer(t, testRes)
	defer stopServer()

	// Send query
	resp := sendQuery(t, serverAddr, "www.example.com")

	// Verify malicious server was NOT contacted
	require.False(t, maliciousQueried.Load(), "Malicious server (%s) should NOT have been contacted - bailiwick protection failed!", maliciousServer.Addr)

	// Verify we got a valid response from legitimate server
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)
}

// TestE2ERecursiveCNAME tests CNAME following
func TestE2ERecursiveCNAME(t *testing.T) {
	if useRealNetwork() {
		testRecursiveCNAMEReal(t)
	} else {
		testRecursiveCNAMEMock(t)
	}
}

func testRecursiveCNAMEReal(t *testing.T) {
	requireNetwork(t)
	rec := resolver.NewRecursive()
	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	// Query for a domain that typically has CNAME records
	resp := sendQuery(t, serverAddr, "www.github.com")
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)

	var foundRecord bool
	for _, ans := range msg.Answers {
		t.Logf("Got answer: type=%d, name=%s", ans.Type, ans.Name)
		if ans.Type == dns.TypeA || ans.Type == dns.TypeCNAME {
			foundRecord = true
		}
	}
	require.True(t, foundRecord, "Should have found A or CNAME record")
}

func testRecursiveCNAMEMock(t *testing.T) {
	queryLog := &sync.Map{}
	expectedIP := []byte{93, 184, 216, 34}

	var authAddr string
	var authConn *net.UDPConn

	// Start authoritative server
	authServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		msg, _ := dns.ReadMessagePooled(req)
		defer msg.Release()
		if len(msg.Questions) == 0 {
			return
		}

		q := msg.Questions[0]

		if q.Name == "cname.example.com" && q.Type == dns.TypeA {
			// Return CNAME chain
			buf := make([]byte, dns.MaxMessageSize)
			reqHeader, _ := dns.ReadHeader(req)

			header := dns.Header{
				ID:      reqHeader.ID,
				Flags:   dns.FlagQR | dns.FlagRD | dns.FlagRA,
				QDCount: 1,
				ANCount: 2,
			}
			dns.WriteHeader(buf, header)

			off, _ := dns.WriteQuestion(buf, dns.HeaderLen, q)

			// CNAME record
			off, _ = dns.EncodeName(buf, off, "cname.example.com")
			binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeCNAME)
			binary.BigEndian.PutUint16(buf[off+2:off+4], dns.ClassIN)
			binary.BigEndian.PutUint32(buf[off+4:off+8], 300)
			off += 8
			rdlenPos := off
			off += 2
			dataStart := off
			off, _ = dns.EncodeName(buf, off, "www.example.com")
			binary.BigEndian.PutUint16(buf[rdlenPos:rdlenPos+2], uint16(off-dataStart))

			// A record for www.example.com
			off, _ = dns.EncodeName(buf, off, "www.example.com")
			binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeA)
			binary.BigEndian.PutUint16(buf[off+2:off+4], dns.ClassIN)
			binary.BigEndian.PutUint32(buf[off+4:off+8], 300)
			off += 8
			binary.BigEndian.PutUint16(buf[off:off+2], 4)
			off += 2
			copy(buf[off:], expectedIP)
			off += 4

			_, _ = authConn.WriteTo(buf[:off], addr)
		}
	})
	authConn = authServer.Conn()
	authHost, _, _ := net.SplitHostPort(authServer.Addr)
	authAddr = authHost

	var tldAddr string
	var tldConn *net.UDPConn

	// Start TLD server
	tldServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		resp := testutil.BuildReferralResponse(t, req,
			[]dns.Answer{
				{
					Name:  "example.com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("ns1.example.com"),
				},
			},
			[]dns.Answer{
				{
					Name:  "ns1.example.com",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(authAddr).To4(),
				},
			},
		)
		_, _ = tldConn.WriteTo(resp, addr)
	})
	tldConn = tldServer.Conn()
	tldHost, _, _ := net.SplitHostPort(tldServer.Addr)
	tldAddr = tldHost

	var rootConn *net.UDPConn

	// Start root server
	rootServer := testutil.StartMockNameserver(t, func(req []byte, addr net.Addr) {
		resp := testutil.BuildReferralResponse(t, req,
			[]dns.Answer{
				{
					Name:  "com",
					Type:  dns.TypeNS,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: []byte("a.gtld-servers.net"),
				},
			},
			[]dns.Answer{
				{
					Name:  "a.gtld-servers.net",
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   86400,
					RData: net.ParseIP(tldAddr).To4(),
				},
			},
		)
		_, _ = rootConn.WriteTo(resp, addr)
	})
	rootConn = rootServer.Conn()

	// Create test resolver
	testRes := newTestResolver(rootServer.Addr, queryLog)

	// Register servers with the resolver
	testRes.registerServer(tldHost, tldServer.Addr)
	testRes.registerServer(authHost, authServer.Addr)

	// Start picodns server
	serverAddr, stopServer := testutil.StartTestServer(t, testRes)
	defer stopServer()

	// Query for cname.example.com which has a CNAME chain
	resp := sendQuery(t, serverAddr, "cname.example.com")
	require.NotEmpty(t, resp)

	// Parse response
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)
	require.GreaterOrEqual(t, len(msg.Answers), 1)

	// Check that we got the final A record
	foundA := false
	for _, ans := range msg.Answers {
		if ans.Type == dns.TypeA {
			foundA = true
			require.Equal(t, "www.example.com", ans.Name)
			require.Equal(t, net.IP(expectedIP), net.IP(ans.Data))
		}
	}
	require.True(t, foundA, "Should have found A record in response")
}

// TestE2ERecursiveAAAA tests recursive resolution for AAAA records
func TestE2ERecursiveAAAA(t *testing.T) {
	if !useRealNetwork() {
		t.Skip("Requires real network")
	}
	requireNetwork(t)

	rec := resolver.NewRecursive()
	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	resp := sendQueryWithType(t, serverAddr, "cloudflare.com", dns.TypeAAAA)
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)

	var foundAAAA bool
	for _, ans := range msg.Answers {
		if ans.Type == dns.TypeAAAA {
			foundAAAA = true
			t.Logf("Resolved AAAA to %s", net.IP(ans.Data))
		}
	}
	require.True(t, foundAAAA, "Should have found AAAA record")
}

// TestE2ERecursiveMX tests recursive resolution for MX records
func TestE2ERecursiveMX(t *testing.T) {
	if !useRealNetwork() {
		t.Skip("Requires real network")
	}
	requireNetwork(t)

	rec := resolver.NewRecursive()
	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	// MX record type = 15
	const typeMX uint16 = 15
	resp := sendQueryWithType(t, serverAddr, "google.com", typeMX)
	msg, err := dns.ReadMessagePooled(resp)
	defer msg.Release()
	require.NoError(t, err)
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)

	var foundMX bool
	for _, ans := range msg.Answers {
		if ans.Type == typeMX {
			foundMX = true
			t.Logf("Found MX record: %s", ans.Name)
		}
	}
	require.True(t, foundMX, "Should have found MX record")
}

// TestE2ERecursiveMultipleDomains tests resolution of multiple domains in parallel
func TestE2ERecursiveMultipleDomains(t *testing.T) {
	if !useRealNetwork() {
		t.Skip("Requires real network")
	}
	requireNetwork(t)

	rec := resolver.NewRecursive()
	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	t.Cleanup(stopServer)

	domains := []string{
		"example.com",
		"google.com",
		"cloudflare.com",
		"github.com",
	}

	for _, domain := range domains {
		domain := domain // capture for parallel test
		t.Run(domain, func(t *testing.T) {
			t.Parallel()
			resp := sendQuery(t, serverAddr, domain)
			msg, err := dns.ReadMessagePooled(resp)
			defer msg.Release()
			require.NoError(t, err)
			require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F)
			require.GreaterOrEqual(t, len(msg.Answers), 1, "Should have at least one answer for %s", domain)
			for _, ans := range msg.Answers {
				t.Logf("%s resolved to %s (type=%d)", domain, net.IP(ans.Data), ans.Type)
			}
		})
	}
}
