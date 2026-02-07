package e2e

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
	"picodns/internal/resolver"
	"picodns/tests/testutil"
	"picodns/tests/testutil/dnstest"
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
	_ = conn.Close()
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
	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()

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
	expectedIP := net.ParseIP("93.184.216.34")
	transport := testutil.NewMockTransport()

	hierarchy := testutil.NewTransportMockHierarchy(t, transport).
		WithRoot("com", "a.gtld-servers.net", "192.0.2.5").
		WithTLD("example.com", "ns1.example.com", "192.0.2.10").
		WithAuthority("www.example.com", []dns.Answer{
			dnstest.ARecord("www.example.com", expectedIP, 300),
		})

	rec := resolver.NewRecursive(
		resolver.WithRootServers([]string{hierarchy.RootAddr()}),
		resolver.WithTransport(transport),
	)

	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	resp := sendQuery(t, serverAddr, "www.example.com")
	require.NotEmpty(t, resp)
	require.True(t, transport.WasQueried(hierarchy.RootAddr()), "Root server should have been queried")

	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()
	require.GreaterOrEqual(t, len(msg.Answers), 1)

	foundA := false
	for _, ans := range msg.Answers {
		if ans.Type == dns.TypeA {
			foundA = true
			require.Equal(t, expectedIP.To4(), net.IP(ans.Data).To4())
		}
	}
	require.True(t, foundA, "Should have found A record")
}

// TestE2ERecursiveBailiwickProtection tests that out-of-bailiwick glue is rejected.
// It sets up a TLD handler that attempts to provide glue for a nameserver
// outside its delegated domain (ns.evil.com for example.com).
func TestE2ERecursiveBailiwickProtection(t *testing.T) {

	maliciousIP := "1.2.3.4"
	var maliciousQueried atomic.Bool
	transport := testutil.NewMockTransport()

	transport.RegisterHandler("192.0.2.1:53", func(req []byte) ([]byte, error) {
		return dnstest.BuildReferralResponse(t, req,
			[]dns.Answer{dnstest.NSRecord("com", "a.gtld-servers.net", 86400)},
			[]dns.Answer{dnstest.ARecord("a.gtld-servers.net", net.ParseIP("192.0.2.5"), 86400)},
		), nil
	})

	transport.RegisterHandler("192.0.2.5:53", func(req []byte) ([]byte, error) {
		return dnstest.BuildReferralResponse(t, req,
			[]dns.Answer{
				dnstest.NSRecord("example.com", "ns.evil.com", 86400),
				dnstest.NSRecord("example.com", "ns1.example.com", 86400),
			},
			[]dns.Answer{
				dnstest.ARecord("ns.evil.com", net.ParseIP(maliciousIP), 86400),
				dnstest.ARecord("ns1.example.com", net.ParseIP("192.0.2.10"), 86400),
			},
		), nil
	})

	transport.RegisterHandler("192.0.2.10:53", func(req []byte) ([]byte, error) {
		return dns.BuildResponse(req, []dns.Answer{
			dnstest.ARecord("www.example.com", net.ParseIP("192.0.2.100"), 300),
		}, dns.RcodeSuccess)
	})

	transport.RegisterHandler(maliciousIP+":53", func(req []byte) ([]byte, error) {
		maliciousQueried.Store(true)
		return nil, nil
	})

	rec := resolver.NewRecursive(
		resolver.WithRootServers([]string{"192.0.2.1:53"}),
		resolver.WithTransport(transport),
	)

	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	resp := sendQuery(t, serverAddr, "www.example.com")
	require.False(t, maliciousQueried.Load(), "Malicious server should NOT have been contacted")
	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()
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

	resp := sendQuery(t, serverAddr, "www.github.com")
	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()

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
	expectedIP := net.ParseIP("93.184.216.34")
	transport := testutil.NewMockTransport()

	hierarchy := testutil.NewTransportMockHierarchy(t, transport).
		WithRoot("com", "a.gtld-servers.net", "192.0.2.5").
		WithTLD("example.com", "ns1.example.com", "192.0.2.10").
		WithAuthority("cname.example.com", []dns.Answer{
			dnstest.CNAMERecord("cname.example.com", "www.example.com", 300),
			dnstest.ARecord("www.example.com", expectedIP, 300),
		})

	rec := resolver.NewRecursive(
		resolver.WithRootServers([]string{hierarchy.RootAddr()}),
		resolver.WithTransport(transport),
	)

	serverAddr, stopServer := testutil.StartServerWithResolver(t, rec)
	defer stopServer()

	resp := sendQuery(t, serverAddr, "cname.example.com")
	require.NotEmpty(t, resp)

	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()
	require.GreaterOrEqual(t, len(msg.Answers), 1)

	foundA := false
	for _, ans := range msg.Answers {
		if ans.Type == dns.TypeA {
			foundA = true
			require.Equal(t, "www.example.com", ans.Name)
			require.Equal(t, expectedIP.To4(), net.IP(ans.Data).To4())
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
	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()

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

	const typeMX uint16 = 15
	resp := sendQueryWithType(t, serverAddr, "google.com", typeMX)
	msg := dnstest.AssertSuccessfulResponse(t, resp)
	defer msg.Release()

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
			msg := dnstest.AssertSuccessfulResponse(t, resp)
			defer msg.Release()
			require.GreaterOrEqual(t, len(msg.Answers), 1, "Should have at least one answer for %s", domain)
			for _, ans := range msg.Answers {
				t.Logf("%s resolved to %s (type=%d)", domain, net.IP(ans.Data), ans.Type)
			}
		})
	}
}
