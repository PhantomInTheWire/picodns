package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
	"picodns/tests/testutil"
)

func isValidIPv4(data []byte) bool {
	return len(data) == 4
}

func TestE2EForwardAndCache(t *testing.T) {
	requireNetwork(t)

	upstreamServers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	serverAddr, stopServer := testutil.StartServerWithUpstreams(t, upstreamServers)
	defer stopServer()

	start1 := time.Now()
	resp1 := sendQuery(t, serverAddr, "example.com")
	duration1 := time.Since(start1)
	msg1, err := dns.ReadMessagePooled(resp1)
	require.NoError(t, err, "Failed to parse first DNS response")

	require.True(t, msg1.Header.Flags&0x8000 != 0, "QR bit should be set (response)")
	require.GreaterOrEqual(t, msg1.Header.ANCount, uint16(1), "Should have at least 1 answer")
	require.Equal(t, uint16(dns.RcodeSuccess), msg1.Header.Flags&0x000F, "Should have NOERROR rcode")

	require.GreaterOrEqual(t, len(msg1.Answers), 1, "Should have at least 1 answer")
	answer := msg1.Answers[0]
	require.Equal(t, dns.TypeA, answer.Type, "Answer should be Type A")
	require.Equal(t, dns.ClassIN, answer.Class, "Answer should be Class IN")
	require.True(t, isValidIPv4(answer.Data), "Answer RData should be a valid IPv4 address")

	start2 := time.Now()
	resp2 := sendQuery(t, serverAddr, "example.com")
	duration2 := time.Since(start2)
	msg2, err := dns.ReadMessagePooled(resp2)
	require.NoError(t, err, "Failed to parse second DNS response")

	require.Equal(t, msg1.Header.Flags, msg2.Header.Flags)
	require.Equal(t, msg1.Header.ANCount, msg2.Header.ANCount)
	require.GreaterOrEqual(t, len(msg2.Answers), 1)
	require.True(t, isValidIPv4(msg2.Answers[0].Data))

	require.Less(t, duration2, duration1/2, "Cached query should be significantly faster")
}

func TestE2ENegativeCache(t *testing.T) {
	requireNetwork(t)

	upstreamServers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	serverAddr, stopServer := testutil.StartServerWithUpstreams(t, upstreamServers)
	defer stopServer()

	start1 := time.Now()
	resp1 := sendQuery(t, serverAddr, "this-definitely-does-not-exist-12345.example")
	duration1 := time.Since(start1)
	msg1, err := dns.ReadMessagePooled(resp1)
	require.NoError(t, err, "Failed to parse first DNS response")

	require.True(t, msg1.Header.Flags&0x8000 != 0, "QR bit should be set (response)")
	require.Equal(t, uint16(dns.RcodeNXDomain), msg1.Header.Flags&0x000F, "Should have NXDOMAIN rcode")
	require.Equal(t, uint16(0), msg1.Header.ANCount, "Should have 0 answers")

	start2 := time.Now()
	resp2 := sendQuery(t, serverAddr, "this-definitely-does-not-exist-12345.example")
	duration2 := time.Since(start2)
	msg2, err := dns.ReadMessagePooled(resp2)
	require.NoError(t, err, "Failed to parse second DNS response")

	require.Equal(t, msg1.Header.Flags, msg2.Header.Flags, "Cached response flags should match")
	require.Equal(t, msg1.Header.ANCount, msg2.Header.ANCount, "Cached ANCount should match")
	require.Equal(t, msg1.Header.NSCount, msg2.Header.NSCount, "Cached NSCount should match")

	require.Less(t, duration2, duration1/2, "Cached query should be significantly faster")
}

func sendQuery(t *testing.T, addr string, name string) []byte {
	return sendQueryWithType(t, addr, name, dns.TypeA)
}

func sendQueryWithType(t *testing.T, addr string, name string, qtype uint16) []byte {
	conn, err := net.Dial("udp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	req := makeQueryWithType(name, qtype)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = conn.Write(req)
	require.NoError(t, err)

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	require.NoError(t, err)
	return respBuf[:n]
}

func makeQuery(name string) []byte {
	return makeQueryWithType(name, dns.TypeA)
}

func makeQueryWithType(name string, qtype uint16) []byte {
	buf := make([]byte, 512)
	_ = dns.WriteHeader(buf, dns.Header{ID: 0xBEEF, Flags: 0x0100, QDCount: 1})
	end, _ := dns.WriteQuestion(buf, dns.HeaderLen, dns.Question{Name: name, Type: qtype, Class: dns.ClassIN})
	return buf[:end]
}
