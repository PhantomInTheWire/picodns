package resolver

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"picodns/internal/dns"
	"picodns/tests/testutil/dnstest"
)

func TestExtractReferral_InBailiwick(t *testing.T) {
	req := dnstest.MakeQuery("example.com", dns.TypeA)
	buf := dnstest.BuildReferralResponse(t, req,
		[]dns.Answer{dnstest.NSRecord("example.com", "ns1.example.com", 86400)},
		[]dns.Answer{dnstest.ARecord("ns1.example.com", net.ParseIP("192.0.2.1"), 86400)},
	)

	msg, err := dns.ReadMessagePooled(buf)
	require.NoError(t, err)
	defer msg.Release()

	nsNames, glueIPs := extractReferral(buf, *msg, "example.com")

	require.Len(t, nsNames, 1)
	require.Equal(t, "ns1.example.com", nsNames[0])
	require.Len(t, glueIPs, 1)
	require.Equal(t, "192.0.2.1:53", glueIPs[0])
}

func TestExtractReferral_OutOfBailiwick(t *testing.T) {
	req := dnstest.MakeQuery("example.com", dns.TypeA)
	buf := dnstest.BuildReferralResponse(t, req,
		[]dns.Answer{dnstest.NSRecord("example.com", "ns.evil.com", 86400)},
		[]dns.Answer{dnstest.ARecord("ns.evil.com", net.ParseIP("1.2.3.4"), 86400)},
	)

	msg, err := dns.ReadMessagePooled(buf)
	require.NoError(t, err)
	defer msg.Release()

	nsNames, glueIPs := extractReferral(buf, *msg, "example.com")

	require.Len(t, nsNames, 1)
	require.Equal(t, "ns.evil.com", nsNames[0])
	require.Len(t, glueIPs, 0) // Out-of-bailiwick glue should be ignored
}

type cnameStep struct {
	owner  string
	target string
}

func TestCnameLoopDetection(t *testing.T) {
	tests := []struct {
		name       string
		cnameChain []cnameStep
		shouldLoop bool
	}{
		{
			name:       "mutual_cname_is_loop",
			shouldLoop: true,
			cnameChain: []cnameStep{
				{owner: "alias1.example.com", target: "alias2.example.com"},
				{owner: "alias2.example.com", target: "alias1.example.com"},
				{owner: "alias1.example.com", target: "alias2.example.com"},
			},
		},
		{
			name:       "actual_loop_detected",
			shouldLoop: true,
			cnameChain: []cnameStep{
				{owner: "alias1.example.com", target: "alias2.example.com"},
				{owner: "alias2.example.com", target: "alias3.example.com"},
				{owner: "alias3.example.com", target: "alias1.example.com"},
				{owner: "alias1.example.com", target: "alias2.example.com"},
			},
		},
		{
			name:       "long_chain_no_loop",
			shouldLoop: false,
			cnameChain: []cnameStep{
				{owner: "a.example.com", target: "b.example.com"},
				{owner: "b.example.com", target: "c.example.com"},
				{owner: "c.example.com", target: "d.example.com"},
				{owner: "d.example.com", target: "final.example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seenCnames := make(map[string]struct{})
			loopDetected := false

			for _, step := range tt.cnameChain {
				// Real code uses: seenCnames[cnameTarget]
				if _, seen := seenCnames[step.target]; seen {
					loopDetected = true
					break
				}
				seenCnames[step.target] = struct{}{}
			}

			if tt.shouldLoop {
				require.True(t, loopDetected)
			} else {
				require.False(t, loopDetected)
			}
		})
	}
}

func TestExtractReferral_CaseInsensitiveCNAME(t *testing.T) {
	buf := make([]byte, dns.MaxMessageSize)
	off := dns.HeaderLen

	off, _ = dns.EncodeName(buf, off, "www.example.com")
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeA)
	binary.BigEndian.PutUint16(buf[off+2:off+4], dns.ClassIN)
	off += 4

	off, _ = dns.EncodeName(buf, off, "WWW.EXAMPLE.COM")
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeCNAME)
	off += 2
	binary.BigEndian.PutUint16(buf[off:off+2], dns.ClassIN)
	off += 2
	binary.BigEndian.PutUint32(buf[off:off+4], 86400)
	off += 4
	rdlenPos := off
	off += 2
	cnameDataStart := off
	off, _ = dns.EncodeName(buf, off, "target.example.com")
	cnameDataLen := off - cnameDataStart
	binary.BigEndian.PutUint16(buf[rdlenPos:rdlenPos+2], uint16(cnameDataLen))

	header := dns.Header{
		ID:      1,
		Flags:   dns.FlagQR,
		QDCount: 1,
		ANCount: 1,
	}
	err := dns.WriteHeader(buf, header)
	require.NoError(t, err)

	msg, err := dns.ReadMessagePooled(buf[:off])
	require.NoError(t, err)
	defer msg.Release()
	require.Len(t, msg.Answers, 1)

	ans := msg.Answers[0]
	require.Equal(t, dns.TypeCNAME, ans.Type)
	require.Equal(t, "WWW.EXAMPLE.COM", ans.Name)

	cnameTarget := dns.ExtractNameFromData(buf, ans.DataOffset)
	require.Equal(t, "target.example.com", cnameTarget)

	queryName := "www.example.com"
	cnameOwner := ans.Name
	matchedCaseSensitive := cnameOwner == queryName || cnameOwner == queryName+"."
	require.False(t, matchedCaseSensitive)

	matchedCaseInsensitive := strings.EqualFold(cnameOwner, queryName) ||
		strings.EqualFold(cnameOwner, queryName+".")
	require.True(t, matchedCaseInsensitive)
}
