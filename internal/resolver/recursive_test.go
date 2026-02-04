package resolver

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"picodns/internal/dns"
)

func TestExtractReferral_InBailiwick(t *testing.T) {
	// Build a DNS message with in-bailiwick glue
	// example.com NS ns1.example.com
	// ns1.example.com A 192.0.2.1

	buf := make([]byte, dns.MaxMessageSize)
	off := dns.HeaderLen

	// Question section
	off, _ = dns.EncodeName(buf, off, "example.com")
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeA)
	binary.BigEndian.PutUint16(buf[off+2:off+4], dns.ClassIN)
	off += 4

	// Authority section: example.com NS ns1.example.com
	// Owner name
	off, _ = dns.EncodeName(buf, off, "example.com")
	// Type NS
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeNS)
	off += 2
	// Class IN
	binary.BigEndian.PutUint16(buf[off:off+2], dns.ClassIN)
	off += 2
	// TTL
	binary.BigEndian.PutUint32(buf[off:off+4], 86400)
	off += 4
	// Save position for RDLENGTH, encode NS target, then fill in length
	rdlenPos := off
	off += 2
	nsDataStart := off
	off, _ = dns.EncodeName(buf, off, "ns1.example.com")
	nsDataLen := off - nsDataStart
	binary.BigEndian.PutUint16(buf[rdlenPos:rdlenPos+2], uint16(nsDataLen))

	// Additional section: ns1.example.com A 192.0.2.1
	off, _ = dns.EncodeName(buf, off, "ns1.example.com")
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeA)
	off += 2
	binary.BigEndian.PutUint16(buf[off:off+2], dns.ClassIN)
	off += 2
	binary.BigEndian.PutUint32(buf[off:off+4], 86400)
	off += 4
	binary.BigEndian.PutUint16(buf[off:off+2], 4) // IP address length
	off += 2
	copy(buf[off:off+4], []byte{192, 0, 2, 1})
	off += 4

	// Set header
	header := dns.Header{
		ID:      1,
		Flags:   dns.FlagQR,
		QDCount: 1,
		NSCount: 1,
		ARCount: 1,
	}
	err := dns.WriteHeader(buf, header)
	require.NoError(t, err)

	msg, err := dns.ReadMessage(buf[:off])
	require.NoError(t, err)

	nsNames, glueIPs := extractReferral(buf, msg, "example.com")

	// Should have one NS name
	require.Len(t, nsNames, 1)
	require.Equal(t, "ns1.example.com", nsNames[0])

	// Should have glue IP (in-bailiwick)
	require.Len(t, glueIPs, 1)
	require.Equal(t, "192.0.2.1:53", glueIPs[0])
}

func TestExtractReferral_OutOfBailiwick(t *testing.T) {
	// Build a DNS message with out-of-bailiwick glue (attack scenario)
	// example.com NS ns.evil.com
	// ns.evil.com A 1.2.3.4 (should be ignored)

	buf := make([]byte, dns.MaxMessageSize)
	off := dns.HeaderLen

	// Question section
	off, _ = dns.EncodeName(buf, off, "example.com")
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeA)
	binary.BigEndian.PutUint16(buf[off+2:off+4], dns.ClassIN)
	off += 4

	// Authority section: example.com NS ns.evil.com
	// Owner name
	off, _ = dns.EncodeName(buf, off, "example.com")
	// Type NS
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeNS)
	off += 2
	// Class IN
	binary.BigEndian.PutUint16(buf[off:off+2], dns.ClassIN)
	off += 2
	// TTL
	binary.BigEndian.PutUint32(buf[off:off+4], 86400)
	off += 4
	// Save position for RDLENGTH, encode NS target, then fill in length
	rdlenPos := off
	off += 2
	nsDataStart := off
	off, _ = dns.EncodeName(buf, off, "ns.evil.com")
	nsDataLen := off - nsDataStart
	binary.BigEndian.PutUint16(buf[rdlenPos:rdlenPos+2], uint16(nsDataLen))

	// Additional section: ns.evil.com A 1.2.3.4 (out-of-bailiwick, should be ignored)
	off, _ = dns.EncodeName(buf, off, "ns.evil.com")
	binary.BigEndian.PutUint16(buf[off:off+2], dns.TypeA)
	off += 2
	binary.BigEndian.PutUint16(buf[off:off+2], dns.ClassIN)
	off += 2
	binary.BigEndian.PutUint32(buf[off:off+4], 86400)
	off += 4
	binary.BigEndian.PutUint16(buf[off:off+2], 4) // IP address length
	off += 2
	copy(buf[off:off+4], []byte{1, 2, 3, 4})
	off += 4

	// Set header
	header := dns.Header{
		ID:      1,
		Flags:   dns.FlagQR,
		QDCount: 1,
		NSCount: 1,
		ARCount: 1,
	}
	err := dns.WriteHeader(buf, header)
	require.NoError(t, err)

	msg, err := dns.ReadMessage(buf[:off])
	require.NoError(t, err)

	nsNames, glueIPs := extractReferral(buf, msg, "example.com")

	// Should have one NS name
	require.Len(t, nsNames, 1)
	require.Equal(t, "ns.evil.com", nsNames[0])

	// Should have NO glue IPs (out-of-bailiwick should be ignored)
	require.Len(t, glueIPs, 0)
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
			name:       "valid_mutual_cname_no_loop",
			shouldLoop: false,
			cnameChain: []cnameStep{
				{owner: "alias1.example.com", target: "alias2.example.com"},
				{owner: "alias2.example.com", target: "alias1.example.com"},
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
		{
			name:       "different_owners_same_target",
			shouldLoop: false,
			cnameChain: []cnameStep{
				{owner: "alias1.example.com", target: "common.example.com"},
				{owner: "alias2.example.com", target: "common.example.com"},
				{owner: "common.example.com", target: "final.example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seenCnames := make(map[string]struct{})
			loopDetected := false

			for _, step := range tt.cnameChain {
				cnameKey := step.owner + "->" + step.target
				if _, seen := seenCnames[cnameKey]; seen {
					loopDetected = true
					break
				}
				seenCnames[cnameKey] = struct{}{}
			}

			if tt.shouldLoop {
				require.True(t, loopDetected)
			} else {
				require.False(t, loopDetected)
			}
		})
	}
}

func TestCnameLoopDetectionKeyFormat(t *testing.T) {
	seenCnames := make(map[string]struct{})
	key1 := "alias1.example.com->alias2.example.com"
	seenCnames[key1] = struct{}{}

	_, exists := seenCnames[key1]
	require.True(t, exists)

	key2 := "alias2.example.com->alias1.example.com"
	_, exists = seenCnames[key2]
	require.False(t, exists)

	seenCnames[key2] = struct{}{}
	require.Len(t, seenCnames, 2)
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

	msg, err := dns.ReadMessage(buf[:off])
	require.NoError(t, err)
	require.Len(t, msg.Answers, 1)

	ans := msg.Answers[0]
	require.Equal(t, dns.TypeCNAME, ans.Type)
	require.Equal(t, "WWW.EXAMPLE.COM", ans.Name)

	cnameTarget := extractNameFromData(buf, ans.DataOffset)
	require.Equal(t, "target.example.com", cnameTarget)

	queryName := "www.example.com"
	cnameOwner := ans.Name
	matchedCaseSensitive := cnameOwner == queryName || cnameOwner == queryName+"."
	require.False(t, matchedCaseSensitive)

	matchedCaseInsensitive := strings.EqualFold(cnameOwner, queryName) ||
		strings.EqualFold(cnameOwner, queryName+".")
	require.True(t, matchedCaseInsensitive)
}
