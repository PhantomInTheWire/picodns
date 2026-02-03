package resolver

import (
	"encoding/binary"
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
	dns.WriteHeader(buf, header)

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

	// Additional section: ns.evil.com A 1.2.3.4 (attack glue)
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
	dns.WriteHeader(buf, header)

	msg, err := dns.ReadMessage(buf[:off])
	require.NoError(t, err)

	nsNames, glueIPs := extractReferral(buf, msg, "example.com")

	// Should have one NS name
	require.Len(t, nsNames, 1)
	require.Equal(t, "ns.evil.com", nsNames[0])

	// Should have NO glue IPs (out-of-bailiwick should be ignored)
	require.Len(t, glueIPs, 0, "Out-of-bailiwick glue should be rejected")
}
