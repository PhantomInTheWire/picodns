package testutil

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
)

// NSRecord creates an NS record answer
func NSRecord(zone, nsName string, ttl uint32) dns.Answer {
	return dns.Answer{
		Name:  zone,
		Type:  dns.TypeNS,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: []byte(nsName),
	}
}

// ARecord creates an A record answer
func ARecord(name string, ip net.IP, ttl uint32) dns.Answer {
	return dns.Answer{
		Name:  name,
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: ip.To4(),
	}
}

// CNAMERecord creates a CNAME record answer
func CNAMERecord(name, target string, ttl uint32) dns.Answer {
	return dns.Answer{
		Name:  name,
		Type:  dns.TypeCNAME,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: []byte(target),
	}
}

// AAAARecord creates an AAAA record answer
func AAAARecord(name string, ip net.IP, ttl uint32) dns.Answer {
	return dns.Answer{
		Name:  name,
		Type:  dns.TypeAAAA,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: ip.To16(),
	}
}

// MXRecord creates an MX record answer
func MXRecord(t *testing.T, name string, preference uint16, exchange string, ttl uint32) dns.Answer {
	// MX record format: 2 bytes preference + DNS-encoded domain name
	// Use a buffer large enough for the encoded name (max 255 bytes + 2 for preference)
	buf := make([]byte, 257)
	binary.BigEndian.PutUint16(buf[0:2], preference)
	off, err := dns.EncodeName(buf, 2, exchange)
	require.NoError(t, err, "Failed to encode MX exchange name: %s", exchange)
	return dns.Answer{
		Name:  name,
		Type:  dns.TypeMX,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: buf[:off],
	}
}

// TXTRecord creates a TXT record answer
func TXTRecord(name, text string, ttl uint32) dns.Answer {
	return dns.Answer{
		Name:  name,
		Type:  dns.TypeTXT,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: []byte(text),
	}
}

// SOARecord creates an SOA record answer following RFC 1035
// SOA format: MNAME (DNS name) + RNAME (DNS name) + SERIAL + REFRESH + RETRY + EXPIRE + MINIMUM
func SOARecord(t *testing.T, zone, mname, rname string, serial, refresh, retry, expire, minimum uint32, ttl uint32) dns.Answer {
	// RFC 1035 SOA record encoding with proper DNS name format
	data := make([]byte, 512)
	off := 0
	var err error

	// Encode MNAME (primary nameserver)
	off, err = dns.EncodeName(data, off, mname)
	require.NoError(t, err, "Failed to encode SOA MNAME: %s", mname)

	// Encode RNAME (responsible party email, with @ replaced by .)
	off, err = dns.EncodeName(data, off, rname)
	require.NoError(t, err, "Failed to encode SOA RNAME: %s", rname)

	// Append 5 uint32 fields (20 bytes)
	require.Less(t, off, len(data)-20, "SOA record buffer overflow")
	binary.BigEndian.PutUint32(data[off:off+4], serial)
	binary.BigEndian.PutUint32(data[off+4:off+8], refresh)
	binary.BigEndian.PutUint32(data[off+8:off+12], retry)
	binary.BigEndian.PutUint32(data[off+12:off+16], expire)
	binary.BigEndian.PutUint32(data[off+16:off+20], minimum)
	off += 20

	return dns.Answer{
		Name:  zone,
		Type:  dns.TypeSOA,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: data[:off],
	}
}

// BuildReferralResponse creates a DNS referral response with authority and additional sections
func BuildReferralResponse(t *testing.T, req []byte, nsRecords []dns.Answer, glueRecords []dns.Answer) []byte {
	buf := make([]byte, dns.MaxMessageSize)

	reqHeader, err := dns.ReadHeader(req)
	if err != nil {
		t.Fatalf("BuildReferralResponse: failed to read header: %v", err)
	}
	q, _, err := dns.ReadQuestion(req, dns.HeaderLen)
	if err != nil {
		t.Fatalf("BuildReferralResponse: failed to read question: %v", err)
	}

	// Write header (QR=1, AA=0 - not authoritative, it's a referral)
	header := dns.Header{
		ID:      reqHeader.ID,
		Flags:   dns.FlagQR | dns.FlagRD | dns.FlagRA,
		QDCount: 1,
		NSCount: uint16(len(nsRecords)),
		ARCount: uint16(len(glueRecords)),
	}
	dns.WriteHeader(buf, header)

	// Write question section
	off, err := dns.WriteQuestion(buf, dns.HeaderLen, q)
	if err != nil {
		t.Fatalf("BuildReferralResponse: failed to write question: %v", err)
	}

	// Write authority section (NS records)
	for _, ns := range nsRecords {
		off, err = dns.EncodeName(buf, off, ns.Name)
		if err != nil {
			t.Fatalf("BuildReferralResponse: failed to encode NS name: %v", err)
		}
		binary.BigEndian.PutUint16(buf[off:off+2], ns.Type)
		binary.BigEndian.PutUint16(buf[off+2:off+4], ns.Class)
		binary.BigEndian.PutUint32(buf[off+4:off+8], ns.TTL)
		off += 8

		rdlenPos := off
		off += 2
		dataStart := off
		off, err = dns.EncodeName(buf, off, string(ns.RData))
		if err != nil {
			t.Fatalf("BuildReferralResponse: failed to encode NS RData: %v", err)
		}
		binary.BigEndian.PutUint16(buf[rdlenPos:rdlenPos+2], uint16(off-dataStart))
	}

	// Write additional section (glue A records)
	for _, glue := range glueRecords {
		off, err = dns.EncodeName(buf, off, glue.Name)
		if err != nil {
			t.Fatalf("BuildReferralResponse: failed to encode glue name: %v", err)
		}
		binary.BigEndian.PutUint16(buf[off:off+2], glue.Type)
		binary.BigEndian.PutUint16(buf[off+2:off+4], glue.Class)
		binary.BigEndian.PutUint32(buf[off+4:off+8], glue.TTL)
		off += 8
		binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(glue.RData)))
		off += 2
		copy(buf[off:], glue.RData)
		off += len(glue.RData)
	}

	return buf[:off]
}

// AssertSuccessfulResponse parses a DNS response and asserts it was successful
// Returns the parsed message (caller must call msg.Release() when done)
func AssertSuccessfulResponse(t *testing.T, resp []byte) *dns.Message {
	msg, err := dns.ReadMessagePooled(resp)
	require.NoError(t, err, "Failed to parse DNS response")
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F, "Expected successful response")
	return msg
}

// AssertResponseCode parses a DNS response and asserts it has the expected response code
// Returns the parsed message (caller must call msg.Release() when done)
func AssertResponseCode(t *testing.T, resp []byte, expectedRcode uint16) *dns.Message {
	msg, err := dns.ReadMessagePooled(resp)
	require.NoError(t, err, "Failed to parse DNS response")
	require.Equal(t, expectedRcode, msg.Header.Flags&0x000F, "Unexpected response code")
	return msg
}

// HasRecordType checks if the message contains an answer of the specified type
func HasRecordType(msg *dns.Message, recordType uint16) bool {
	for _, ans := range msg.Answers {
		if ans.Type == recordType {
			return true
		}
	}
	return false
}

// GetRecordsByType returns all answers of the specified type
func GetRecordsByType(msg *dns.Message, recordType uint16) []dns.ResourceRecord {
	var results []dns.ResourceRecord
	for _, ans := range msg.Answers {
		if ans.Type == recordType {
			results = append(results, ans)
		}
	}
	return results
}
