// Package dnstest provides DNS test utilities that can be imported by any test.
// This package has no dependencies on resolver, avoiding import cycles.
package dnstest

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"picodns/internal/dns"
)

// Answer creates a DNS answer for testing
func Answer(name string, rtype uint16, ttl uint32, rdata []byte) dns.Answer {
	return dns.Answer{
		Name:  name,
		Type:  rtype,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: rdata,
	}
}

// NSRecord creates an NS record for testing
func NSRecord(zone, nsName string, ttl uint32) dns.Answer {
	return Answer(zone, dns.TypeNS, ttl, []byte(nsName))
}

// ARecord creates an A record for testing
func ARecord(name string, ip net.IP, ttl uint32) dns.Answer {
	return Answer(name, dns.TypeA, ttl, ip.To4())
}

// CNAMERecord creates a CNAME record for testing
func CNAMERecord(name, target string, ttl uint32) dns.Answer {
	return Answer(name, dns.TypeCNAME, ttl, []byte(target))
}

// AAAARecord creates an AAAA record for testing
func AAAARecord(name string, ip net.IP, ttl uint32) dns.Answer {
	return Answer(name, dns.TypeAAAA, ttl, ip.To16())
}

// MakeQuery creates a DNS query for testing
func MakeQuery(name string, qtype uint16) []byte {
	buf := make([]byte, 512)
	_ = dns.WriteHeader(buf, dns.Header{ID: 0xBEEF, Flags: 0x0100, QDCount: 1})
	end, _ := dns.WriteQuestion(buf, dns.HeaderLen, dns.Question{Name: name, Type: qtype, Class: dns.ClassIN})
	return buf[:end]
}

// BuildReferralResponse creates a DNS referral response for testing
func BuildReferralResponse(t *testing.T, req []byte, nsRecords []dns.Answer, glueRecords []dns.Answer) []byte {
	buf := make([]byte, dns.MaxMessageSize)

	reqHeader, err := dns.ReadHeader(req)
	require.NoError(t, err, "BuildReferralResponse: failed to read header")
	q, _, err := dns.ReadQuestion(req, dns.HeaderLen)
	require.NoError(t, err, "BuildReferralResponse: failed to read question")

	header := dns.Header{
		ID:      reqHeader.ID,
		Flags:   dns.FlagQR | dns.FlagRD | dns.FlagRA,
		QDCount: 1,
		NSCount: uint16(len(nsRecords)),
		ARCount: uint16(len(glueRecords)),
	}
	err = dns.WriteHeader(buf, header)
	require.NoError(t, err, "BuildReferralResponse: failed to write header")

	off, err := dns.WriteQuestion(buf, dns.HeaderLen, q)
	require.NoError(t, err, "BuildReferralResponse: failed to write question")

	for _, ns := range nsRecords {
		off, err = writeRecord(buf, off, ns)
		require.NoError(t, err, "BuildReferralResponse: failed to write authority")
	}

	for _, glue := range glueRecords {
		off, err = writeRecord(buf, off, glue)
		require.NoError(t, err, "BuildReferralResponse: failed to write additional")
	}

	return buf[:off]
}

func writeRecord(buf []byte, off int, rec dns.Answer) (int, error) {
	off, err := dns.EncodeName(buf, off, rec.Name)
	if err != nil {
		return off, err
	}
	binary.BigEndian.PutUint16(buf[off:off+2], rec.Type)
	binary.BigEndian.PutUint16(buf[off+2:off+4], dns.ClassIN)
	binary.BigEndian.PutUint32(buf[off+4:off+8], rec.TTL)
	off += 8

	if rec.Type == dns.TypeNS {
		rdlenPos := off
		off += 2
		dataStart := off
		off, err = dns.EncodeName(buf, off, string(rec.RData))
		if err != nil {
			return off, err
		}
		binary.BigEndian.PutUint16(buf[rdlenPos:rdlenPos+2], uint16(off-dataStart))
	} else {
		binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(rec.RData)))
		off += 2
		copy(buf[off:], rec.RData)
		off += len(rec.RData)
	}
	return off, nil
}

// AssertSuccessfulResponse parses a DNS response and asserts it was successful
func AssertSuccessfulResponse(t *testing.T, resp []byte) *dns.Message {
	msg, err := dns.ReadMessagePooled(resp)
	require.NoError(t, err, "Failed to parse DNS response")
	require.Equal(t, uint16(dns.RcodeSuccess), msg.Header.Flags&0x000F, "Expected successful response")
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
