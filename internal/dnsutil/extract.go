// Package dnsutil provides helper functions for DNS name manipulation and extraction.
package dnsutil

import (
	"encoding/binary"
	"strings"

	"picodns/internal/dns"
)

// ExtractNameFromData extracts a domain name from resource record data,
// using the full message buffer to resolve compression pointers.
func ExtractNameFromData(fullMsg []byte, dataOffset int) string {
	if len(fullMsg) == 0 || dataOffset >= len(fullMsg) {
		return ""
	}
	name, _, err := dns.DecodeName(fullMsg, dataOffset)
	if err != nil {
		return ""
	}
	return name
}

// BuildQuery constructs a DNS query message for the given name, type, and class.
// Returns the serialized query as a byte slice.
func BuildQuery(id uint16, name string, qtype, qclass uint16) ([]byte, error) {
	labelCount := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labelCount++
		}
	}
	if len(name) > 0 && !strings.HasSuffix(name, ".") {
		labelCount++
	}

	buf := make([]byte, dns.HeaderLen+len(name)+labelCount+1+4)

	header := dns.Header{
		ID:      id,
		Flags:   dns.FlagRD,
		QDCount: 1,
	}
	if err := dns.WriteHeader(buf, header); err != nil {
		return nil, err
	}

	off := dns.HeaderLen
	off, err := dns.EncodeName(buf, off, name)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(buf[off:off+2], qtype)
	binary.BigEndian.PutUint16(buf[off+2:off+4], qclass)
	off += 4

	return buf[:off], nil
}
