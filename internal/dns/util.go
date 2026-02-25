package dns

import (
	"encoding/binary"
	"strings"
)

// NormalizeName returns a normalized domain name (lowercase, no trailing dot).
func NormalizeName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return asciiLowerIfNeeded(name)
}

// IsSubdomain checks if child is a subdomain of parent.
// Both names should be normalized (lowercase, no trailing dot).
func IsSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	child = NormalizeName(child)
	parent = NormalizeName(parent)

	if child == parent {
		return true
	}

	return strings.HasSuffix(child, "."+parent)
}

func asciiLowerIfNeeded(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] = b[j] + ('a' - 'A')
				}
			}
			return string(b)
		}
	}
	return s
}

// ExtractNameFromData extracts a domain name from resource record data,
// using the full message buffer to resolve compression pointers.
func ExtractNameFromData(fullMsg []byte, dataOffset int) string {
	if len(fullMsg) == 0 || dataOffset >= len(fullMsg) {
		return ""
	}
	name, _, err := DecodeName(fullMsg, dataOffset)
	if err != nil {
		return ""
	}
	return NormalizeName(name)
}

// BuildQueryInto writes a DNS query into the provided buffer.
// Returns the number of bytes written, or an error.
func BuildQueryInto(buf []byte, id uint16, name string, qtype, qclass uint16) (int, error) {
	header := Header{
		ID:      id,
		Flags:   FlagRD,
		QDCount: 1,
	}
	if err := WriteHeader(buf, header); err != nil {
		return 0, err
	}

	off := HeaderLen
	off, err := EncodeName(buf, off, name)
	if err != nil {
		return 0, err
	}

	if len(buf) < off+4 {
		return 0, ErrShortBuffer
	}
	binary.BigEndian.PutUint16(buf[off:off+2], qtype)
	binary.BigEndian.PutUint16(buf[off+2:off+4], qclass)
	off += 4

	return off, nil
}

// BuildQueryIntoWithEDNS writes a DNS query with an EDNS0 OPT record.
// udpSize sets the advertised maximum UDP payload size.
func BuildQueryIntoWithEDNS(buf []byte, id uint16, name string, qtype, qclass uint16, udpSize uint16) (int, error) {
	header := Header{
		ID:      id,
		Flags:   FlagRD,
		QDCount: 1,
		ARCount: 1,
	}
	if err := WriteHeader(buf, header); err != nil {
		return 0, err
	}

	off := HeaderLen
	off, err := EncodeName(buf, off, name)
	if err != nil {
		return 0, err
	}

	if len(buf) < off+4 {
		return 0, ErrShortBuffer
	}
	binary.BigEndian.PutUint16(buf[off:off+2], qtype)
	binary.BigEndian.PutUint16(buf[off+2:off+4], qclass)
	off += 4

	if len(buf) < off+11 {
		return 0, ErrShortBuffer
	}
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:off+2], TypeOPT)
	off += 2
	binary.BigEndian.PutUint16(buf[off:off+2], udpSize)
	off += 2
	binary.BigEndian.PutUint32(buf[off:off+4], 0)
	off += 4
	binary.BigEndian.PutUint16(buf[off:off+2], 0)
	off += 2

	return off, nil
}
