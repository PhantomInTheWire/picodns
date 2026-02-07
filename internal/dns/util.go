package dns

import (
	"encoding/binary"
	"strings"
)

// NormalizeName returns a normalized domain name (lowercase, no trailing dot).
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// JoinLabels joins a slice of domain name labels with dots.
// Returns "." if the labels slice is empty.
func JoinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	return strings.Join(labels, ".")
}

// SplitLabels splits a domain name into its constituent labels.
// Returns an empty slice for empty names or root (".") names.
func SplitLabels(name string) []string {
	if name == "" || name == "." {
		return nil
	}
	name = strings.TrimSuffix(name, ".")

	dotCount := strings.Count(name, ".")
	labels := make([]string, 0, dotCount+1)

	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

// IsSubdomain checks if child is a subdomain of parent.
// Both names should be normalized (lowercase, no trailing dot).
func IsSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	child = strings.ToLower(strings.TrimSuffix(child, "."))
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))

	if child == parent {
		return true
	}

	return strings.HasSuffix(child, "."+parent)
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
	return name
}

// BuildQuery constructs a DNS query message for the given name, type, and class.
// It uses a maximum-size buffer to avoid calculation errors, as DNS messages
// over UDP are limited to 512 bytes per RFC 1035.
// Returns the serialized query as a byte slice.
func BuildQuery(id uint16, name string, qtype, qclass uint16) ([]byte, error) {
	buf := make([]byte, MaxMessageSize)

	header := Header{
		ID:      id,
		Flags:   FlagRD,
		QDCount: 1,
	}
	if err := WriteHeader(buf, header); err != nil {
		return nil, err
	}

	off := HeaderLen
	off, err := EncodeName(buf, off, name)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(buf[off:off+2], qtype)
	binary.BigEndian.PutUint16(buf[off+2:off+4], qclass)
	off += 4

	return buf[:off], nil
}
