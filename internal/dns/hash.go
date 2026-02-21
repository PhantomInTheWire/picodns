package dns

import "encoding/binary"

// FNV-1a 64-bit constants.
const (
	fvn64Offset = 14695981039346656037
	fvn64Prime  = 1099511628211
)

func fnv64Add(h uint64, b byte) uint64 {
	h ^= uint64(b)
	h *= fvn64Prime
	return h
}

// HashNormalizedNameString hashes a normalized DNS name (lowercase, no trailing dot).
// It uses '.' as the label separator.
func HashNormalizedNameString(name string) uint64 {
	h := uint64(fvn64Offset)
	for i := 0; i < len(name); i++ {
		c := name[i]
		// Defensive: normalize ASCII case in case caller didn't.
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		h = fnv64Add(h, c)
	}
	return h
}

// HashQuestionKeyFromWire reads the first question name/type/class from wire
// and returns a combined key hash.
//
// It does not follow compression pointers; if a pointer is encountered, compressed=true
// and the caller should fall back to full parsing.
func HashQuestionKeyFromWire(msg []byte, off int) (key uint64, qtype uint16, qclass uint16, next int, compressed bool, err error) {
	h := uint64(fvn64Offset)
	i := off
	firstLabel := true
	for {
		if i >= len(msg) {
			return 0, 0, 0, 0, false, ErrShortBuffer
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&CompressionMask == CompressionFlag {
			return 0, 0, 0, 0, true, nil
		}
		if l > maxLabelLen {
			return 0, 0, 0, 0, false, ErrLabelTooLong
		}
		i++
		if i+l > len(msg) {
			return 0, 0, 0, 0, false, ErrShortBuffer
		}
		if !firstLabel {
			h = fnv64Add(h, '.')
		} else {
			firstLabel = false
		}
		for j := 0; j < l; j++ {
			c := msg[i+j]
			if c >= 'A' && c <= 'Z' {
				c = c + ('a' - 'A')
			}
			h = fnv64Add(h, c)
		}
		i += l
	}

	if len(msg) < i+4 {
		return 0, 0, 0, 0, false, ErrShortBuffer
	}
	qtype = binary.BigEndian.Uint16(msg[i : i+2])
	qclass = binary.BigEndian.Uint16(msg[i+2 : i+4])
	next = i + 4

	key = h
	key ^= uint64(qtype) << 32
	key ^= uint64(qclass)
	return key, qtype, qclass, next, false, nil
}
