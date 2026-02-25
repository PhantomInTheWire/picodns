package dns

import "encoding/binary"

// RewriteTTLsAtOffsets rewrites TTL fields at provided offsets.
// Offsets must point at the start of the 4-byte TTL field.
func RewriteTTLsAtOffsets(msg []byte, ttl uint32, offsets []uint16) {
	if ttl == 0 || len(offsets) == 0 {
		return
	}
	for _, off := range offsets {
		i := int(off)
		if i+4 > len(msg) {
			continue
		}
		binary.BigEndian.PutUint32(msg[i:i+4], ttl)
	}
}

// CollectTTLOffsets returns offsets of TTL fields for all non-pseudo RRs.
// Offsets point at the start of the 4-byte TTL field.
func CollectTTLOffsets(msg []byte) ([]uint16, error) {
	h, err := ReadHeader(msg)
	if err != nil {
		return nil, err
	}
	off := HeaderLen
	for i := 0; i < int(h.QDCount); i++ {
		next, err := SkipName(msg, off)
		if err != nil {
			return nil, err
		}
		if len(msg) < next+4 {
			return nil, ErrShortBuffer
		}
		off = next + 4
	}

	var offsets []uint16
	addRR := func(count uint16) error {
		for i := 0; i < int(count); i++ {
			next, err := SkipName(msg, off)
			if err != nil {
				return err
			}
			if len(msg) < next+10 {
				return ErrShortBuffer
			}
			rrType := binary.BigEndian.Uint16(msg[next : next+2])
			if rrType != TypeOPT && rrType != TypeTSIG {
				ttlOff := next + 4
				if ttlOff+4 <= len(msg) {
					offsets = append(offsets, uint16(ttlOff))
				}
			}
			rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
			off = next + 10 + rdlen
			if off > len(msg) {
				return ErrShortBuffer
			}
		}
		return nil
	}

	if err := addRR(h.ANCount); err != nil {
		return nil, err
	}
	if err := addRR(h.NSCount); err != nil {
		return nil, err
	}
	if err := addRR(h.ARCount); err != nil {
		return nil, err
	}
	return offsets, nil
}
