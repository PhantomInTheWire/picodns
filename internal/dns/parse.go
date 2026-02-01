package dns

import "encoding/binary"

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

func ReadResourceRecord(buf []byte, off int) (ResourceRecord, int, error) {
	name, next, err := DecodeName(buf, off)
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	if len(buf) < next+10 {
		return ResourceRecord{}, 0, ErrShortBuffer
	}

	rr := ResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(buf[next : next+2]),
		Class: binary.BigEndian.Uint16(buf[next+2 : next+4]),
		TTL:   binary.BigEndian.Uint32(buf[next+4 : next+8]),
	}
	dataLen := int(binary.BigEndian.Uint16(buf[next+8 : next+10]))
	dataStart := next + 10
	dataEnd := dataStart + dataLen
	if dataEnd > len(buf) {
		return ResourceRecord{}, 0, ErrShortBuffer
	}
	rr.Data = buf[dataStart:dataEnd]
	return rr, dataEnd, nil
}
