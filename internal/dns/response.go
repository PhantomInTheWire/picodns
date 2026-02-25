package dns

import "encoding/binary"

type Answer struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

func BuildResponse(req []byte, answers []Answer, rcode uint16) ([]byte, error) {
	if len(req) < HeaderLen {
		return nil, ErrShortBuffer
	}
	reqHeader, err := ReadHeader(req)
	if err != nil {
		return nil, err
	}
	if reqHeader.QDCount == 0 {
		return nil, ErrNoQuestion
	}

	_, qEnd, err := ReadQuestion(req, HeaderLen)
	if err != nil {
		return nil, err
	}
	if qEnd > len(req) {
		return nil, ErrShortBuffer
	}

	resp := make([]byte, MaxMessageSize)
	respHeader := Header{
		ID:      reqHeader.ID,
		Flags:   responseFlags(reqHeader.Flags, rcode),
		QDCount: 1,
		ANCount: uint16(len(answers)),
	}
	if err := WriteHeader(resp, respHeader); err != nil {
		return nil, err
	}

	copy(resp[HeaderLen:qEnd], req[HeaderLen:qEnd])
	idx := qEnd

	for _, ans := range answers {
		var err error
		if ans.Name == "" {
			if idx+2 >= len(resp) {
				return nil, ErrShortBuffer
			}
			resp[idx] = CompressionFlag
			resp[idx+1] = QuestionNameOffset
			idx += 2
		} else {
			idx, err = EncodeName(resp, idx, ans.Name)
			if err != nil {
				return nil, err
			}
		}

		if idx+10 > len(resp) {
			return nil, ErrShortBuffer
		}
		binary.BigEndian.PutUint16(resp[idx:idx+2], ans.Type)
		binary.BigEndian.PutUint16(resp[idx+2:idx+4], ans.Class)
		binary.BigEndian.PutUint32(resp[idx+4:idx+8], ans.TTL)
		binary.BigEndian.PutUint16(resp[idx+8:idx+10], uint16(len(ans.RData)))
		idx += 10

		if idx+len(ans.RData) > len(resp) {
			return nil, ErrShortBuffer
		}
		copy(resp[idx:idx+len(ans.RData)], ans.RData)
		idx += len(ans.RData)
	}

	return resp[:idx], nil
}

func responseFlags(reqFlags uint16, rcode uint16) uint16 {
	return FlagQR | (reqFlags & FlagOpcode) | (reqFlags & FlagRD) | FlagRA | (rcode & RcodeMask)
}

// MinimizeResponse strips authority/additional sections to reduce size.
// If keepAuthorities is true, authority records are preserved and additionals dropped.
// The response is modified in place and returned as a sliced buffer.
//
// NOTE: This unconditionally strips ALL additional records, including EDNS0 OPT
// (type 41) records. This is intentional — the server does not advertise EDNS0
// support to clients, so cached (minimized) responses omit OPT. Clients that
// send EDNS0 queries will not receive an OPT record in responses. This is a
// known limitation.
func MinimizeResponse(resp []byte, keepAuthorities bool) ([]byte, error) {
	header, err := ReadHeader(resp)
	if err != nil {
		return nil, err
	}

	off := HeaderLen
	for i := 0; i < int(header.QDCount); i++ {
		_, next, err := ReadQuestion(resp, off)
		if err != nil {
			return nil, err
		}
		off = next
	}
	for i := 0; i < int(header.ANCount); i++ {
		_, next, err := ReadResourceRecord(resp, off)
		if err != nil {
			return nil, err
		}
		off = next
	}
	if keepAuthorities {
		for i := 0; i < int(header.NSCount); i++ {
			_, next, err := ReadResourceRecord(resp, off)
			if err != nil {
				return nil, err
			}
			off = next
		}
	} else {
		header.NSCount = 0
	}
	header.ARCount = 0
	if err := WriteHeader(resp, header); err != nil {
		return nil, err
	}
	if off > len(resp) {
		return nil, ErrShortBuffer
	}
	return resp[:off], nil
}
