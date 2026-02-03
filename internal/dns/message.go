package dns

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrShortBuffer  = errors.New("dns: short buffer")
	ErrNameTooLong  = errors.New("dns: name too long")
	ErrLabelTooLong = errors.New("dns: label too long")
	ErrNoQuestion   = errors.New("dns: no question")
	ErrIDMismatch   = errors.New("dns: transaction ID mismatch")
	ErrNotResponse  = errors.New("dns: not a response")
	ErrQDMismatch   = errors.New("dns: question section mismatch")
)

const (
	FlagQR     = 0x8000
	FlagOpcode = 0x7800
	FlagTC     = 0x0200
	FlagRD     = 0x0100
	FlagRA     = 0x0080

	RcodeSuccess  = 0
	RcodeFormat   = 1
	RcodeServer   = 2
	RcodeNXDomain = 3

	TypeA    uint16 = 1
	TypeSOA  uint16 = 6
	TypeAAAA uint16 = 28
	ClassIN  uint16 = 1

	MaxMessageSize = 4096
)

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const HeaderLen = 12

func ReadHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderLen {
		return Header{}, ErrShortBuffer
	}

	return Header{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   binary.BigEndian.Uint16(buf[2:4]),
		QDCount: binary.BigEndian.Uint16(buf[4:6]),
		ANCount: binary.BigEndian.Uint16(buf[6:8]),
		NSCount: binary.BigEndian.Uint16(buf[8:10]),
		ARCount: binary.BigEndian.Uint16(buf[10:12]),
	}, nil
}

func WriteHeader(buf []byte, h Header) error {
	if len(buf) < HeaderLen {
		return ErrShortBuffer
	}

	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)
	return nil
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q Question) Normalize() Question {
	q.Name = strings.ToLower(strings.TrimSuffix(q.Name, "."))
	return q
}

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

func ReadMessage(buf []byte) (Message, error) {
	if len(buf) < HeaderLen {
		return Message{}, ErrShortBuffer
	}
	header, err := ReadHeader(buf)
	if err != nil {
		return Message{}, err
	}

	msg := Message{
		Header: header,
	}

	off := HeaderLen

	msg.Questions = make([]Question, 0, header.QDCount)
	for i := 0; i < int(header.QDCount); i++ {
		q, next, err := ReadQuestion(buf, off)
		if err != nil {
			return Message{}, err
		}
		msg.Questions = append(msg.Questions, q)
		off = next
	}

	msg.Answers = make([]ResourceRecord, 0, header.ANCount)
	for i := 0; i < int(header.ANCount); i++ {
		rr, next, err := ReadResourceRecord(buf, off)
		if err != nil {
			return Message{}, err
		}
		msg.Answers = append(msg.Answers, rr)
		off = next
	}

	msg.Authorities = make([]ResourceRecord, 0, header.NSCount)
	for i := 0; i < int(header.NSCount); i++ {
		rr, next, err := ReadResourceRecord(buf, off)
		if err != nil {
			return Message{}, err
		}
		msg.Authorities = append(msg.Authorities, rr)
		off = next
	}

	msg.Additionals = make([]ResourceRecord, 0, header.ARCount)
	for i := 0; i < int(header.ARCount); i++ {
		rr, next, err := ReadResourceRecord(buf, off)
		if err != nil {
			return Message{}, err
		}
		msg.Additionals = append(msg.Additionals, rr)
		off = next
	}

	return msg, nil
}

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

func ReadQuestion(buf []byte, off int) (Question, int, error) {
	name, next, err := DecodeName(buf, off)
	if err != nil {
		return Question{}, 0, err
	}
	if len(buf) < next+4 {
		return Question{}, 0, ErrShortBuffer
	}

	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(buf[next : next+2]),
		Class: binary.BigEndian.Uint16(buf[next+2 : next+4]),
	}
	return q, next + 4, nil
}

func WriteQuestion(buf []byte, off int, q Question) (int, error) {
	next, err := EncodeName(buf, off, q.Name)
	if err != nil {
		return 0, err
	}
	if len(buf) < next+4 {
		return 0, ErrShortBuffer
	}

	binary.BigEndian.PutUint16(buf[next:next+2], q.Type)
	binary.BigEndian.PutUint16(buf[next+2:next+4], q.Class)
	return next + 4, nil
}

func ValidateResponse(req, resp []byte) error {
	reqHeader, err := ReadHeader(req)
	if err != nil {
		return err
	}
	respHeader, err := ReadHeader(resp)
	if err != nil {
		return err
	}

	if reqHeader.ID != respHeader.ID {
		return ErrIDMismatch
	}

	// QR bit is the most significant bit of the flags
	if respHeader.Flags&0x8000 == 0 {
		return ErrNotResponse
	}

	if reqHeader.QDCount != respHeader.QDCount {
		return ErrQDMismatch
	}

	offReq := HeaderLen
	offResp := HeaderLen

	for i := 0; i < int(reqHeader.QDCount); i++ {
		qReq, nextReq, err := ReadQuestion(req, offReq)
		if err != nil {
			return err
		}
		qResp, nextResp, err := ReadQuestion(resp, offResp)
		if err != nil {
			return err
		}

		if !strings.EqualFold(qReq.Name, qResp.Name) || qReq.Type != qResp.Type || qReq.Class != qResp.Class {
			return ErrQDMismatch
		}
		offReq = nextReq
		offResp = nextResp
	}

	return nil
}
