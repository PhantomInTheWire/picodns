package dns

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync"
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

// messagePool is a pool of reusable Message structs
var messagePool = sync.Pool{
	New: func() interface{} {
		return &Message{
			Questions:   make([]Question, 0, 4),
			Answers:     make([]ResourceRecord, 0, 8),
			Authorities: make([]ResourceRecord, 0, 4),
			Additionals: make([]ResourceRecord, 0, 4),
		}
	},
}

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

	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	ClassIN   uint16 = 1

	MaxMessageSize = 4096

	// Compression pointer constants
	CompressionMask    = 0xC0 // Top 2 bits indicate compression pointer
	CompressionFlag    = 0xC0 // Full value indicating compression pointer
	PointerMask        = 0x3F // Bottom 6 bits of first byte + second byte form offset
	QuestionNameOffset = 0x0C // Offset of question name in DNS message (after header)
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

// Reset clears the message for reuse without deallocating slices
func (m *Message) Reset() {
	m.Header = Header{}
	m.Questions = m.Questions[:0]
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
}

// Release returns the message to the pool for reuse
func (m *Message) Release() {
	m.Reset()
	messagePool.Put(m)
}

// AcquireMessage gets a message from the pool
func AcquireMessage() *Message {
	return messagePool.Get().(*Message)
}

// ReadMessagePooled parses a DNS message using a pooled Message struct.
// The caller MUST call msg.Release() when done to return it to the pool.
func ReadMessagePooled(buf []byte) (*Message, error) {
	if len(buf) < HeaderLen {
		return nil, ErrShortBuffer
	}
	header, err := ReadHeader(buf)
	if err != nil {
		return nil, err
	}

	msg := AcquireMessage()
	msg.Header = header

	off := HeaderLen

	for i := 0; i < int(header.QDCount); i++ {
		q, next, err := ReadQuestion(buf, off)
		if err != nil {
			msg.Release()
			return nil, err
		}
		msg.Questions = append(msg.Questions, q)
		off = next
	}

	for i := 0; i < int(header.ANCount); i++ {
		rr, next, err := ReadResourceRecord(buf, off)
		if err != nil {
			msg.Release()
			return nil, err
		}
		msg.Answers = append(msg.Answers, rr)
		off = next
	}

	for i := 0; i < int(header.NSCount); i++ {
		rr, next, err := ReadResourceRecord(buf, off)
		if err != nil {
			msg.Release()
			return nil, err
		}
		msg.Authorities = append(msg.Authorities, rr)
		off = next
	}

	for i := 0; i < int(header.ARCount); i++ {
		rr, next, err := ReadResourceRecord(buf, off)
		if err != nil {
			msg.Release()
			return nil, err
		}
		msg.Additionals = append(msg.Additionals, rr)
		off = next
	}

	return msg, nil
}

type ResourceRecord struct {
	Name       string
	Type       uint16
	Class      uint16
	TTL        uint32
	Data       []byte
	DataOffset int
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
		Name:       name,
		Type:       binary.BigEndian.Uint16(buf[next : next+2]),
		Class:      binary.BigEndian.Uint16(buf[next+2 : next+4]),
		TTL:        binary.BigEndian.Uint32(buf[next+4 : next+8]),
		DataOffset: next + 10,
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

func ValidateResponse(req []byte, resp []byte) error {
	reqHeader, err := ReadHeader(req)
	if err != nil {
		return err
	}
	offReq := HeaderLen
	questions := make([]Question, 0, reqHeader.QDCount)
	for i := 0; i < int(reqHeader.QDCount); i++ {
		q, next, err := ReadQuestion(req, offReq)
		if err != nil {
			return err
		}
		questions = append(questions, q)
		offReq = next
	}

	return ValidateResponseWithRequest(reqHeader, questions, resp)
}

// ValidateResponseWithRequest validates a DNS response against a pre-parsed request.
func ValidateResponseWithRequest(reqHeader Header, reqQuestions []Question, resp []byte) error {
	respHeader, err := ReadHeader(resp)
	if err != nil {
		return err
	}

	if reqHeader.ID != respHeader.ID {
		return ErrIDMismatch
	}

	if respHeader.Flags&0x8000 == 0 {
		return ErrNotResponse
	}

	if reqHeader.QDCount != respHeader.QDCount {
		return ErrQDMismatch
	}

	offResp := HeaderLen
	for i := 0; i < int(reqHeader.QDCount); i++ {
		qResp, nextResp, err := ReadQuestion(resp, offResp)
		if err != nil {
			return err
		}

		qReq := reqQuestions[i]
		if !strings.EqualFold(qReq.Name, qResp.Name) || qReq.Type != qResp.Type || qReq.Class != qResp.Class {
			return ErrQDMismatch
		}
		offResp = nextResp
	}

	return nil
}
