package dns

import (
	"encoding/binary"
	"errors"
)

var (
	ErrShortBuffer  = errors.New("dns: short buffer")
	ErrNameTooLong  = errors.New("dns: name too long")
	ErrLabelTooLong = errors.New("dns: label too long")
	ErrNoQuestion   = errors.New("dns: no question")
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
