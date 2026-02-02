package dns

import (
	"testing"
)

func FuzzDecodeName(f *testing.F) {
	f.Add([]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeName(data, 0)
	})
}

func FuzzReadHeader(f *testing.F) {
	f.Add(make([]byte, HeaderLen))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadHeader(data)
	})
}

func FuzzReadQuestion(f *testing.F) {
	f.Add([]byte{3, 'w', 'w', 'w', 0, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadQuestion(data, 0)
	})
}

func FuzzReadResourceRecord(f *testing.F) {
	f.Add([]byte{3, 'w', 'w', 'w', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadResourceRecord(data, 0)
	})
}

func FuzzValidateResponse(f *testing.F) {
	req := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1}
	resp := []byte{0, 1, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1}
	f.Add(req, resp)
	f.Fuzz(func(t *testing.T, req, resp []byte) {
		_ = ValidateResponse(req, resp)
	})
}
