package dns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaderRoundTrip(t *testing.T) {
	buf := make([]byte, HeaderLen)
	header := Header{
		ID:      0xBEEF,
		Flags:   0x8180,
		QDCount: 1,
		ANCount: 2,
		NSCount: 3,
		ARCount: 4,
	}

	err := WriteHeader(buf, header)
	require.NoError(t, err)
	decoded, err := ReadHeader(buf)
	require.NoError(t, err)
	require.Equal(t, header, decoded)
}

func TestQuestionRoundTrip(t *testing.T) {
	buf := make([]byte, 512)
	q := Question{Name: "example.com", Type: 1, Class: 1}

	next, err := WriteQuestion(buf, 0, q)
	require.NoError(t, err)

	got, end, err := ReadQuestion(buf, 0)
	require.NoError(t, err)
	require.Equal(t, next, end)
	require.Equal(t, q, got)
}

func TestReadMessage(t *testing.T) {
	buf := make([]byte, 512)
	h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1, ANCount: 1}
	err := WriteHeader(buf, h)
	require.NoError(t, err)

	q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
	qEnd, err := WriteQuestion(buf, HeaderLen, q)
	require.NoError(t, err)

	ans := Answer{Name: "", Type: TypeA, Class: ClassIN, TTL: 60, RData: []byte{1, 2, 3, 4}}
	resp, err := BuildResponse(buf[:qEnd], []Answer{ans}, 0)
	require.NoError(t, err)

	msg, err := ReadMessagePooled(resp)
	require.NoError(t, err)
	defer msg.Release()
	require.Equal(t, h.ID, msg.Header.ID)
	require.Equal(t, uint16(1), msg.Header.QDCount)
	require.Equal(t, uint16(1), msg.Header.ANCount)
	require.Len(t, msg.Questions, 1)
	require.Equal(t, "example.com", msg.Questions[0].Name)
	require.Len(t, msg.Answers, 1)
	require.Equal(t, uint32(60), msg.Answers[0].TTL)
}

func TestIsValidRequest(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, []byte) int
		want  bool
	}{
		{
			name: "valid request",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				return n
			},
			want: true,
		},
		{
			name: "too short for header",
			setup: func(t *testing.T, buf []byte) int {
				return 5
			},
			want: false,
		},
		{
			name: "response instead of query",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: FlagQR | 0x0100, QDCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				return n
			},
			want: false,
		},
		{
			name: "zero questions",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 0}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				return HeaderLen
			},
			want: false,
		},
		{
			name: "multiple questions",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 2}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				return n
			},
			want: true,
		},
		{
			name: "has answers",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1, ANCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				return n
			},
			want: true,
		},
		{
			name: "has authorities",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1, NSCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				return n
			},
			want: true,
		},
		{
			name: "non-zero opcode",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x2800, QDCount: 1} // Opcode 1 (inverse query)
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				return n
			},
			want: true,
		},
		{
			name: "truncated question name",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				// Write incomplete name - just a label length byte
				buf[HeaderLen] = 10
				return HeaderLen + 1
			},
			want: false,
		},
		{
			name: "missing qtype and qclass",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				q := Question{Name: "x", Type: TypeA, Class: ClassIN}
				n, err := WriteQuestion(buf, HeaderLen, q)
				require.NoError(t, err)
				// Remove the 4 bytes for qtype and qclass
				return n - 2
			},
			want: true,
		},
		{
			name: "invalid first byte",
			setup: func(t *testing.T, buf []byte) int {
				h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1}
				err := WriteHeader(buf, h)
				require.NoError(t, err)
				// Put an invalid byte (0x80 - not a valid label length or compression)
				buf[HeaderLen] = 0x80
				return HeaderLen + 5
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 512)
			n := tt.setup(t, buf)
			got := IsValidRequest(buf[:n])
			require.Equal(t, tt.want, got)
		})
	}
}

func BenchmarkIsValidRequest(b *testing.B) {
	buf := make([]byte, 512)
	h := Header{ID: 0x1234, Flags: 0x0100, QDCount: 1}
	err := WriteHeader(buf, h)
	require.NoError(b, err)
	q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
	n, _ := WriteQuestion(buf, HeaderLen, q)
	req := buf[:n]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidRequest(req)
	}
}
