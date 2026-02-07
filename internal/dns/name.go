package dns

import (
	"errors"
	"strings"
)

const (
	maxNameLen  = 255
	maxLabelLen = 63
	maxDepth    = 16
)

var ErrBadPointer = errors.New("dns: bad compression pointer")

func DecodeName(buf []byte, off int) (string, int, error) {
	var builder strings.Builder
	builder.Grow(64)
	next, err := decodeNameInto(buf, off, 0, nil, &builder)
	if err != nil {
		return "", 0, err
	}
	name := builder.String()
	if len(name) > maxNameLen {
		return "", 0, ErrNameTooLong
	}
	return name, next, nil
}

func decodeNameInto(buf []byte, off int, depth int, visited map[int]struct{}, builder *strings.Builder) (int, error) {
	if depth > maxDepth {
		return 0, ErrBadPointer
	}
	if off >= len(buf) {
		return 0, ErrShortBuffer
	}

	i := off
	for {
		if i >= len(buf) {
			return 0, ErrShortBuffer
		}
		length := int(buf[i])
		if length == 0 {
			i++
			break
		}

		if length&CompressionMask == CompressionFlag {
			if i+1 >= len(buf) {
				return 0, ErrShortBuffer
			}
			if visited == nil {
				visited = make(map[int]struct{}, 4)
			}
			ptr := int(length&PointerMask)<<8 | int(buf[i+1])
			if _, seen := visited[ptr]; seen {
				return 0, ErrBadPointer
			}
			visited[ptr] = struct{}{}
			_, err := decodeNameInto(buf, ptr, depth+1, visited, builder)
			if err != nil {
				return 0, err
			}
			i += 2
			return i, nil
		}

		if length > maxLabelLen {
			return 0, ErrLabelTooLong
		}
		if i+1+length > len(buf) {
			return 0, ErrShortBuffer
		}

		if builder.Len() > 0 {
			builder.WriteByte('.')
		}
		builder.Write(buf[i+1 : i+1+length])
		i += 1 + length
	}

	return i, nil
}

func EncodeName(buf []byte, off int, name string) (int, error) {
	if name == "." {
		name = ""
	}
	if len(name) > maxNameLen {
		return 0, ErrNameTooLong
	}
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		if off >= len(buf) {
			return 0, ErrShortBuffer
		}
		buf[off] = 0
		return off + 1, nil
	}

	i := off
	start := 0
	for j := 0; j <= len(name); j++ {
		if j == len(name) || name[j] == '.' {
			labelLen := j - start
			if labelLen > maxLabelLen {
				return 0, ErrLabelTooLong
			}
			if i+1+labelLen > len(buf) {
				return 0, ErrShortBuffer
			}
			buf[i] = byte(labelLen)
			copy(buf[i+1:i+1+labelLen], name[start:j])
			i += 1 + labelLen
			start = j + 1
		}
	}
	if i >= len(buf) {
		return 0, ErrShortBuffer
	}
	buf[i] = 0
	return i + 1, nil
}
