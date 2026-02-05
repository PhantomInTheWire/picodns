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
	labels, next, err := decodeName(buf, off, 0, nil)
	if err != nil {
		return "", 0, err
	}
	name := strings.Join(labels, ".")
	if len(name) > maxNameLen {
		return "", 0, ErrNameTooLong
	}
	return name, next, nil
}

func decodeName(buf []byte, off int, depth int, visited map[int]struct{}) ([]string, int, error) {
	if depth > maxDepth {
		return nil, 0, ErrBadPointer
	}
	if off >= len(buf) {
		return nil, 0, ErrShortBuffer
	}

	// Stack-allocated array for up to 16 labels (covers 99.9% of names)
	var stackLabels [16]string
	labels := stackLabels[:0]

	i := off
	for {
		if i >= len(buf) {
			return nil, 0, ErrShortBuffer
		}
		length := int(buf[i])
		if length == 0 {
			i++
			break
		}

		if length&CompressionMask == CompressionFlag {
			if i+1 >= len(buf) {
				return nil, 0, ErrShortBuffer
			}
			// Lazy allocation: only create map when we encounter first compression pointer
			if visited == nil {
				visited = make(map[int]struct{}, 4)
			}
			ptr := int(length&PointerMask)<<8 | int(buf[i+1])
			if _, seen := visited[ptr]; seen {
				return nil, 0, ErrBadPointer
			}
			visited[ptr] = struct{}{}
			pointedLabels, _, err := decodeName(buf, ptr, depth+1, visited)
			if err != nil {
				return nil, 0, err
			}
			labels = append(labels, pointedLabels...)
			i += 2
			break
		}

		if length > maxLabelLen {
			return nil, 0, ErrLabelTooLong
		}
		if i+1+length > len(buf) {
			return nil, 0, ErrShortBuffer
		}

		if len(labels) < cap(labels) {
			labels = append(labels, string(buf[i+1:i+1+length]))
		} else {
			heapLabels := make([]string, len(labels), len(labels)+1)
			copy(heapLabels, labels)
			heapLabels = append(heapLabels, string(buf[i+1:i+1+length]))
			labels = heapLabels
		}
		i += 1 + length
	}

	return labels, i, nil
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
