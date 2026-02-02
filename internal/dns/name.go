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
	name, next, err := decodeName(buf, off, 0, nil)
	if err != nil {
		return "", 0, err
	}
	return name, next, nil
}

func decodeName(buf []byte, off int, depth int, visited map[int]struct{}) (string, int, error) {
	if depth > maxDepth {
		return "", 0, ErrBadPointer
	}
	if off >= len(buf) {
		return "", 0, ErrShortBuffer
	}
	if visited == nil {
		visited = map[int]struct{}{}
	}
	if _, ok := visited[off]; ok {
		return "", 0, ErrBadPointer
	}
	visited[off] = struct{}{}

	labels := make([]string, 0, 8)
	i := off
	for {
		if i >= len(buf) {
			return "", 0, ErrShortBuffer
		}
		length := int(buf[i])
		if length == 0 {
			i++
			break
		}

		if length&0xC0 == 0xC0 {
			if i+1 >= len(buf) {
				return "", 0, ErrShortBuffer
			}
			ptr := int(length&0x3F)<<8 | int(buf[i+1])
			pointed, _, err := decodeName(buf, ptr, depth+1, visited)
			if err != nil {
				return "", 0, err
			}
			if pointed != "" {
				labels = append(labels, pointed)
			}
			i += 2
			break
		}

		if length > maxLabelLen {
			return "", 0, ErrLabelTooLong
		}
		if i+1+length > len(buf) {
			return "", 0, ErrShortBuffer
		}

		labels = append(labels, string(buf[i+1:i+1+length]))
		i += 1 + length
	}

	name := strings.Join(labels, ".")
	if len(name) > maxNameLen {
		return "", 0, ErrNameTooLong
	}
	return name, i, nil
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

	labels := strings.Split(name, ".")
	i := off
	for _, label := range labels {
		if len(label) > maxLabelLen {
			return 0, ErrLabelTooLong
		}
		if i+1+len(label) > len(buf) {
			return 0, ErrShortBuffer
		}
		buf[i] = byte(len(label))
		copy(buf[i+1:i+1+len(label)], label)
		i += 1 + len(label)
	}
	if i >= len(buf) {
		return 0, ErrShortBuffer
	}
	buf[i] = 0
	return i + 1, nil
}
