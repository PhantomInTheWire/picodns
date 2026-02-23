package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"picodns/internal/dns"
)

type inflightCall struct {
	done chan struct{}
	resp []byte
	err  error
}

// hashQuestion returns a cache key for a DNS question.
func hashQuestion(name string, qType, qClass uint16) uint64 {
	h := dns.HashNameString(name)
	h ^= uint64(qType) << 32
	h ^= uint64(qClass)
	return h
}

// secureRandUint16 generates a cryptographically secure random uint16.
func secureRandUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// formatIPPort formats an IP address as "ip:port" string.
func formatIPPort(ip net.IP, port int) string {
	var buf [50]byte
	n := copy(buf[:], ip.String())
	buf[n] = ':'
	portStart := n + 1
	if port >= 10000 {
		buf[portStart] = byte('0' + port/10000)
		portStart++
	}
	if port >= 1000 {
		buf[portStart] = byte('0' + (port/1000)%10)
		portStart++
	}
	if port >= 100 {
		buf[portStart] = byte('0' + (port/100)%10)
		portStart++
	}
	if port >= 10 {
		buf[portStart] = byte('0' + (port/10)%10)
		portStart++
	}
	buf[portStart] = byte('0' + port%10)
	return string(buf[:portStart+1])
}

// cleanupBoth releases a pooled message and executes a cleanup function.
func cleanupBoth(msg *dns.Message, cleanup func()) {
	if msg != nil {
		msg.Release()
	}
	if cleanup != nil {
		cleanup()
	}
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// cacheTTLForResponse returns a conservative TTL to use when caching a response.
// It supports:
// - Positive answers with optional CNAME chains (minimum TTL across chain + final RRset).
// - NXDOMAIN and NOERROR/NODATA negative caching using SOA.MINIMUM (RFC2308-ish).
// It returns (ttl, true) when cacheable.
func cacheTTLForResponse(fullResp []byte, msg dns.Message, q dns.Question) (time.Duration, bool) {
	rcode := msg.Header.Flags & 0x000F
	q = q.Normalize()

	soaTTL, hasSOA := negativeTTLFromSOA(fullResp, msg.Authorities)

	if rcode == dns.RcodeNXDomain {
		if hasSOA && soaTTL > 0 {
			return soaTTL, true
		}
		return 0, false
	}
	if rcode != dns.RcodeSuccess {
		return 0, false
	}

	minTTL := uint32(0)
	setMin := func(v uint32) {
		if v == 0 {
			return
		}
		if minTTL == 0 || v < minTTL {
			minTTL = v
		}
	}

	current := q.Name
	seen := make(map[string]struct{}, 4)
	seen[current] = struct{}{}
	for i := 0; i < 16; i++ {
		var next string
		var ttl uint32
		found := false
		for _, rr := range msg.Answers {
			if rr.Type != dns.TypeCNAME || rr.Class != q.Class {
				continue
			}
			if rr.Name != current {
				continue
			}
			target := dns.ExtractNameFromData(fullResp, rr.DataOffset)
			if target == "" {
				continue
			}
			next = target
			ttl = rr.TTL
			found = true
			break
		}
		if !found {
			break
		}
		setMin(ttl)
		if _, ok := seen[next]; ok {
			break
		}
		seen[next] = struct{}{}
		current = next
	}

	finalName := current

	foundFinal := false
	for _, rr := range msg.Answers {
		if rr.Class != q.Class {
			continue
		}
		if rr.Name != finalName {
			continue
		}
		if rr.Type == q.Type {
			setMin(rr.TTL)
			foundFinal = true
		}
	}

	if foundFinal {
		if minTTL > 0 {
			return time.Duration(minTTL) * time.Second, true
		}
		return 0, false
	}

	if minTTL > 0 {
		return time.Duration(minTTL) * time.Second, true
	}

	if hasSOA && soaTTL > 0 {
		return soaTTL, true
	}
	return 0, false
}

func negativeTTLFromSOA(fullResp []byte, authorities []dns.ResourceRecord) (time.Duration, bool) {
	for _, rr := range authorities {
		if rr.Type != dns.TypeSOA || rr.DataOffset <= 0 {
			continue
		}
		min, ok := soaMinimumTTL(fullResp, rr.DataOffset)
		if ok && min > 0 {
			return time.Duration(min) * time.Second, true
		}
	}
	return 0, false
}

func soaMinimumTTL(fullResp []byte, dataOffset int) (uint32, bool) {
	if dataOffset < 0 || dataOffset >= len(fullResp) {
		return 0, false
	}
	_, offM, err := dns.DecodeName(fullResp, dataOffset)
	if err != nil {
		return 0, false
	}
	_, offR, err := dns.DecodeName(fullResp, offM)
	if err != nil {
		return 0, false
	}
	if offR+20 > len(fullResp) {
		return 0, false
	}
	return binary.BigEndian.Uint32(fullResp[offR+16 : offR+20]), true
}

// setRAFlag sets the Recursion Available (RA) flag in a DNS response header.
func setRAFlag(resp []byte) {
	if len(resp) >= 4 {
		flags := binary.BigEndian.Uint16(resp[2:4])
		flags |= dns.FlagRA
		binary.BigEndian.PutUint16(resp[2:4], flags)
	}
}

// setResponseID updates the transaction ID in a DNS message header.
func setResponseID(resp []byte, id uint16) {
	if len(resp) >= 2 {
		binary.BigEndian.PutUint16(resp[0:2], id)
	}
}

// minimizeAndSetID minimizes the response and sets the transaction ID.
// This is a helper to avoid duplication since MinimizeResponse calls WriteHeader
// which overwrites the transaction ID.
func minimizeAndSetID(resp []byte, clientID uint16, keepAuthorities bool) ([]byte, error) {
	minimized, err := dns.MinimizeResponse(resp, keepAuthorities)
	if err != nil {
		setResponseID(resp, clientID)
		return resp, err
	}
	setResponseID(minimized, clientID)
	return minimized, nil
}

// extractReferral extracts nameserver names and their associated glue record IPs from a DNS message.
// It validates that NS records are in-bailiwick to prevent cache poisoning.
func extractReferral(fullMsg []byte, msg dns.Message, zone string) ([]string, []string) {
	var nsNames []string
	nsIPs := make(map[string][]string)
	zoneNorm := dns.NormalizeName(zone)
	for _, rr := range msg.Authorities {
		if rr.Type == dns.TypeNS {
			nsOwner := dns.NormalizeName(rr.Name)
			if zoneNorm != "" {
				if !dns.IsSubdomain(nsOwner, zoneNorm) && nsOwner != zoneNorm {
					continue
				}
			}
			nsName := dns.ExtractNameFromData(fullMsg, rr.DataOffset)
			if nsName != "" {
				nsNameNorm := dns.NormalizeName(nsName)
				if nsNameNorm != "" {
					nsNames = append(nsNames, nsNameNorm)
				}
			}
		}
	}
	for _, rr := range msg.Additionals {
		if rr.Type == dns.TypeA && len(rr.Data) == 4 {
			ip := formatIPPort(net.IP(rr.Data), 53)
			name := dns.NormalizeName(rr.Name)
			nsIPs[name] = append(nsIPs[name], ip)
		}
	}
	var glueIPs []string
	for _, nsNameNorm := range nsNames {
		if zoneNorm != "" {
			if !dns.IsSubdomain(nsNameNorm, zoneNorm) {
				continue
			}
		}
		if ips, ok := nsIPs[nsNameNorm]; ok {
			glueIPs = append(glueIPs, ips...)
		}
	}
	return nsNames, glueIPs
}
