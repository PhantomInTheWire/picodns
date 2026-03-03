package resolver

import (
	"encoding/binary"
	"time"

	"picodns/internal/dns"
)

// cacheTTLForResponse returns a conservative TTL to use when caching a response.
// It supports:
// - Positive answers with optional CNAME chains (minimum TTL across chain + final RRset).
// - NXDOMAIN and NOERROR/NODATA negative caching using SOA.MINIMUM (RFC2308-ish).
// It returns (ttl, true) when cacheable.
func cacheTTLForResponse(fullResp []byte, msg dns.Message, q dns.Question) (time.Duration, bool) {
	rcode := msg.Header.Flags & dns.RcodeMask
	q = q.Normalize()

	soaTTL, hasSOA := negativeTTLFromSOA(fullResp, msg.Authorities)

	if rcode == dns.RcodeNXDomain {
		if hasSOA && soaTTL > 0 {
			return soaTTL, true
		}
		// Some broken/middlebox NXDOMAIN responses omit SOA. Cache briefly anyway
		// so repeated NX queries don't force recursion each time.
		return negativeFallbackTTL, true
	}
	if rcode == dns.RcodeServer {
		// SERVFAIL is not normally cached, but a short TTL helps under load by
		// avoiding immediate retry storms for the same name/type.
		return servfailCacheTTL, true
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
	for i := 0; i < maxCNAMEChainLength; i++ {
		var next string
		var ttl uint32
		found := false
		for _, rr := range msg.Answers {
			if rr.Type != dns.TypeCNAME || rr.Class != q.Class || rr.Name != current {
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
		if rr.Class != q.Class || rr.Name != finalName {
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
