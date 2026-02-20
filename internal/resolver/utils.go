package resolver

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"picodns/internal/dns"
)

// secureRandUint16 generates a cryptographically secure random uint16.
func secureRandUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// formatIPPort formats an IP address as "ip:port" string.
// Uses a stack buffer to avoid allocations for the common case.
// net.IP.String() returns at most 45 chars (IPv6 max)
// plus ":53\0" = 5 more, so 50 bytes is plenty
func formatIPPort(ip net.IP, port int) string {
	var buf [50]byte
	n := copy(buf[:], ip.String())
	buf[n] = ':'
	// Write port as decimal
	portStart := n + 1
	if port >= 10000 {
		buf[portStart] = byte('0' + port/10000)
		portStart++
		port %= 10000
	}
	if port >= 1000 {
		buf[portStart] = byte('0' + port/1000)
		portStart++
		port %= 1000
	}
	if port >= 100 {
		buf[portStart] = byte('0' + port/100)
		portStart++
		port %= 100
	}
	if port >= 10 {
		buf[portStart] = byte('0' + port/10)
		portStart++
		port %= 10
	}
	buf[portStart] = byte('0' + port)
	return string(buf[:portStart+1])
}

// cleanupBoth releases a pooled message and executes a cleanup function.
// It safely handles nil cleanup functions.
func cleanupBoth(msg *dns.Message, cleanup func()) {
	if msg != nil {
		msg.Release()
	}
	if cleanup != nil {
		cleanup()
	}
}

// extractTTL extracts the TTL from a DNS message for the given question.
// For NXDOMAIN responses, extracts the SOA minimum TTL.
func extractTTL(msg dns.Message, q dns.Question) (time.Duration, bool) {
	if (msg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
		for _, rr := range msg.Authorities {
			if rr.Type == dns.TypeSOA && len(rr.Data) >= 22 {
				_, nextM, err := dns.DecodeName(rr.Data, 0)
				if err != nil {
					continue
				}
				_, nextR, err := dns.DecodeName(rr.Data, nextM)
				if err != nil {
					continue
				}
				if len(rr.Data) >= nextR+20 {
					return time.Duration(binary.BigEndian.Uint32(rr.Data[nextR+16:nextR+20])) * time.Second, true
				}
			}
		}
		return 0, false
	}

	q = q.Normalize()
	for _, rr := range msg.Answers {
		if rr.Type == q.Type && rr.Class == q.Class && rr.TTL > 0 {
			if dns.NormalizeName(rr.Name) == q.Name {
				return time.Duration(rr.TTL) * time.Second, true
			}
		}
	}
	return 0, false
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
				nsNames = append(nsNames, nsName)
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
	for _, nsName := range nsNames {
		nsNameNorm := dns.NormalizeName(nsName)
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
