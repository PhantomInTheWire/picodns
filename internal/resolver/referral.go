package resolver

import (
	"net"

	"picodns/internal/dns"
)

// extractReferral extracts nameserver names and their associated glue record IPs from a DNS message.
// It validates that NS records are in-bailiwick to prevent cache poisoning.
//
// Returns:
// - nsNames: normalized NS names from the authority section
// - glueIPs: flattened list of "ip:53" for in-bailiwick glue A records
// - glueByNS: map of NS name -> []"ip:53" for in-bailiwick glue
func extractReferral(fullMsg []byte, msg dns.Message, zone string) ([]string, []string, map[string][]string) {
	var nsNames []string
	nsIPs := make(map[string][]string)
	zoneNorm := dns.NormalizeName(zone)
	for _, rr := range msg.Authorities {
		if rr.Type != dns.TypeNS {
			continue
		}
		nsOwner := dns.NormalizeName(rr.Name)
		if zoneNorm != "" && !dns.IsSubdomain(nsOwner, zoneNorm) && nsOwner != zoneNorm {
			continue
		}
		nsName := dns.ExtractNameFromData(fullMsg, rr.DataOffset)
		if nsName == "" {
			continue
		}
		nsNameNorm := dns.NormalizeName(nsName)
		if nsNameNorm != "" {
			nsNames = append(nsNames, nsNameNorm)
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
	glueByNS := make(map[string][]string)
	for _, nsNameNorm := range nsNames {
		if zoneNorm != "" && !dns.IsSubdomain(nsNameNorm, zoneNorm) {
			continue
		}
		if ips, ok := nsIPs[nsNameNorm]; ok {
			glueIPs = append(glueIPs, ips...)
			glueByNS[nsNameNorm] = append(glueByNS[nsNameNorm], ips...)
		}
	}
	if len(glueByNS) == 0 {
		glueByNS = nil
	}
	return nsNames, glueIPs, glueByNS
}
