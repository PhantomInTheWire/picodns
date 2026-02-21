package server

import "picodns/internal/dns"

// servfailFromRequestInPlace rewrites req in-place into a minimal SERVFAIL response.
// The returned slice references req.
func servfailFromRequestInPlace(req []byte) ([]byte, bool) {
	hdr, err := dns.ReadHeader(req)
	if err != nil || hdr.QDCount == 0 {
		return nil, false
	}
	nameEnd, err := dns.SkipName(req, dns.HeaderLen)
	if err != nil {
		return nil, false
	}
	qEnd := nameEnd + 4 // qtype + qclass
	if qEnd > len(req) {
		return nil, false
	}

	hdr.Flags = dns.FlagQR | (hdr.Flags & dns.FlagOpcode) | (hdr.Flags & dns.FlagRD) | dns.FlagRA | (dns.RcodeServer & 0x000F)
	hdr.QDCount = 1
	hdr.ANCount = 0
	hdr.NSCount = 0
	hdr.ARCount = 0
	_ = dns.WriteHeader(req, hdr)

	return req[:qEnd], true
}
