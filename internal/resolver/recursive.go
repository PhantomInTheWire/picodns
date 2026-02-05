package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"picodns/internal/dns"
)

var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"199.9.14.201:53",   // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net
}

const (
	maxRecursionDepth = 32
	defaultTimeout    = 5 * time.Second

	// ConnPoolIdleTimeout is how long idle connections are kept in the pool
	ConnPoolIdleTimeout = 30 * time.Second

	// ConnPoolMaxConns is the maximum number of connections in the pool
	ConnPoolMaxConns = 10
)

var (
	ErrMaxDepth      = errors.New("recursive resolver: max recursion depth exceeded")
	ErrNoNameservers = errors.New("recursive resolver: no nameservers found")
	ErrNoGlueRecords = errors.New("recursive resolver: no glue records for NS")
	ErrCnameLoop     = errors.New("recursive resolver: CNAME loop detected")
	ErrNoRootServers = errors.New("recursive resolver: no root servers available")
)

func secureRandUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

type Recursive struct {
	pool sync.Pool
}

func NewRecursive() *Recursive {
	r := &Recursive{}
	r.pool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	return r
}

func (r *Recursive) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	reqMsg, err := dns.ReadMessage(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return nil, errors.New("recursive resolver: invalid request")
	}

	q := reqMsg.Questions[0]

	return r.resolveIterative(ctx, req, q.Name, 0, nil)
}

// resolveIterative performs iterative DNS resolution starting from root servers.
// It queries servers iteratively, following referrals until an answer is found.
// The depth parameter tracks recursion to prevent infinite loops from CNAME chains or circular referrals.
func (r *Recursive) resolveIterative(ctx context.Context, origReq []byte, name string, depth int, seenCnames map[string]struct{}) ([]byte, error) {
	if depth >= maxRecursionDepth {
		return nil, ErrMaxDepth
	}

	origMsg, _ := dns.ReadMessage(origReq)
	q := origMsg.Questions[0]

	servers := rootServers
	labels := splitLabels(name)

	for i := len(labels); i >= 0; i-- {
		zone := joinLabels(labels[i:])
		if zone != "." {
			zone = normalizeName(zone)
		}

		for _, server := range servers {
			resp, err := r.queryServer(ctx, server, origReq)
			if err != nil {
				continue
			}

			respMsg, err := dns.ReadMessage(resp)
			if err != nil {
				continue
			}

			if len(respMsg.Answers) > 0 {
				for _, ans := range respMsg.Answers {
					if ans.Type == dns.TypeCNAME {
						if !strings.EqualFold(ans.Name, name) && !strings.EqualFold(ans.Name, name+".") {
							continue
						}

						cnameTarget := extractNameFromData(resp, ans.DataOffset)
						if cnameTarget == "" {
							continue
						}

						cnameKey := name + "->" + cnameTarget
						if seenCnames == nil {
							seenCnames = make(map[string]struct{})
						}
						if _, seen := seenCnames[cnameKey]; seen {
							return nil, ErrCnameLoop
						}
						seenCnames[cnameKey] = struct{}{}

						newReq, err := buildQuery(origMsg.Header.ID, cnameTarget, q.Type, q.Class)
						if err != nil {
							continue
						}
						return r.resolveIterative(ctx, newReq, cnameTarget, depth+1, seenCnames)
					}
				}

				return resp, nil
			}

			if (respMsg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
				return resp, nil
			}

			if len(respMsg.Authorities) > 0 {
				nsServers, glueIPs := extractReferral(resp, respMsg, zone)
				if len(nsServers) == 0 {
					continue
				}

				if len(glueIPs) > 0 {
					servers = glueIPs
				} else {
					resolvedIPs, err := r.resolveNSNames(ctx, nsServers, depth+1, seenCnames)
					if err != nil {
						continue
					}
					servers = resolvedIPs
				}

				break
			}
		}
	}

	return nil, ErrNoNameservers
}

func (r *Recursive) queryServer(ctx context.Context, server string, req []byte) ([]byte, error) {
	resp, needsTCP, err := queryUDPString(ctx, server, req, defaultTimeout, &r.pool, true)
	if err != nil {
		return nil, err
	}
	if needsTCP {
		return r.queryServerTCP(ctx, server, req)
	}
	return resp, nil
}

func (r *Recursive) queryServerTCP(ctx context.Context, server string, req []byte) ([]byte, error) {
	return tcpQuery(ctx, server, req, defaultTimeout, true)
}

// tcpQuery performs a TCP DNS query to the given server.
// If validate is true, it validates the response against the request.
func tcpQuery(ctx context.Context, server string, req []byte, timeout time.Duration, validate bool) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	reqLen := uint16(len(req))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], reqLen)

	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	if validate {
		if err := dns.ValidateResponse(req, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// resolveNSNames resolves the IP addresses of nameservers when glue records are missing.
// This is a recursive call to get A records for NS hostnames.
func (r *Recursive) resolveNSNames(ctx context.Context, nsNames []string, depth int, seenCnames map[string]struct{}) ([]string, error) {
	if depth >= maxRecursionDepth {
		return nil, ErrMaxDepth
	}

	var ips []string
	for _, nsName := range nsNames {
		req, err := buildQuery(secureRandUint16(), nsName, dns.TypeA, dns.ClassIN)
		if err != nil {
			continue
		}
		resp, err := r.resolveIterative(ctx, req, nsName, depth+1, seenCnames)
		if err != nil {
			continue
		}

		respMsg, err := dns.ReadMessage(resp)
		if err != nil {
			continue
		}

		for _, ans := range respMsg.Answers {
			if ans.Type == dns.TypeA && len(ans.Data) == 4 {
				ip := net.IP(ans.Data).String() + ":53"
				ips = append(ips, ip)
			}
		}
	}

	if len(ips) == 0 {
		return nil, ErrNoGlueRecords
	}

	return ips, nil
}

func splitLabels(name string) []string {
	if name == "" || name == "." {
		return nil
	}
	name = strings.TrimSuffix(name, ".")

	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	return strings.Join(labels, ".")
}

// extractNameFromData extracts a domain name from resource record data,
// using the full message buffer to resolve compression pointers.
func extractNameFromData(fullMsg []byte, dataOffset int) string {
	if len(fullMsg) == 0 || dataOffset >= len(fullMsg) {
		return ""
	}
	name, _, err := dns.DecodeName(fullMsg, dataOffset)
	if err != nil {
		return ""
	}
	return name
}

// isSubdomain checks if child is a subdomain of parent.
// Both names should be normalized (lowercase, no trailing dot).
func isSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	child = strings.ToLower(strings.TrimSuffix(child, "."))
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))

	if child == parent {
		return true
	}

	return strings.HasSuffix(child, "."+parent)
}

// extractReferral extracts nameserver names and their associated glue record IPs from a DNS message.
// It validates that NS records are in-bailiwick to prevent cache poisoning.
func extractReferral(fullMsg []byte, msg dns.Message, zone string) ([]string, []string) {
	var nsNames []string
	nsIPs := make(map[string][]string)

	zoneNorm := strings.ToLower(strings.TrimSuffix(zone, "."))

	for _, rr := range msg.Authorities {
		if rr.Type == dns.TypeNS {
			nsOwner := strings.ToLower(strings.TrimSuffix(rr.Name, "."))

			if zoneNorm != "" {
				if !isSubdomain(nsOwner, zoneNorm) && nsOwner != zoneNorm {
					continue
				}
			}

			nsName := extractNameFromData(fullMsg, rr.DataOffset)
			if nsName != "" {
				nsNames = append(nsNames, nsName)
			}
		}
	}

	for _, rr := range msg.Additionals {
		if rr.Type == dns.TypeA && len(rr.Data) == 4 {
			ip := net.IP(rr.Data).String() + ":53"
			nsIPs[rr.Name] = append(nsIPs[rr.Name], ip)
		}
	}

	var glueIPs []string
	for _, nsName := range nsNames {
		if zoneNorm != "" {
			nsNameNorm := strings.ToLower(strings.TrimSuffix(nsName, "."))
			if !isSubdomain(nsNameNorm, zoneNorm) {
				continue
			}
		}
		if ips, ok := nsIPs[nsName]; ok {
			glueIPs = append(glueIPs, ips...)
		}
	}

	return nsNames, glueIPs
}

func buildQuery(id uint16, name string, qtype, qclass uint16) ([]byte, error) {
	labelCount := strings.Count(name, ".") + 1
	if strings.HasSuffix(name, ".") {
		labelCount--
	}
	buf := make([]byte, dns.HeaderLen+len(name)+labelCount+1+4)

	header := dns.Header{
		ID:      id,
		Flags:   dns.FlagRD,
		QDCount: 1,
	}
	if err := dns.WriteHeader(buf, header); err != nil {
		return nil, err
	}

	off := dns.HeaderLen
	off, err := dns.EncodeName(buf, off, name)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(buf[off:off+2], qtype)
	binary.BigEndian.PutUint16(buf[off+2:off+4], qclass)
	off += 4

	return buf[:off], nil
}
