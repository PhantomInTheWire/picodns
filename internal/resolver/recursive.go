package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"picodns/internal/dns"
	"picodns/internal/dnsutil"
)

// defaultRootServers contains the default DNS root server addresses.
// These are used when no custom root servers are provided.
var defaultRootServers = []string{
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

// Option is a functional option for configuring the Recursive resolver.
type Option func(*Recursive)

// WithRootServers sets custom root servers for the recursive resolver.
// If not provided, the resolver uses the default root servers.
func WithRootServers(servers []string) Option {
	return func(r *Recursive) {
		r.rootServers = servers
	}
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

// Recursive is a recursive DNS resolver that performs iterative resolution
// starting from root servers and following referrals.
type Recursive struct {
	pool        sync.Pool
	connPool    *connPool
	rootServers []string
}

// NewRecursive creates a new recursive DNS resolver with the provided options.
// If no options are provided, the resolver uses default root servers.
func NewRecursive(opts ...Option) *Recursive {
	r := &Recursive{
		connPool:    newConnPool(),
		rootServers: defaultRootServers,
	}
	r.pool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Recursive) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	reqMsg, err := dns.ReadMessagePooled(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return nil, nil, errors.New("recursive resolver: invalid request")
	}
	q := reqMsg.Questions[0]
	name := q.Name
	reqHeader := reqMsg.Header
	questions := make([]dns.Question, len(reqMsg.Questions))
	copy(questions, reqMsg.Questions)
	reqMsg.Release()

	return r.resolveIterative(ctx, reqHeader, questions, name, 0, nil)
}

// resolveIterative performs iterative DNS resolution starting from root servers.
func (r *Recursive) resolveIterative(ctx context.Context, reqHeader dns.Header, questions []dns.Question, name string, depth int, seenCnames map[string]struct{}) ([]byte, func(), error) {
	if depth >= maxRecursionDepth {
		return nil, nil, ErrMaxDepth
	}

	q := questions[0]
	servers := r.rootServers
	var labelsBuf [16]string
	labelCount := splitLabelsInto(name, labelsBuf[:])
	labels := labelsBuf[:labelCount]

	// Rebuild query for this specific name/type if it's different from original (e.g. following CNAME)
	query, err := dnsutil.BuildQuery(reqHeader.ID, name, q.Type, q.Class)
	if err != nil {
		return nil, nil, err
	}

	for i := len(labels); i >= 0; i-- {
		zone := dnsutil.JoinLabels(labels[i:])
		if zone != "." {
			zone = dnsutil.NormalizeName(zone)
		}

		for _, server := range servers {
			resp, cleanup, err := r.queryServer(ctx, server, query, reqHeader, questions)
			if err != nil {
				continue
			}

			respMsg, err := dns.ReadMessagePooled(resp)
			if err != nil {
				if cleanup != nil {
					cleanup()
				}
				continue
			}

			if len(respMsg.Answers) > 0 {
				for _, ans := range respMsg.Answers {
					if ans.Type == dns.TypeCNAME {
						if !strings.EqualFold(ans.Name, name) && !strings.EqualFold(ans.Name, name+".") {
							continue
						}

						cnameTarget := dnsutil.ExtractNameFromData(resp, ans.DataOffset)
						if cnameTarget == "" {
							continue
						}

						if seenCnames == nil {
							seenCnames = make(map[string]struct{})
						}
						if _, seen := seenCnames[cnameTarget]; seen {
							respMsg.Release()
							if cleanup != nil {
								cleanup()
							}
							return nil, nil, ErrCnameLoop
						}
						seenCnames[cnameTarget] = struct{}{}

						respMsg.Release()
						if cleanup != nil {
							cleanup()
						}
						return r.resolveIterative(ctx, reqHeader, questions, cnameTarget, depth+1, seenCnames)
					}
				}

				respMsg.Release()
				return resp, cleanup, nil
			}

			if (respMsg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
				respMsg.Release()
				return resp, cleanup, nil
			}

			if len(respMsg.Authorities) > 0 {
				nsServers, glueIPs := extractReferral(resp, *respMsg, zone)
				respMsg.Release()
				if len(nsServers) == 0 {
					if cleanup != nil {
						cleanup()
					}
					continue
				}

				if len(glueIPs) > 0 {
					servers = glueIPs
					if cleanup != nil {
						cleanup()
					}
				} else {
					resolvedIPs, err := r.resolveNSNames(ctx, nsServers, depth+1, seenCnames)
					if cleanup != nil {
						cleanup()
					}
					if err != nil {
						continue
					}
					servers = resolvedIPs
				}

				break
			}
			respMsg.Release()
			if cleanup != nil {
				cleanup()
			}
		}
	}

	return nil, nil, ErrNoNameservers
}

func (r *Recursive) queryServer(ctx context.Context, server string, req []byte, reqHeader dns.Header, questions []dns.Question) ([]byte, func(), error) {
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, nil, err
	}

	resp, cleanup, needsTCP, err := queryUDP(ctx, raddr, req, defaultTimeout, &r.pool, r.connPool, false)
	if err != nil {
		return nil, nil, err
	}

	if err := dns.ValidateResponseWithRequest(reqHeader, questions, resp); err != nil {
		cleanup()
		return nil, nil, err
	}

	if needsTCP {
		cleanup()
		respTCP, err := r.queryServerTCP(ctx, server, req, reqHeader, questions)
		return respTCP, nil, err
	}
	return resp, cleanup, nil
}

func (r *Recursive) queryServerTCP(ctx context.Context, server string, req []byte, reqHeader dns.Header, questions []dns.Question) ([]byte, error) {
	resp, err := tcpQuery(ctx, server, req, defaultTimeout, false)
	if err != nil {
		return nil, err
	}
	if err := dns.ValidateResponseWithRequest(reqHeader, questions, resp); err != nil {
		return nil, err
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
		id := secureRandUint16()
		reqHeader := dns.Header{ID: id, QDCount: 1, Flags: dns.FlagRD}
		questions := []dns.Question{{Name: nsName, Type: dns.TypeA, Class: dns.ClassIN}}

		resp, cleanup, err := r.resolveIterative(ctx, reqHeader, questions, nsName, depth+1, seenCnames)
		if err != nil {
			continue
		}

		respMsg, err := dns.ReadMessagePooled(resp)
		if err != nil {
			cleanup()
			continue
		}

		for _, ans := range respMsg.Answers {
			if ans.Type == dns.TypeA && len(ans.Data) == 4 {
				ip := net.IP(ans.Data).String() + ":53"
				ips = append(ips, ip)
			}
		}
		respMsg.Release()
		cleanup()
	}

	if len(ips) == 0 {
		return nil, ErrNoGlueRecords
	}

	return ips, nil
}

func splitLabelsInto(name string, labels []string) int {
	if name == "" || name == "." {
		return 0
	}
	name = strings.TrimSuffix(name, ".")

	count := 0
	start := 0
	for i := 0; i < len(name) && count < len(labels); i++ {
		if name[i] == '.' {
			if i > start {
				labels[count] = name[start:i]
				count++
			}
			start = i + 1
		}
	}
	if start < len(name) && count < len(labels) {
		labels[count] = name[start:]
		count++
	}
	return count
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
				if !dnsutil.IsSubdomain(nsOwner, zoneNorm) && nsOwner != zoneNorm {
					continue
				}
			}

			nsName := dnsutil.ExtractNameFromData(fullMsg, rr.DataOffset)
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
			if !dnsutil.IsSubdomain(nsNameNorm, zoneNorm) {
				continue
			}
		}
		if ips, ok := nsIPs[nsName]; ok {
			glueIPs = append(glueIPs, ips...)
		}
	}

	return nsNames, glueIPs
}
