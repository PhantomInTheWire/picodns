package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/dns"
	"picodns/internal/pool"
)

// defaultRootServers contains the default DNS root server addresses.
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

// WithTransport sets a custom transport for the recursive resolver.
// This is primarily used for testing with mock transports.
func WithTransport(transport Transport) Option {
	return func(r *Recursive) {
		r.transport = transport
	}
}

const (
	maxRecursionDepth = 32
	defaultTimeout    = 2 * time.Second

	// ConnPoolIdleTimeout is how long idle connections are kept in the pool
	ConnPoolIdleTimeout = 30 * time.Second

	// ConnPoolMaxConns is the maximum number of connections in the pool
	ConnPoolMaxConns = 64

	// Prefetch settings
	prefetchThreshold      = 2                // Minimum cache hits before considering prefetch
	prefetchRemainingRatio = 10               // Prefetch when remaining TTL is less than 1/10th of original
	prefetchTimeout        = 10 * time.Second // Timeout for background prefetch operations

	// Parallel query settings
	defaultMaxServers = 3                      // Maximum concurrent servers for normal queries
	glueMaxServers    = 2                      // Maximum concurrent servers for glue queries
	minStaggerDelay   = 30 * time.Millisecond  // Minimum stagger between concurrent queries
	maxStaggerDelay   = 400 * time.Millisecond // Maximum stagger between concurrent queries
	rttMultiplier     = 12                     // RTT multiplier for stagger (12/10 = 1.2x)

	// NS resolution settings
	maxConcurrentNSNames = 4                     // Maximum NS names to resolve concurrently
	nsResolutionTimeout  = 3 * time.Second       // Timeout for NS name resolution
	nsResolutionStagger  = 50 * time.Millisecond // Stagger between NS resolution attempts
	nsCacheTTL           = 5 * time.Minute       // TTL for cached NS name resolutions

	// Warmup settings
	warmupQueryTimeout = 2 * time.Second // Timeout for warmup queries
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
	transport       Transport
	bufPool         *pool.Bytes
	connPool        *connPool
	rootServers     []string
	logger          *slog.Logger
	nsCache         *nsCache
	delegationCache *delegationCache
	rttTracker      *rttTracker
}

// NewRecursive creates a new recursive DNS resolver with the provided options.
// If no options are provided, the resolver uses default root servers.
func NewRecursive(opts ...Option) *Recursive {
	r := &Recursive{
		bufPool:         pool.DefaultPool,
		connPool:        newConnPool(),
		rootServers:     defaultRootServers,
		logger:          slog.Default(),
		nsCache:         newNSCache(),
		delegationCache: newDelegationCache(),
		rttTracker:      newRTTTracker(),
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.transport == nil {
		r.transport = NewTransport(r.bufPool, r.connPool, defaultTimeout)
	}
	return r
}

// resolutionStats tracks resolution metrics
type resolutionStats struct {
	hops         int           // Successful referral hops (root -> TLD -> auth)
	totalQueries atomic.Uint32 // All query attempts including failures
	glueLookups  int           // NS name resolution queries (when no glue records)
}

// nsCacheEntry stores resolved NS name IPs with expiration
type nsCacheEntry struct {
	ips     []string
	expires time.Time
}

// nsCache caches NS name to IP mappings
type nsCache struct {
	mu    sync.RWMutex
	items map[string]nsCacheEntry
}

func newNSCache() *nsCache {
	return &nsCache{
		items: make(map[string]nsCacheEntry),
	}
}

func (c *nsCache) Get(key string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.items[key]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.ips, true
}

func (c *nsCache) Set(key string, ips []string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = nsCacheEntry{
		ips:     ips,
		expires: time.Now().Add(ttl),
	}
}

// delegationEntry stores nameservers for a zone
type delegationEntry struct {
	servers []string
	expires time.Time
}

// delegationCache caches zone to nameserver IP mappings
type delegationCache struct {
	mu    sync.RWMutex
	items map[string]delegationEntry
}

func newDelegationCache() *delegationCache {
	return &delegationCache{
		items: make(map[string]delegationEntry),
	}
}

func (c *delegationCache) Get(zone string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.items[zone]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.servers, true
}

func (c *delegationCache) Set(zone string, servers []string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	c.items[zone] = delegationEntry{
		servers: servers,
		expires: time.Now().Add(ttl),
	}
}

func (c *delegationCache) FindLongestMatchingZone(name string) (string, []string, bool) {
	name = dns.NormalizeName(name)
	labels := strings.Split(name, ".")

	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := 0; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		if entry, ok := c.items[zone]; ok && time.Now().Before(entry.expires) {
			return zone, entry.servers, true
		}
	}

	return ".", nil, false
}

// rttTracker tracks nameserver response times
type rttTracker struct {
	mu   sync.RWMutex
	rtts map[string]time.Duration
}

func newRTTTracker() *rttTracker {
	return &rttTracker{
		rtts: make(map[string]time.Duration),
	}
}

func (t *rttTracker) Update(server string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.rtts[server]
	if !ok {
		t.rtts[server] = d
	} else {
		t.rtts[server] = (prev*4 + d) / 5
	}
}

func (t *rttTracker) Get(server string) time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()
	d, ok := t.rtts[server]
	if !ok {
		return 200 * time.Millisecond
	}
	return d
}

var commonTLDs = []string{
	"com", "net", "org", "edu", "gov", "io", "ai", "co", "in", "me", "dev", "app", "sh", "is",
}

func (r *Recursive) Warmup(ctx context.Context) {
	r.logger.Info("warming up recursive resolver cache for common TLDs")
	start := time.Now()

	for _, tld := range commonTLDs {
		tctx, cancel := context.WithTimeout(ctx, warmupQueryTimeout)
		id := secureRandUint16()
		reqHeader := dns.Header{ID: id, QDCount: 1, Flags: dns.FlagRD}
		questions := []dns.Question{{Name: tld + ".", Type: dns.TypeNS, Class: dns.ClassIN}}

		resp, cleanup, _ := r.resolveIterative(tctx, reqHeader, questions, tld+".", 0, nil, nil, false)
		if cleanup != nil {
			cleanup()
		}
		_ = resp
		cancel()
	}

	r.logger.Info("warmup complete", "duration", time.Since(start))
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

	stats := &resolutionStats{}
	return r.resolveIterative(ctx, reqHeader, questions, name, 0, nil, stats, false)
}

// resolveIterative performs iterative DNS resolution starting from root servers.
// It follows referrals until it gets an answer or reaches max depth.
// It rebuilds queries if the name changes (e.g. following CNAME) and
// performs bailiwick checking: root can provide glue for any TLD, but
// TLDs should only provide glue for in-bailiwick nameservers.
func (r *Recursive) resolveIterative(ctx context.Context, reqHeader dns.Header, questions []dns.Question, name string, depth int, seenCnames map[string]struct{}, stats *resolutionStats, isGlue bool) ([]byte, func(), error) {
	if depth >= maxRecursionDepth {
		return nil, nil, ErrMaxDepth
	}

	questions = []dns.Question{{Name: name, Type: questions[0].Type, Class: questions[0].Class}}
	q := questions[0]

	zone, servers, ok := r.delegationCache.FindLongestMatchingZone(name)
	if !ok {
		servers = append([]string(nil), r.rootServers...)
		zone = "."
	} else {
		servers = append([]string(nil), servers...)
	}

	query, err := dns.BuildQuery(reqHeader.ID, name, q.Type, q.Class)
	if err != nil {
		return nil, nil, err
	}

	for range maxRecursionDepth {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		var gotReferral bool
		var lastErr error

		type queryResult struct {
			resp    []byte
			cleanup func()
			err     error
		}

		sort.Slice(servers, func(i, j int) bool {
			return r.rttTracker.Get(servers[i]) < r.rttTracker.Get(servers[j])
		})

		maxServers := defaultMaxServers
		if isGlue {
			maxServers = glueMaxServers
		}
		if len(servers) > maxServers {
			servers = servers[:maxServers]
		}

		resultChan := make(chan queryResult, len(servers))
		queryCtx, cancelQueries := context.WithCancel(ctx)
		var wg sync.WaitGroup

		for i, server := range servers {
			wg.Add(1)
			go func(srv string, idx int) {
				defer wg.Done()
				if idx > 0 {
					stagger := r.rttTracker.Get(servers[idx-1]) * rttMultiplier / 10
					if stagger < minStaggerDelay {
						stagger = minStaggerDelay
					}
					if stagger > maxStaggerDelay {
						stagger = maxStaggerDelay
					}
					select {
					case <-time.After(stagger):
					case <-queryCtx.Done():
						return
					}
				}
				if stats != nil {
					stats.totalQueries.Add(1)
				}
				startQ := time.Now()
				resp, cleanup, err := r.queryServer(queryCtx, srv, query, reqHeader, questions)
				if err == nil {
					r.rttTracker.Update(srv, time.Since(startQ))
				}
				resultChan <- queryResult{resp: resp, cleanup: cleanup, err: err}
			}(server, i)
		}

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		var resp []byte
		var cleanup func()
		for res := range resultChan {
			if res.err == nil {
				if resp == nil {
					resp = res.resp
					cleanup = res.cleanup
					if stats != nil {
						stats.hops++
					}
					cancelQueries()
				} else if res.cleanup != nil {
					res.cleanup()
				}
			} else {
				lastErr = res.err
			}
		}
		cancelQueries()

		if resp == nil {
			if lastErr != nil {
				return nil, nil, lastErr
			}
			return nil, nil, ErrNoNameservers
		}

		respMsg, err := dns.ReadMessagePooled(resp)
		if err != nil {
			cleanupBoth(nil, cleanup)
			return nil, nil, err
		}

		if len(respMsg.Answers) > 0 {
			for _, ans := range respMsg.Answers {
				if ans.Type == dns.TypeCNAME {
					if !strings.EqualFold(ans.Name, name) && !strings.EqualFold(ans.Name, name+".") {
						continue
					}
					cnameTarget := dns.ExtractNameFromData(resp, ans.DataOffset)
					if cnameTarget == "" {
						continue
					}
					if seenCnames == nil {
						seenCnames = make(map[string]struct{})
					}
					if _, seen := seenCnames[cnameTarget]; seen {
						cleanupBoth(respMsg, cleanup)
						return nil, nil, ErrCnameLoop
					}
					seenCnames[cnameTarget] = struct{}{}
					cleanupBoth(respMsg, cleanup)
					return r.resolveIterative(ctx, reqHeader, questions, cnameTarget, depth+1, seenCnames, stats, isGlue)
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
			childZone := zone
			minTTL := uint32(3600)
			for _, auth := range respMsg.Authorities {
				if auth.Type == dns.TypeNS {
					authZone := dns.NormalizeName(auth.Name)
					if authZone != "" {
						childZone = authZone
					}
				}
				if auth.TTL > 0 && auth.TTL < minTTL {
					minTTL = auth.TTL
				}
			}

			bailiwickZone := zone
			if zone != "." {
				bailiwickZone = childZone
			}
			nsServers, glueIPs := extractReferral(resp, *respMsg, bailiwickZone)
			respMsg.Release()
			if len(nsServers) == 0 {
				cleanupBoth(nil, cleanup)
				continue
			}

			if len(glueIPs) > 0 {
				servers = glueIPs
				r.delegationCache.Set(childZone, glueIPs, time.Duration(minTTL)*time.Second)
				cleanupBoth(nil, cleanup)
			} else {
				resolvedIPs, err := r.resolveNSNames(ctx, nsServers, depth+1, seenCnames, stats)
				cleanupBoth(nil, cleanup)
				if err != nil {
					continue
				}
				servers = resolvedIPs
				r.delegationCache.Set(childZone, resolvedIPs, time.Duration(minTTL)*time.Second)
			}
			zone = childZone
			gotReferral = true
			continue
		}
		cleanupBoth(respMsg, cleanup)
		if !gotReferral {
			if lastErr != nil {
				return nil, nil, lastErr
			}
			return nil, nil, ErrNoNameservers
		}
	}
	return nil, nil, ErrMaxDepth
}

func (r *Recursive) queryServer(ctx context.Context, server string, req []byte, reqHeader dns.Header, questions []dns.Question) ([]byte, func(), error) {
	resp, cleanup, err := r.transport.Query(ctx, server, req)
	if err != nil {
		return nil, nil, err
	}
	if err := dns.ValidateResponseWithRequest(reqHeader, questions, resp); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, err
	}
	return resp, cleanup, nil
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

// resolveNSNames resolves the IP addresses of nameservers when glue records are missing.
// This is a recursive call to get A records for NS hostnames.
func (r *Recursive) resolveNSNames(ctx context.Context, nsNames []string, depth int, seenCnames map[string]struct{}, stats *resolutionStats) ([]string, error) {
	if depth >= maxRecursionDepth {
		return nil, ErrMaxDepth
	}
	var cachedIPs []string
	var uncachedNames []string
	for _, nsName := range nsNames {
		cacheKey := nsName + ":" + strconv.Itoa(int(dns.TypeA))
		if cached, ok := r.nsCache.Get(cacheKey); ok {
			cachedIPs = append(cachedIPs, cached...)
		} else {
			uncachedNames = append(uncachedNames, nsName)
		}
	}
	if len(cachedIPs) >= 1 {
		return cachedIPs, nil
	}
	type result struct {
		ips   []string
		stats *resolutionStats
	}
	results := make(chan result, len(uncachedNames))
	nsCtx, nsCancel := context.WithTimeout(ctx, nsResolutionTimeout)
	defer nsCancel()

	var wg sync.WaitGroup
	resolvedCount := atomic.Uint32{}
	errorCount := atomic.Uint32{}

loop:
	for i, nsName := range uncachedNames {
		if i > 0 {
			select {
			case <-time.After(nsResolutionStagger):
			case <-nsCtx.Done():
				break loop
			}
		}
		if resolvedCount.Load() >= 1 {
			break
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			var localSeenCnames map[string]struct{}
			if seenCnames != nil {
				localSeenCnames = make(map[string]struct{}, len(seenCnames))
				for k, v := range seenCnames {
					localSeenCnames[k] = v
				}
			}

			nsStats := &resolutionStats{}
			id := secureRandUint16()
			reqHeader := dns.Header{ID: id, QDCount: 1, Flags: dns.FlagRD}
			questions := []dns.Question{{Name: name, Type: dns.TypeA, Class: dns.ClassIN}}

			resp, cleanup, err := r.resolveIterative(nsCtx, reqHeader, questions, name, depth+1, localSeenCnames, nsStats, true)
			if err != nil {
				errorCount.Add(1)
				return
			}
			respMsg, err := dns.ReadMessagePooled(resp)
			if err != nil {
				errorCount.Add(1)
				cleanupBoth(nil, cleanup)
				return
			}
			var nsIPs []string
			for _, ans := range respMsg.Answers {
				if ans.Type == dns.TypeA && len(ans.Data) == 4 {
					nsIPs = append(nsIPs, net.IP(ans.Data).String()+":53")
				}
			}
			if len(nsIPs) > 0 {
				r.nsCache.Set(name+":"+strconv.Itoa(int(dns.TypeA)), nsIPs, nsCacheTTL)
				if resolvedCount.Add(1) == 1 {
					nsCancel()
				}
			} else {
				errorCount.Add(1)
			}
			select {
			case results <- result{ips: nsIPs, stats: nsStats}:
			case <-nsCtx.Done():
			}
			cleanupBoth(respMsg, cleanup)
		}(nsName)
		if i+1 >= maxConcurrentNSNames {
			break
		}
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	allIPs := cachedIPs
	for res := range results {
		allIPs = append(allIPs, res.ips...)
		if stats != nil && res.stats != nil {
			stats.glueLookups += res.stats.hops
			stats.totalQueries.Add(res.stats.totalQueries.Load())
		}
		if len(allIPs) >= 1 {
			nsCancel()
		}
	}
	if len(allIPs) == 0 {
		return nil, fmt.Errorf("%w (failed: %d)", ErrNoGlueRecords, errorCount.Load())
	}
	return allIPs, nil
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
			ip := net.IP(rr.Data).String() + ":53"
			nsIPs[rr.Name] = append(nsIPs[rr.Name], ip)
		}
	}
	var glueIPs []string
	for _, nsName := range nsNames {
		if zoneNorm != "" {
			nsNameNorm := dns.NormalizeName(nsName)
			if !dns.IsSubdomain(nsNameNorm, zoneNorm) {
				continue
			}
		}
		if ips, ok := nsIPs[nsName]; ok {
			glueIPs = append(glueIPs, ips...)
		}
	}
	return nsNames, glueIPs
}
