package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/pool"
	"picodns/internal/types"
)

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
func WithTransport(transport types.Transport) Option {
	return func(r *Recursive) {
		r.transport = transport
	}
}

// Recursive is a recursive DNS resolver that performs iterative resolution
// starting from root servers and following referrals.
type Recursive struct {
	transport       types.Transport
	bufPool         *pool.Bytes
	connPool        *connPool
	rootServers     []string
	logger          *slog.Logger
	nsCache         *cache.TTL[string, []string]
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
		nsCache:         cache.NewTTL[string, []string](nil),
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
	// For single-question queries (the vast majority), use slice directly
	var questions []dns.Question
	if len(reqMsg.Questions) == 1 {
		questions = reqMsg.Questions
	} else {
		questions = make([]dns.Question, len(reqMsg.Questions))
		copy(questions, reqMsg.Questions)
	}
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

	bufPtr := r.bufPool.Get()
	buf := *bufPtr
	n, err := dns.BuildQueryInto(buf, reqHeader.ID, name, q.Type, q.Class)
	if err != nil {
		r.bufPool.Put(bufPtr)
		return nil, nil, err
	}
	query := buf[:n]
	defer r.bufPool.Put(bufPtr)

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

		maxServers := defaultMaxServers
		if isGlue {
			maxServers = glueMaxServers
		}
		servers = r.rttTracker.SortBest(servers, maxServers)

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
					timer := time.NewTimer(stagger)
					select {
					case <-timer.C:
					case <-queryCtx.Done():
						timer.Stop()
						return
					}
				}
				if stats != nil {
					stats.totalQueries.Add(1)
				}
				startQ := time.Now()
				resp, cleanup, err := r.transport.Query(queryCtx, srv, query)
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

// resolveNSNames resolves the IP addresses of nameservers when glue records are missing.
// This is a recursive call to get A records for NS hostnames.
func (r *Recursive) resolveNSNames(ctx context.Context, nsNames []string, depth int, seenCnames map[string]struct{}, stats *resolutionStats) ([]string, error) {
	if depth >= maxRecursionDepth {
		return nil, ErrMaxDepth
	}
	var cachedIPs []string
	var uncachedNames []string
	for _, nsName := range nsNames {
		if cached, ok := r.nsCache.Get(nsName); ok {
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
			timer := time.NewTimer(nsResolutionStagger)
			select {
			case <-timer.C:
			case <-nsCtx.Done():
				timer.Stop()
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
					nsIPs = append(nsIPs, formatIPPort(net.IP(ans.Data), 53))
				}
			}
			if len(nsIPs) > 0 {
				r.nsCache.Set(name, nsIPs, nsCacheTTL)
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
