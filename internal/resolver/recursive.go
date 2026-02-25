package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
	"picodns/internal/obs"
	"picodns/internal/pool"
	"picodns/internal/types"
)

type inflightRecursive struct {
	done chan struct{}
	resp []byte
	err  error
}

// Recursive performs full iterative DNS resolution starting from the root servers.
// It maintains a connection pool, RTT tracker, NS cache, and delegation cache.
type Recursive struct {
	transport       types.Transport
	bufPool         *pool.Bytes
	connPool        *connPool
	rootServers     []string
	logger          *slog.Logger
	nsCache         *cache.TTL[string, []string]
	delegationCache *delegationCache
	rttTracker      *rttTracker
	ObsEnabled      bool
	querySem        chan struct{}

	inflightMu sync.Mutex
	inflight   map[uint64]*inflightRecursive

	tracers struct {
		resolve          *obs.FuncTracer
		resolveIterative *obs.FuncTracer
		iterHopWait      *obs.FuncTracer
		iterParseMsg     *obs.FuncTracer
		iterMinimize     *obs.FuncTracer
		iterReferral     *obs.FuncTracer
		iterResolveNS    *obs.FuncTracer
		resolveNSNames   *obs.FuncTracer
		warmup           *obs.FuncTracer
		warmupRTT        *obs.FuncTracer
	}
}

// NewRecursive creates a new recursive DNS resolver.
func NewRecursive(opts ...Option) *Recursive {
	r := &Recursive{
		bufPool:         pool.DefaultPool,
		connPool:        newConnPool(),
		rootServers:     defaultRootServers,
		logger:          slog.Default(),
		nsCache:         cache.NewTTL[string, []string](nil),
		delegationCache: newDelegationCache(),
		querySem:        make(chan struct{}, 1024),
		inflight:        make(map[uint64]*inflightRecursive),
	}
	r.nsCache.MaxLen = maxNSCacheEntries

	r.tracers.resolve = obs.NewFuncTracer("Recursive.Resolve", nil)
	r.tracers.resolveIterative = obs.NewFuncTracer("Recursive.resolveIterative", r.tracers.resolve)
	r.tracers.iterHopWait = obs.NewFuncTracer("Recursive.resolveIterative.hopWait", r.tracers.resolveIterative)
	r.tracers.iterParseMsg = obs.NewFuncTracer("Recursive.resolveIterative.parseMsg", r.tracers.resolveIterative)
	r.tracers.iterMinimize = obs.NewFuncTracer("Recursive.resolveIterative.minimize", r.tracers.resolveIterative)
	r.tracers.iterReferral = obs.NewFuncTracer("Recursive.resolveIterative.referral", r.tracers.resolveIterative)
	r.tracers.iterResolveNS = obs.NewFuncTracer("Recursive.resolveIterative.resolveNS", r.tracers.resolveIterative)
	r.tracers.resolveNSNames = obs.NewFuncTracer("Recursive.resolveNSNames", r.tracers.resolveIterative)
	r.tracers.warmup = obs.NewFuncTracer("Recursive.Warmup", r.tracers.resolve)
	r.tracers.warmupRTT = obs.NewFuncTracer("Recursive.warmupRTT", r.tracers.warmup)

	r.rttTracker = newRTTTracker(r.tracers.resolveIterative)

	obs.GlobalRegistry.Register(r.tracers.resolve)
	obs.GlobalRegistry.Register(r.tracers.resolveIterative)
	obs.GlobalRegistry.Register(r.tracers.iterHopWait)
	obs.GlobalRegistry.Register(r.tracers.iterParseMsg)
	obs.GlobalRegistry.Register(r.tracers.iterMinimize)
	obs.GlobalRegistry.Register(r.tracers.iterReferral)
	obs.GlobalRegistry.Register(r.tracers.iterResolveNS)
	obs.GlobalRegistry.Register(r.tracers.resolveNSNames)
	obs.GlobalRegistry.Register(r.tracers.warmup)
	obs.GlobalRegistry.Register(r.tracers.warmupRTT)

	for _, opt := range opts {
		opt(r)
	}
	if r.transport == nil {
		r.transport = NewTransport(r.bufPool, r.connPool, defaultTimeout)
	}
	return r
}

// SetObsEnabled enables or disables observability (stats collection) on the
// resolver and its internal caches and transport.
func (r *Recursive) SetObsEnabled(enabled bool) {
	r.ObsEnabled = enabled
	if r.nsCache != nil {
		r.nsCache.ObsEnabled = enabled
	}
	if r.delegationCache != nil && r.delegationCache.TTL != nil {
		r.delegationCache.ObsEnabled = enabled
	}
	if t, ok := r.transport.(*udpTransport); ok {
		t.SetObsEnabled(enabled)
	}
}

// NSCacheStatsSnapshot returns a point-in-time snapshot of the NS name cache statistics.
func (r *Recursive) NSCacheStatsSnapshot() cache.TTLStatsSnapshot {
	if r.nsCache == nil {
		return cache.TTLStatsSnapshot{}
	}
	return r.nsCache.StatsSnapshot()
}

// DelegationCacheStatsSnapshot returns a point-in-time snapshot of the delegation cache statistics.
func (r *Recursive) DelegationCacheStatsSnapshot() cache.TTLStatsSnapshot {
	if r.delegationCache == nil || r.delegationCache.TTL == nil {
		return cache.TTLStatsSnapshot{}
	}
	return r.delegationCache.StatsSnapshot()
}

// TransportAddrCacheStatsSnapshot returns a point-in-time snapshot of the transport address cache statistics.
func (r *Recursive) TransportAddrCacheStatsSnapshot() cache.TTLStatsSnapshot {
	if t, ok := r.transport.(*udpTransport); ok && t.addrCache != nil {
		return t.addrCache.StatsSnapshot()
	}
	return cache.TTLStatsSnapshot{}
}

// resolutionStats tracks resolution metrics
type resolutionStats struct {
	hops         int           // Successful referral hops (root -> TLD -> auth)
	totalQueries atomic.Uint32 // All query attempts including failures
	glueLookups  int           // NS name resolution queries (when no glue records)
}

// Resolve resolves a DNS query by iteratively querying authoritative servers
// from the root. It deduplicates concurrent identical queries.
func (r *Recursive) Resolve(ctx context.Context, req []byte) ([]byte, func(), error) {
	defer r.tracers.resolve.Trace()()

	hdr, err := dns.ReadHeader(req)
	if err != nil || hdr.QDCount == 0 {
		return nil, nil, errors.New("recursive resolver: invalid request")
	}
	q, _, qErr := dns.ReadQuestion(req, dns.HeaderLen)
	if qErr != nil {
		return nil, nil, errors.New("recursive resolver: invalid request")
	}

	key := hashQuestion(q.Name, q.Type, q.Class)

	call, leader := r.acquireInflightRecursive(key)
	if !leader {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-call.done:
		}
		if call.err != nil {
			return nil, nil, call.err
		}
		resp := make([]byte, len(call.resp))
		copy(resp, call.resp)
		setResponseID(resp, hdr.ID)
		return resp, nil, nil
	}

	// Leader path: resolve once, then publish a deep copy to waiters.
	// Waiters must never observe pooled backing bytes or share cleanup funcs.
	var (
		outResp    []byte
		outCleanup func()
		outErr     error
	)
	defer func() {
		rec := recover()
		if rec != nil {
			call.err = fmt.Errorf("recursive resolver panic: %v", rec)
			call.resp = nil
		} else {
			call.err = outErr
			if outErr == nil && outResp != nil {
				respCopy := make([]byte, len(outResp))
				copy(respCopy, outResp)
				call.resp = respCopy
			} else {
				call.resp = nil
			}
		}
		close(call.done)
		r.releaseInflightRecursive(key)
		if rec != nil {
			panic(rec)
		}
	}()

	stats := &resolutionStats{}
	outResp, outCleanup, outErr = r.resolveIterative(ctx, hdr, []dns.Question{q}, q.Name, 0, nil, stats, false)
	return outResp, outCleanup, outErr
}

func (r *Recursive) acquireInflightRecursive(key uint64) (*inflightRecursive, bool) {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()

	if existing, ok := r.inflight[key]; ok {
		return existing, false
	}

	call := &inflightRecursive{done: make(chan struct{})}
	r.inflight[key] = call
	return call, true
}

func (r *Recursive) releaseInflightRecursive(key uint64) {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	delete(r.inflight, key)
}

// resolveIterative performs iterative DNS resolution starting from root servers.
// It follows referrals until it gets an answer or reaches max depth.
// It rebuilds queries if the name changes (e.g. following CNAME) and
// performs bailiwick checking: root can provide glue for any TLD, but
// TLDs should only provide glue for in-bailiwick nameservers.
func (r *Recursive) resolveIterative(ctx context.Context, reqHeader dns.Header, questions []dns.Question, name string, depth int, seenCnames map[string]struct{}, stats *resolutionStats, isGlue bool) ([]byte, func(), error) {
	sampled := r.tracers.resolveIterative.ShouldSample()
	done := r.tracers.resolveIterative.TraceSampled(sampled)
	defer done()

	if depth >= maxRecursionDepth {
		return nil, nil, ErrMaxDepth
	}

	clientID := reqHeader.ID
	debugEnabled := r.logger != nil && r.logger.Enabled(ctx, slog.LevelDebug)

	questions = []dns.Question{{Name: name, Type: questions[0].Type, Class: questions[0].Class}}
	q := questions[0]

	zone, servers, ok := r.delegationCache.FindLongestMatchingZone(name)
	if !ok {
		servers = append([]string(nil), r.rootServers...)
		zone = "."
	} else {
		servers = append([]string(nil), servers...)
	}

	attempt := 0
	for range maxRecursionDepth {
		attempt++
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		var hopStart time.Time
		if debugEnabled {
			hopStart = time.Now()
		}

		var gotReferral bool
		var lastErr error

		type queryResult struct {
			resp    []byte
			cleanup func()
			err     error
			server  string
		}

		maxServers := defaultMaxServers
		if isGlue {
			maxServers = glueMaxServers
		}
		servers = r.rttTracker.SortBest(ctx, servers, maxServers)

		resultChan := make(chan queryResult, len(servers))
		queryCtx, cancelQueries := context.WithCancel(ctx)

		for i, server := range servers {
			go func(srv string, idx int) {
				res := queryResult{server: srv}
				defer func() { resultChan <- res }()

				if idx > 0 {
					prevRTT, ok := r.rttTracker.Get(queryCtx, servers[idx-1])
					if !ok {
						prevRTT = unknownStaggerRTT
					}
					stagger := prevRTT * rttMultiplier / 10
					if stagger < minStaggerDelay {
						stagger = minStaggerDelay
					}
					if stagger > maxStaggerDelay {
						stagger = maxStaggerDelay
					}
					if !sleepOrDone(queryCtx, stagger) {
						res.err = queryCtx.Err()
						return
					}
				}
				if stats != nil {
					stats.totalQueries.Add(1)
				}

				outID := secureRandUint16()
				bufPtr := r.bufPool.Get()
				buf := *bufPtr
				n, err := dns.BuildQueryIntoWithEDNS(buf, outID, name, q.Type, q.Class, ednsUDPSize)
				if err != nil {
					r.bufPool.Put(bufPtr)
					res.err = err
					return
				}
				query := buf[:n]
				startQ := time.Now()
				rtt, ok := r.rttTracker.Get(queryCtx, srv)
				if !ok || rtt <= 0 {
					rtt = unknownRTT
				}
				qTimeout := rtt * queryTimeoutMul
				qTimeout = min(maxQueryTimeout, max(minQueryTimeout, qTimeout))
				select {
				case r.querySem <- struct{}{}:
					defer func() { <-r.querySem }()
				case <-queryCtx.Done():
					r.bufPool.Put(bufPtr)
					res.err = queryCtx.Err()
					return
				}

				resp, cleanup, err := r.transport.Query(queryCtx, srv, query, qTimeout)
				r.bufPool.Put(bufPtr)
				if err == nil {
					r.rttTracker.Update(queryCtx, srv, time.Since(startQ))
				} else {
					r.rttTracker.Failure(queryCtx, srv)
				}
				if err == nil {
					validateHeader := dns.Header{ID: outID, QDCount: 1}
					if vErr := dns.ValidateResponseWithRequest(validateHeader, questions, resp); vErr != nil {
						if cleanup != nil {
							cleanup()
						}
						res.err = vErr
						return
					}
				}
				res.resp = resp
				res.cleanup = cleanup
				res.err = err
			}(server, i)
		}

		var resp []byte
		var cleanup func()
		var respServer string
		received := 0
		var ctxErr error
		// Receive results; pick a winner (first success) but ensure all other
		// successful results have their cleanup called to return pooled buffers
		// and release pooled UDP conns.
		segWait := r.tracers.iterHopWait.TraceNested(sampled)
		for received < len(servers) {
			select {
			case res := <-resultChan:
				received++
				if res.err == nil {
					if ctxErr != nil {
						if res.cleanup != nil {
							res.cleanup()
						}
						continue
					}
					if resp == nil {
						resp = res.resp
						cleanup = res.cleanup
						respServer = res.server
						if stats != nil {
							stats.hops++
						}
						cancelQueries()

						// Drain remaining results in the background so we always run
						// cleanup for non-winning successful queries.
						remaining := len(servers) - received
						if remaining > 0 {
							go func(n int) {
								for i := 0; i < n; i++ {
									r := <-resultChan
									if r.cleanup != nil {
										r.cleanup()
									}
								}
							}(remaining)
						}
						received = len(servers)
						break
					}
					if res.cleanup != nil {
						res.cleanup()
					}
				} else if ctxErr == nil {
					lastErr = res.err
				}
			case <-ctx.Done():
				if ctxErr == nil {
					ctxErr = ctx.Err()
					cancelQueries()
				}
			}
		}
		segWait()
		cancelQueries()

		if ctxErr != nil && resp == nil {
			return nil, nil, ctxErr
		}

		if resp == nil {
			if debugEnabled {
				r.logger.Debug("dns recursive hop failed",
					"name", name,
					"type", q.Type,
					"zone", zone,
					"attempt", attempt,
					"servers", len(servers),
					"duration", time.Since(hopStart),
					"error", lastErr)
			}
			if lastErr != nil {
				return nil, nil, lastErr
			}
			return nil, nil, ErrNoNameservers
		}

		segParse := r.tracers.iterParseMsg.TraceNested(sampled)
		respMsg, err := dns.ReadMessagePooled(resp)
		segParse()
		if err != nil {
			cleanupBoth(nil, cleanup)
			return nil, nil, err
		}

		if debugEnabled {
			rcode := respMsg.Header.Flags & 0x000F
			kind := "empty"
			if len(respMsg.Answers) > 0 {
				kind = "answer"
			} else if rcode == dns.RcodeNXDomain {
				kind = "nxdomain"
			} else if len(respMsg.Authorities) > 0 {
				kind = "referral"
			}
			r.logger.Debug("dns recursive hop",
				"name", name,
				"type", q.Type,
				"zone", zone,
				"attempt", attempt,
				"server", respServer,
				"duration", time.Since(hopStart),
				"rcode", rcode,
				"result", kind)
		}

		if len(respMsg.Answers) > 0 {
			for _, ans := range respMsg.Answers {
				if ans.Type == dns.TypeCNAME {
					if ans.Name != name {
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
			segMin := r.tracers.iterMinimize.TraceNested(sampled)
			minimized, _ := minimizeAndSetID(resp, clientID, false)
			segMin()
			return minimized, cleanup, nil
		}

		if (respMsg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
			respMsg.Release()
			segMin := r.tracers.iterMinimize.TraceNested(sampled)
			minimized, _ := minimizeAndSetID(resp, clientID, true)
			segMin()
			return minimized, cleanup, nil
		}

		if len(respMsg.Authorities) > 0 {
			childZone := zone
			minTTL := uint32(3600)
			for _, auth := range respMsg.Authorities {
				if auth.Type == dns.TypeNS {
					authZone := auth.Name
					if authZone != "" {
						childZone = authZone
					}
				}
				if auth.TTL > 0 && auth.TTL < minTTL {
					minTTL = auth.TTL
				}
			}
			childZone = dns.NormalizeName(childZone)
			if childZone == "" {
				childZone = zone
			}

			bailiwickZone := zone
			if zone != "." {
				bailiwickZone = childZone
			}
			segRef := r.tracers.iterReferral.TraceNested(sampled)
			nsServers, glueIPs, glueByNS := extractReferral(resp, *respMsg, bailiwickZone)
			segRef()
			respMsg.Release()
			if len(nsServers) == 0 {
				cleanupBoth(nil, cleanup)
				continue
			}

			if len(glueIPs) > 0 {
				// Populate nsCache from glue so subsequent glue-less referrals can avoid
				// extra A lookups for the same NS names.
				for nsName, ips := range glueByNS {
					if len(ips) > 0 {
						r.nsCache.Set(nsName, ips, nsCacheTTL)
					}
				}
				servers = glueIPs
				r.delegationCache.Set(childZone, glueIPs, time.Duration(minTTL)*time.Second)
				cleanupBoth(nil, cleanup)
			} else {
				segNS := r.tracers.iterResolveNS.TraceNested(sampled)
				resolvedIPs, err := r.resolveNSNames(ctx, nsServers, depth+1, seenCnames, stats)
				segNS()
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
	defer r.tracers.resolveNSNames.Trace()()

	if depth >= maxRecursionDepth {
		return nil, ErrMaxDepth
	}
	var cachedIPs []string
	var uncachedNames []string
	for _, nsName := range nsNames {
		nsName = dns.NormalizeName(nsName)
		if nsName == "" {
			continue
		}
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
		ips          []string
		glueLookups  int
		totalQueries uint32
	}
	results := make(chan result, len(uncachedNames))
	nsCtx, nsCancel := context.WithTimeout(ctx, nsResolutionTimeout)
	defer nsCancel()

	var wg sync.WaitGroup
	resolvedCount := atomic.Uint32{}
	errorCount := atomic.Uint32{}

	for i, nsName := range uncachedNames {
		if i >= maxConcurrentNSNames {
			break
		}
		// Launch a small burst immediately to avoid tail latency from serial NS
		// hostname resolution (glue-less referrals). Then stagger additional lookups.
		if i >= nsResolutionBurst {
			if resolvedCount.Load() >= 1 {
				break
			}
			if !sleepOrDone(nsCtx, nsResolutionStagger) {
				break
			}
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
			case results <- result{ips: nsIPs, glueLookups: nsStats.hops, totalQueries: nsStats.totalQueries.Load()}:
			case <-nsCtx.Done():
			}
			cleanupBoth(respMsg, cleanup)
		}(nsName)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	allIPs := cachedIPs
	for res := range results {
		allIPs = append(allIPs, res.ips...)
		if stats != nil {
			stats.glueLookups += res.glueLookups
			stats.totalQueries.Add(res.totalQueries)
		}
		if len(allIPs) >= 1 {
			nsCancel()
			return allIPs, nil
		}
	}
	if len(allIPs) == 0 {
		return nil, fmt.Errorf("%w (failed: %d)", ErrNoGlueRecords, errorCount.Load())
	}
	return allIPs, nil
}
