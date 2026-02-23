package resolver

import (
	"errors"
	"time"
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

// commonTLDs is a list of common TLDs used for cache warmup.
var commonTLDs = []string{
	"com", "net", "org", "edu", "gov", "io", "ai", "co", "in", "me", "dev", "app", "sh", "is",
}

// Recursive resolver constants
const (
	maxRecursionDepth = 32
	defaultTimeout    = 1000 * time.Millisecond

	// ConnPoolIdleTimeout is how long idle connections are kept in the pool
	ConnPoolIdleTimeout = 30 * time.Second

	// ConnPoolMaxConns is the maximum number of connections in the pool
	ConnPoolMaxConns = 64

	// Prefetch settings
	prefetchThreshold      = 2                // Minimum cache hits before considering prefetch
	prefetchRemainingRatio = 10               // Prefetch when remaining TTL is less than 1/10th of original
	prefetchTimeout        = 10 * time.Second // Timeout for background prefetch operations
	serveStaleFor          = 30 * time.Second // Serve expired cache entries for this long (stale-while-revalidate)

	// Parallel query settings
	defaultMaxServers  = 3                      // Maximum concurrent servers for normal queries
	glueMaxServers     = 2                      // Maximum concurrent servers for glue queries
	minStaggerDelay    = 0 * time.Millisecond   // Minimum stagger between concurrent queries
	maxStaggerDelay    = 20 * time.Millisecond  // Maximum stagger between concurrent queries
	rttMultiplier      = 7                      // RTT multiplier for stagger (7/10 = 0.7x)
	unknownRTT         = 250 * time.Millisecond // RTT used for servers with no prior samples
	unknownStaggerRTT  = 0 * time.Millisecond   // Stagger RTT baseline when no RTT sample exists
	queryTimeoutMul    = 4                      // Per-hop timeout = RTT * mul
	minQueryTimeout    = 80 * time.Millisecond  // Lower bound for per-hop timeout
	maxQueryTimeout    = 500 * time.Millisecond // Upper bound for per-hop timeout (tail latency control)
	maxTimeoutBackoff  = 5 * time.Second        // Upper bound on timeout backoff
	baseTimeoutBackoff = 1 * time.Second        // Base backoff for timeouts

	// NS resolution settings
	maxConcurrentNSNames = 6                     // Maximum NS names to resolve concurrently
	nsResolutionTimeout  = 2 * time.Second       // Timeout for NS name resolution
	nsResolutionStagger  = 15 * time.Millisecond // Stagger between NS resolution attempts
	nsResolutionBurst    = 3                     // Launch this many NS lookups immediately before staggering
	nsCacheTTL           = 5 * time.Minute       // TTL for cached NS name resolutions

	// Negative/failure caching
	negativeFallbackTTL = 60 * time.Second // Used when NXDOMAIN lacks SOA (best-effort)
	servfailCacheTTL    = 1 * time.Second  // Cache SERVFAIL briefly to dampen retry storms

	// Cache bounds (best-effort eviction)
	maxNSCacheEntries         = 4096
	maxDelegationCacheEntries = 4096
	maxAddrCacheEntries       = 4096
	maxRTTTrackerEntries      = 2048

	// Warmup settings
	warmupQueryTimeout = 2 * time.Second       // Timeout for warmup queries
	warmupParallelism  = 4                     // Concurrent warmup workers
	warmupStagger      = 50 * time.Millisecond // Stagger between warmup queries

	// EDNS0 settings
	ednsUDPSize = 1232 // Common safe UDP size to avoid fragmentation
)

// Resolver errors
var (
	ErrMaxDepth      = errors.New("recursive resolver: max recursion depth exceeded")
	ErrNoNameservers = errors.New("recursive resolver: no nameservers found")
	ErrNoGlueRecords = errors.New("recursive resolver: no glue records for NS")
	ErrCnameLoop     = errors.New("recursive resolver: CNAME loop detected")
	ErrNoRootServers = errors.New("recursive resolver: no root servers available")
)
