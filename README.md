# PicoDNS

PicoDNS is a high-performance, lightweight DNS forwarding server written in Go. It features a built-in LRU cache, worker pool for concurrent request handling, and atomic metrics for observability.

## Architecture Overview

PicoDNS is designed with a focus on simplicity and performance:

- **Server**: Orchestrates multiple UDP listeners and manages a worker pool.
- **Worker Pool**: A configurable number of goroutines process incoming DNS packets from a shared queue, preventing resource exhaustion under high load.
- **Resolver**:
    - **Cached Resolver**: Intercepts requests to check the local LRU cache before forwarding to upstreams.
    - **Upstream Resolver**: Handles communication with external DNS servers (e.g., Cloudflare, Google) with support for timeouts and failover.
- **Cache**: An in-memory LRU cache that respects DNS TTLs.
- **Metrics**: Uses `sync/atomic` for zero-allocation tracking of operational statistics.

## Supported Record Types

PicoDNS is largely record-type agnostic as a forwarding proxy. It has been tested with common types including:
- `A` (IPv4 address)
- `AAAA` (IPv6 address)
- `CNAME` (Canonical name)
- `MX` (Mail exchange)
- `TXT` (Text records)
- `SRV` (Service locator)

The server correctly parses and caches any valid DNS resource record based on the TTL provided by upstream responses.

## Threat Model & Security

While PicoDNS is suitable for local development and private networks, users should be aware of the following:

- **DNSSEC**: PicoDNS does NOT currently perform DNSSEC validation. It will forward DNSSEC-related records (RRSIG, DNSKEY, etc.), but it cannot guarantee the authenticity of responses.
- **Cache Poisoning**: Basic protections are in place (matching Query ID and Question), but it lacks advanced mitigation techniques against sophisticated cache poisoning attacks.
- **No Encryption**: This version focuses on standard DNS over UDP. It does not support DoH (DNS over HTTPS) or DoT (DNS over TLS) for client-to-server or server-to-upstream communication.
- **DDoS**: While the worker pool and queue limits provide some protection against load spikes, it is not hardened against intentional DDoS attacks.

## Deployment Instructions

### Prerequisites
- Go 1.25 or later
- Root/Admin privileges (to bind to port 53)

### Building
```bash
make build
# or
go build -o dnsd ./cmd/dnsd
```

### Running
```bash
./dnsd -listen :53 -upstreams 1.1.1.1:53,8.8.8.8:53 -workers 256
```

### Configuration Flags
- `-listen`: Comma-separated list of UDP addresses to listen on (default ":53").
- `-upstreams`: Comma-separated list of upstream DNS servers (default "1.1.1.1:53").
- `-workers`: Number of concurrent worker goroutines (default 128).
- `-queue-size`: Maximum number of packets to queue before dropping (default 256).
- `-cache-size`: Maximum number of entries in the LRU cache (default 10000).
- `-timeout`: Upstream query timeout (default 5s).
- `-log-level`: Logging verbosity (debug, info, warn, error).

## Operational Notes

### Observability
PicoDNS tracks the following metrics internally:
- **Total Queries**: Total number of packets received.
- **Dropped Packets**: Packets dropped due to a full worker queue.
- **Cache Hits/Misses**: Effectiveness of the local cache.
- **Upstream Latency**: Total time spent waiting for upstream responses.
- **Errors**: Granular tracking of handler and write errors.

These metrics are currently exposed via logs at the `info` level and can be integrated into telemetry systems by extending the `Server` struct.

### Performance Tuning
- For high-throughput environments, increase `-workers` and `-queue-size`.
- Ensure the OS UDP buffer limits are sufficient for the expected packet volume.
