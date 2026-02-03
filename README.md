# PicoDNS

High-performance, lightweight DNS forwarding proxy in Go. Built for speed and security.

## Features
- **Zero-Allocation**: Buffer pooling via `sync.Pool` minimizes GC and latency.
- **Negative Caching**: RFC-compliant `NXDOMAIN` caching with SOA TTL extraction.
- **TCP Fallback**: Automatic failover to TCP for large records.
- **Loop Protection**: Built-in detection of malicious DNS compression loops.
- **Strict Validation**: Deep verification of IDs and questions ensures integrity.

## Quick Start
```bash
make build
sudo ./bin/dnsd -listen :53 -upstreams 1.1.1.1:53,8.8.8.8:53
```

## Configuration
- `-listen`: Listen addresses (default `:53`)
- `-upstreams`: Upstream DNS servers
- `-workers`: Concurrency limit (default `128`)
- `-queue-size`: Max burst capacity (default `256`)
- `-cache-size`: LRU entries (default `10000`)
- `-timeout`: Query timeout (default `5s`)
- `-log-level`: Log verbosity (debug, info, warn, error)

## Development
- `make test`: Run unit tests
- `make test-race`: Check for races
- `-make test-e2e`: Run E2E tests
