# PicoDNS

High-performance, lightweight DNS forwarding proxy in Go. Built for speed, reliability, and security.

## Features
- **Fast**: Concurrent worker pool with bounded queues and zero-allocation buffer reuse.
- **Reliable**: Automatic TCP fallback, negative caching, and upstream failover.
- **Secure**: Strict protocol validation, loop protection, and memory-safe parsing.
- **Smart**: TTL-aware LRU cache and deep observability through atomic metrics.

## What makes PicoDNS different?
- **Zero-Allocation Hot Path**: Buffer pooling via `sync.Pool` with pointer-optimized lifecycle management to minimize GC pressure.
- **Resilient Protocol Parsing**: Built-in protection against DNS compression loops and malformed packet resource exhaustion.
- **Full TCP Fallback**: Seamlessly handles large records by failing over to TCP when UDP truncation occurs.

## Quick Start
```bash
make build
sudo ./bin/dnsd -listen :53 -upstreams 1.1.1.1:53,8.8.8.8:53
```

## Configuration
- `-listen`: Listen addresses (default `:53`)
- `-upstreams`: Upstream DNS servers
- `-workers`: Concurrent workers (default `128`)
- `-cache-size`: LRU entries (default `10000`)
- `-timeout`: Query timeout (default `5s`)

## Development
- `make test`: Run unit tests
- `make test-race`: Check for race conditions
- `make test-e2e`: Run integration tests
