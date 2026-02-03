# PicoDNS

High-performance, lightweight DNS forwarding proxy in Go. Built for speed, reliability, and security.

## Features
- **Fast**: Concurrent worker pool with bounded queues and zero-allocation metrics.
- **Reliable**: Automatic TCP fallback, negative caching, and upstream failover.
- **Secure**: Strict protocol validation, loop protection, and memory-safe parsing.
- **Smart**: TTL-aware LRU cache and deep observability through structured logs.

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
