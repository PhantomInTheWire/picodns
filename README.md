# PicoDNS

PicoDNS is a high-performance, lightweight DNS forwarding server written in Go. It is built for reliability and speed, featuring a concurrent architecture, hardened protocol parsing, and zero-allocation observability.

## Core Features

- **Concurrent Architecture**: Utilizes a configurable worker pool and bounded request queue to handle high query volumes while maintaining stable resource usage.
- **Protocol Reliability**:
    - **TCP Fallback**: Implements automatic failover to TCP when UDP responses are truncated (TC flag), ensuring large records are always deliverable.
    - **Negative Caching**: Optimizes network traffic by caching NXDOMAIN responses using SOA Minimum TTLs.
    - **Failover Support**: Supports multiple upstream DNS servers with automatic failover and configurable timeouts.
- **Security Hardened Parsing**:
    - **Validation**: Enforces strict matching of Transaction IDs and Question sections between requests and responses.
    - **Cycle Protection**: Built-in detection for malicious DNS name compression loops.
    - **Memory Safety**: Enforces maximum message sizes for both UDP and TCP to prevent resource exhaustion.
- **Smart LRU Cache**: High-performance, thread-safe in-memory cache that respects DNS TTLs and normalizes query keys.
- **Deep Observability**: Real-time tracking of cache hits/misses, upstream latency, and queue backpressure via atomic metrics.

## Architecture

PicoDNS follows a clean, layered design:

- **Server**: Manages multiple concurrent UDP listeners and dispatches work to the pool.
- **Worker Pool**: Decouples network I/O from request processing to handle bursts gracefully.
- **Resolver**: Layered system that handles local caching before delegating to upstreams.
- **DNS Core**: Specialized wire-format implementation with cycle detection and bounds checking.

## Supported Record Types

As a forwarding proxy, PicoDNS is record-type agnostic and handles all standard DNS resource records, including `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `SOA`, and more.

## Getting Started

### Prerequisites
- Go 1.25 or later
- Privileges to bind to your chosen port (e.g., 53)

### Installation
```bash
make build
```
The binary will be generated in `bin/dnsd`.

### Usage
```bash
# Start with Cloudflare and Google as upstreams
sudo ./bin/dnsd -listen :53 -upstreams 1.1.1.1:53,8.8.8.8:53
```

### Configuration
- `-listen`: Comma-separated list of UDP addresses to listen on.
- `-upstreams`: Comma-separated list of upstream servers.
- `-workers`: Number of concurrent workers (default: 128).
- `-queue-size`: Maximum packet queue depth (default: 256).
- `-cache-size`: Maximum LRU entries (default: 10000).
- `-timeout`: Upstream query timeout (default: 5s).
- `-log-level`: Logging verbosity (debug, info, warn, error).

## Quality & Testing

PicoDNS is built with a focus on correctness:
- **Unit Tests**: Full coverage for cache, wire format, and resolver logic.
- **Race Detection**: Verified thread-safety with `make test-race`.
- **E2E Suite**: Integration tests for real-world packet flow, including TCP fallback.
- **Fuzzing**: Protocol parsers are fuzzed to ensure resilience against malformed inputs.

## Observability

Monitor server health through structured logs and internal metrics:
- **Cache**: Tracking hit/miss efficiency.
- **Upstreams**: Monitoring latency and query success rates.
- **System**: Tracking dropped packets and queue saturation.
