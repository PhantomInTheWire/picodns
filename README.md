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
- `-recursive`: Use recursive resolver (iterative resolution from root servers)
- `-workers`: Concurrency limit (default `128`)
- `-queue-size`: Max burst capacity (default `256`)
- `-cache-size`: LRU entries (default `10000`)
- `-timeout`: Query timeout (default `5s`)
- `-log-level`: Log verbosity (debug, info, warn, error)

## Recursive Mode

Run as a recursive resolver (queries root servers directly, no upstream forwarding):

```bash
# Build the server
make build

# Run in recursive mode on port 53 (requires root/sudo for port 53)
sudo ./bin/dnsd -recursive -listen :53

# Or run on a non-privileged port
./bin/dnsd -recursive -listen :1053
```

### Testing Recursive Mode

Send DNS queries through your recursive server:

```bash
# Using dig
dig @127.0.0.1 -p 53 example.com
dig @127.0.0.1 -p 53 google.com A
dig @127.0.0.1 -p 53 cloudflare.com AAAA
dig @127.0.0.1 -p 53 github.com MX

# Using nslookup
nslookup example.com 127.0.0.1

# Using host
host example.com 127.0.0.1
```

### Recursive Mode Features

- **Root-to-Leaf Resolution**: Performs iterative queries from root servers down to authoritative servers
- **Bailiwick Protection**: Rejects out-of-bailiwick glue records to prevent cache poisoning
- **CNAME Following**: Automatically follows CNAME chains to final answers
- **TCP Fallback**: Falls back to TCP for truncated UDP responses
- **Full Record Support**: Supports A, AAAA, MX, TXT, and other record types

## Development
- `make test`: Run unit tests
- `make test-race`: Check for races
- `make test-e2e`: Run E2E tests
