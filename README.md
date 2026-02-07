# PicoDNS

High-performance, lightweight DNS forwarding proxy in Go. Built for speed and security.(Built mostly for educational purposes but works remarkably well on a lot of things)

## Features

- **Zero‑allocation request handling via `sync.Pool`**: We reuse byte buffers and message structs across requests, keeping the hot path garbage‑free and avoiding GC pauses under load.

- **Compression‑safe name parsing with loop detection**: DNS packets use "compression pointers" to repeat domain names without re‑sending bytes. Malicious or broken packets can create pointer cycles (A→B→A) that hang naive parsers. We track visited offsets and enforce a depth limit, so a poisoned packet can't DoS the server.

- **Recursive resolver mode**: Can operate as a full recursive resolver starting from root servers, not just a forwarding proxy

- **RFC 2308 negative caching with SOA‑MINIMUM extraction**  
  "NXDOMAIN" isn't just an error—it's an answer with a TTL. We parse the authority section, extract the SOA record's minimum TTL, and cache the negative result for exactly that duration. This prevents hammering upstreams for non-existent domains and respects the zone operator's intent.

- **Seamless TCP fallback for truncated responses**  
  UDP DNS is capped at 512 bytes (or 4096 with EDNS0). When a response is larger, the server sets the "TC" (truncated) bit. We detect this instantly and re-issue the query over TCP, ensuring you never lose records in large DNSSEC replies or long TXT records.

## Quick Start
```bash
make run # regular mode
make run-recursive # recursive mode
./bin/dnsd -listen :1053 -upstreams 1.1.1.1:53,8.8.8.8:53 -queue-size 128 -timeout 10 # regular mode config options
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
```

### Recursive Mode Features

- **True Iterative Resolution (No Forwarding)**  
  In recursive mode, instead of forwarding queries to Google or Cloudflare, PicoDNS performs full recursion: it starts at the root servers (`.`), follows NS delegations down to the authoritative server for the domain, and queries it directly. This eliminates a trust hop and gives you complete control over the resolution path.

- **Bailiwick Protection Against Cache Poisoning**  
  When a server refers you to a nameserver, it may include "glue" records (IP addresses for that nameserver). Malicious servers can try to sneak in glue for domains they don't control. We validate that glue records are "in bailiwick"—meaning the referring server actually has authority over the domain it's giving IPs for—preventing a classic DNS cache poisoning attack.

- **Automatic CNAME Chain Resolution**  
  DNS allows one name to alias to another via CNAME records (e.g., `www.example.com` → `cdn.example.net`). These chains can be multiple hops long. We automatically follow the entire chain until we reach the final A/AAAA record, returning the complete answer in a single query.

- **TCP Fallback for Truncated Responses**  
  UDP packets can be truncated if responses are too large (common with DNSSEC). When we see the TC (truncated) flag, we seamlessly retry the query over TCP to get the full response, ensuring reliability even for complex DNS setups.

- **Full Record Type Support**  
  Supports all standard DNS record types: A, AAAA, MX, TXT, NS, SOA, CNAME, and more. Whether you're looking up mail servers, text records, or IPv6 addresses, PicoDNS handles them correctly.

## Development
- `make test`: Run unit tests
- `make test-race`: Check for races
- `make test-e2e`: Run E2E tests
