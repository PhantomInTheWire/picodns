# PicoDNS

High-performance, lightweight DNS Resolver and forwarding proxy in Go. Built for speed and security.(Built mostly for educational purposes but works well on a lot of things). 

## Quick Start
```bash
make run # regular mode
make run-recursive # recursive mode
./bin/dnsd -listen :1053 -upstreams 1.1.1.1:53,8.8.8.8:53 -queue-size 128 -timeout 10 # regular mode config options
```

## Capabilities

It supports both UDP and TCP queries. It also has a recursive mode, that doesn't depend on upstream google/cloudflare services and performs full recursion: it starts at the root servers (`.`), follows NS delegations down to the authoritative server for the domain, and queries it directly. It also supports all standard DNS types like A, AAAA, MX, TXT, NS, SOA, CNAME, and more. It alo supports CNAME alias chain rsolution(eg. 'example.com' -> 'cdn.example.com').

It respects negative caching and TTL. Security features include: bailiwick checking (prevents cache poisoning), CNAME loop detection, max recursion depth (32), query timeouts, connection pooling (max 64), worker queue with backpressure, transaction ID validation, message size limits (4096 bytes), TTL clamping (5s min, 24h max), and secure random transaction IDs etc.

