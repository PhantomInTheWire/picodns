# PicoDNS

High-performance, lightweight DNS resolver and forwarding proxy in Go.

## Quick Start

```bash
make run # regular mode
make run-recursive # recursive mode

# manual
./bin/dnsd -listen :1053 -upstreams 1.1.1.1:53,8.8.8.8:53

# see all flags
./bin/dnsd -h
```

## Capabilities

It supports both UDP and TCP queries. It also has a recursive mode that doesn't depend on upstream services and performs full recursion: it starts at the root servers (`.`), follows NS delegations down to the authoritative server for the domain, and queries it directly. It supports common DNS types like A, AAAA, MX, TXT, NS, SOA, CNAME, and more, including CNAME chain resolution (e.g. `example.com` -> `cdn.example.com`).

It respects negative caching and TTL. Security features include: bailiwick checking (prevents cache poisoning), CNAME loop detection, max recursion depth (32), query timeouts, connection pooling (max 64), worker queue with backpressure, transaction ID validation, message size limits (4096 bytes), TTL clamping (5s min, 24h max), and secure random transaction IDs etc.

## Benchmarking

`make bench` runs `scripts/bench.sh` (uses `dnsperf`; optionally compares against `kresd`). The script:

- builds with `make build-perf`
- runs PicoDNS with `-stats` and writes a perf JSON report to `perf/picodns-perf.json`
- writes runtime logs to `/tmp/picodns.log`

You can override the perf output location:

```bash
PERF_REPORT_PATH="$PWD/perf/picodns-perf.json" make bench
```

## Stats / Perf Reports

- `-stats` prints a one-time stats summary on shutdown.
- Perf tracing is enabled only in perf builds (`make build-perf`). When enabled, the function timing report is written to `-perf-report` (default: `perf/picodns-perf.json`) and is not printed to stdout/stderr.
