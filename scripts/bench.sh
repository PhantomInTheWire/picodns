#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DURATION="${DURATION:-10}"
QPS="${QPS:-20000}"
PORT="${PORT:-1053}"
UDP_SOCKETS="${UDP_SOCKETS:-4}"
QUERY_FILE="${QUERY_FILE:-${ROOT_DIR}/queries.txt}"
KNOT_PORT="${KNOT_PORT:-1054}"
KNOT_WORKERS="${KNOT_WORKERS:-1}"
START_DELAY="${START_DELAY:-2}"
WARMUP_DURATION="${WARMUP_DURATION:-2}"
WARMUP_QPS="${WARMUP_QPS:-2000}"

if ! command -v dnsperf >/dev/null 2>&1; then
  echo "dnsperf not found. Install with: brew install dnsperf" >&2
  exit 1
fi

cd "${ROOT_DIR}"

make build

DNSD_PID=""
KRESD_PID=""
KRESD_DIR=""
PICO_RESULT=""
PICO_STATS_SERVER=""
PICO_STATS_CACHE=""
PICO_STATS_REC_CACHE=""
PICO_STATS_ADDR_CACHE=""
KNOT_RESULT=""

cleanup() {
  if [[ -n "${DNSD_PID}" ]]; then
    kill "${DNSD_PID}" >/dev/null 2>&1 || true
    wait "${DNSD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${KRESD_PID}" ]]; then
    kill "${KRESD_PID}" >/dev/null 2>&1 || true
    wait "${KRESD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${KRESD_DIR}" ]]; then
    rm -rf "${KRESD_DIR}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

./bin/dnsd -recursive -listen "127.0.0.1:${PORT}" -udp-sockets "${UDP_SOCKETS}" -stats > /tmp/picodns.log 2>&1 &
DNSD_PID=$!
sleep "${START_DELAY}"

echo "== PicoDNS recursive (local) =="
if [[ "${WARMUP_DURATION}" != "0" ]]; then
  echo "-- warmup ${WARMUP_DURATION}s @ ${WARMUP_QPS} QPS"
  dnsperf -s 127.0.0.1 -p "${PORT}" -d "${QUERY_FILE}" -l "${WARMUP_DURATION}" -Q "${WARMUP_QPS}" > /dev/null 2>&1 || true
fi
PICO_RESULT=$(dnsperf -s 127.0.0.1 -p "${PORT}" -d "${QUERY_FILE}" -l "${DURATION}" -Q "${QPS}" 2>&1)
echo "${PICO_RESULT}"

kill "${DNSD_PID}" >/dev/null 2>&1 || true
wait "${DNSD_PID}" >/dev/null 2>&1 || true
DNSD_PID=""

if [[ -f /tmp/picodns.log ]]; then
  PICO_STATS_SERVER=$(grep '"msg":"server shutdown complete"' /tmp/picodns.log | tail -1 || true)
  PICO_STATS_CACHE=$(grep '"msg":"resolver cache stats"' /tmp/picodns.log | tail -1 || true)
  PICO_STATS_REC_CACHE=$(grep '"msg":"recursive internal cache stats"' /tmp/picodns.log | tail -1 || true)
  PICO_STATS_ADDR_CACHE=$(grep '"msg":"transport addr cache stats"' /tmp/picodns.log | tail -1 || true)
fi

# echo "== Cloudflare (1.1.1.1) =="
# dnsperf -s 1.1.1.1 -p 53 -d "${QUERY_FILE}" -l "${DURATION}" -Q "${QPS}"

# echo "== Google (8.8.8.8) =="
# dnsperf -s 8.8.8.8 -p 53 -d "${QUERY_FILE}" -l "${DURATION}" -Q "${QPS}"

if command -v kresd >/dev/null 2>&1; then
  echo "== Knot Resolver (local) =="
  KRESD_DIR="$(mktemp -d)"
  cat > "${KRESD_DIR}/config" <<EOF
net.listen('127.0.0.1', ${KNOT_PORT})
cache.size = 100 * MB
EOF
  kresd -n -q -c config "${KRESD_DIR}" > /tmp/kresd.log 2>&1 &
  KRESD_PID=$!
  sleep "${START_DELAY}"
  if kill -0 "${KRESD_PID}" >/dev/null 2>&1; then
    if [[ "${WARMUP_DURATION}" != "0" ]]; then
      echo "-- warmup ${WARMUP_DURATION}s @ ${WARMUP_QPS} QPS"
      dnsperf -s 127.0.0.1 -p "${KNOT_PORT}" -d "${QUERY_FILE}" -l "${WARMUP_DURATION}" -Q "${WARMUP_QPS}" > /dev/null 2>&1 || true
    fi
    KNOT_RESULT=$(dnsperf -s 127.0.0.1 -p "${KNOT_PORT}" -d "${QUERY_FILE}" -l "${DURATION}" -Q "${QPS}" 2>&1)
    echo "${KNOT_RESULT}"
    kill "${KRESD_PID}" >/dev/null 2>&1 || true
    wait "${KRESD_PID}" >/dev/null 2>&1 || true
    KRESD_PID=""
  else
    echo "kresd failed to start; see /tmp/kresd.log" >&2
  fi
else
  echo "kresd not found; install with: brew install knot-resolver" >&2
fi

echo ""
echo "========================================"
echo "           SUMMARY"
echo "========================================"
echo ""
echo "PicoDNS Results:"
echo "----------------"
echo "${PICO_RESULT}" | tail -16
echo ""
echo "PicoDNS Stats (shutdown):"
echo "-------------------------"
if [[ -n "${PICO_STATS_SERVER}" ]]; then
  echo "${PICO_STATS_SERVER}"
fi
if [[ -n "${PICO_STATS_CACHE}" ]]; then
  echo "${PICO_STATS_CACHE}"
fi
if [[ -n "${PICO_STATS_REC_CACHE}" ]]; then
  echo "${PICO_STATS_REC_CACHE}"
fi
if [[ -n "${PICO_STATS_ADDR_CACHE}" ]]; then
  echo "${PICO_STATS_ADDR_CACHE}"
fi
if [[ -z "${PICO_STATS_SERVER}${PICO_STATS_CACHE}${PICO_STATS_REC_CACHE}${PICO_STATS_ADDR_CACHE}" ]]; then
  echo "(no stats found; ensure dnsd started with -stats and see /tmp/picodns.log)"
fi
echo ""
if [[ -n "${KNOT_RESULT}" ]]; then
  echo "Knot Results:"
  echo "-------------"
  echo "${KNOT_RESULT}" | tail -16
fi
