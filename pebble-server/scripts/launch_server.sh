#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR="${BIN_DIR:-$ROOT/bin}"
mkdir -p "$BIN_DIR"

THREADS=4
POLICY="default"
LISTEN="127.0.0.1:9000"
LOG_DIR="$ROOT/logs/server"
RESULTS_DIR="$ROOT/results"
RUN_STATE_DIR="${RUN_STATE_DIR:-$ROOT/run}"
BUILD_SERVER_BIN="${BUILD_SERVER_BIN:-true}"
SERVER_BIN="${PEBBLE_SERVER_BIN:-$BIN_DIR/pebble_server}"
GET_DELAY="${GET_DELAY:-}"
SCAN_DELAY="${SCAN_DELAY:-}"
REDIS_DB="${REDIS_DB:-}"
DB_KEYS="${DB_KEYS:-}"
DB_VALUE_BYTES="${DB_VALUE_BYTES:-}"
DB_SCAN_COUNT="${DB_SCAN_COUNT:-}"
DB_KEY_PREFIX="${DB_KEY_PREFIX:-}"

usage() {
  cat <<USAGE
Usage: $0 [options]
  -t <threads>   number of worker sockets (default: $THREADS)
  -p <policy>    load-balancing policy: default|round_robin|agent|scan_split
  -l <address>   UDP listen address (default: $LISTEN)
  -o <log-dir>   directory for server logs (default: $LOG_DIR)
  -r <results>   directory to store experiment metadata (default: $RESULTS_DIR)
  -g <duration>  synthetic GET latency (passed to -get-delay)
  -s <duration>  synthetic SCAN latency (passed to -scan-delay)
USAGE
}

while getopts ":t:p:l:o:r:g:s:" opt; do
  case "$opt" in
    t) THREADS="$OPTARG" ;;
    p) POLICY="$OPTARG" ;;
    l) LISTEN="$OPTARG" ;;
    o) LOG_DIR="$OPTARG" ;;
    r) RESULTS_DIR="$OPTARG" ;;
    g) GET_DELAY="$OPTARG" ;;
    s) SCAN_DELAY="$OPTARG" ;;
    :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
    \?) usage; exit 1 ;;
  esac
done

mkdir -p "$LOG_DIR" "$RESULTS_DIR" "$RUN_STATE_DIR"

export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
if [[ "$BUILD_SERVER_BIN" == "true" ]]; then
  go build -o "$SERVER_BIN" ./cmd/pebble_server
elif [[ ! -x "$SERVER_BIN" ]]; then
  echo "Server binary missing at $SERVER_BIN; set BUILD_SERVER_BIN=true to build automatically." >&2
  exit 1
fi

PID_FILE="$RUN_STATE_DIR/server.pid"
if [[ -f "$PID_FILE" ]]; then
  if kill -0 "$(cat "$PID_FILE")" >/dev/null 2>&1; then
    echo "Existing server detected; terminating"
    kill "$(cat "$PID_FILE")" || true
    sleep 1
  fi
fi

SERVER_CMD=(
  "$SERVER_BIN"
  -listen "$LISTEN"
  -workers "$THREADS"
  -policy "$POLICY"
  -log-dir "$LOG_DIR"
  -results-dir "$RESULTS_DIR"
)
if [[ -n "$GET_DELAY" ]]; then
  SERVER_CMD+=(-get-delay "$GET_DELAY")
fi
if [[ -n "$SCAN_DELAY" ]]; then
  SERVER_CMD+=(-scan-delay "$SCAN_DELAY")
fi
if [[ -n "$REDIS_DB" ]]; then
  SERVER_CMD+=(-redis-db "$REDIS_DB")
fi
if [[ -n "$DB_KEYS" ]]; then
  SERVER_CMD+=(-db-keys "$DB_KEYS")
fi
if [[ -n "$DB_VALUE_BYTES" ]]; then
  SERVER_CMD+=(-db-value-bytes "$DB_VALUE_BYTES")
fi
if [[ -n "$DB_SCAN_COUNT" ]]; then
  SERVER_CMD+=(-db-scan-count "$DB_SCAN_COUNT")
fi
if [[ -n "$DB_KEY_PREFIX" ]]; then
  SERVER_CMD+=(-db-key-prefix "$DB_KEY_PREFIX")
fi

"${SERVER_CMD[@]}" &

PID=$!
echo "$PID" > "$PID_FILE"

echo "Server started (pid=$PID, policy=$POLICY, workers=$THREADS)"
