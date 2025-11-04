#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR="${BIN_DIR:-$ROOT/bin}"
mkdir -p "$BIN_DIR"

THREADS=4
POLICY="default"
DB_PATH="$ROOT/pebble.data"
LISTEN="127.0.0.1:9000"
LOG_DIR="$ROOT/logs/server"
RESULTS_DIR="$ROOT/results"
RUN_STATE_DIR="${RUN_STATE_DIR:-$ROOT/run}"
BUILD_SERVER_BIN="${BUILD_SERVER_BIN:-true}"
SERVER_BIN="${PEBBLE_SERVER_BIN:-$BIN_DIR/pebble_server}"

usage() {
  cat <<USAGE
Usage: $0 [options]
  -t <threads>   number of worker sockets (default: $THREADS)
  -p <policy>    load-balancing policy: default|round_robin|agent|scan_split
  -d <db-path>   Pebble directory (default: $DB_PATH)
  -l <address>   UDP listen address (default: $LISTEN)
  -o <log-dir>   directory for server logs (default: $LOG_DIR)
  -r <results>   directory to store experiment metadata (default: $RESULTS_DIR)
USAGE
}

while getopts ":t:p:d:l:o:r:" opt; do
  case "$opt" in
    t) THREADS="$OPTARG" ;;
    p) POLICY="$OPTARG" ;;
    d) DB_PATH="$OPTARG" ;;
    l) LISTEN="$OPTARG" ;;
    o) LOG_DIR="$OPTARG" ;;
    r) RESULTS_DIR="$OPTARG" ;;
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

"$SERVER_BIN" \
  -db "$DB_PATH" \
  -listen "$LISTEN" \
  -workers "$THREADS" \
  -policy "$POLICY" \
  -log-dir "$LOG_DIR" \
  -results-dir "$RESULTS_DIR" &

PID=$!
echo "$PID" > "$PID_FILE"

echo "Server started (pid=$PID, policy=$POLICY, workers=$THREADS)"
