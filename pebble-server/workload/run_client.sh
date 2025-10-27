#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

LOG_FILE="$ROOT/logs/client.log"
SERVER="127.0.0.1:9000"
DURATION=30
RATE=1000
GET_FRAC=0.8
SCAN_LIMIT=10
KEY_PREFIX="key"
KEY_SPACE=100000
SEND_WORKERS=1

usage() {
  cat <<USAGE
Usage: $0 [options]
  -s <server>     UDP server address (default: $SERVER)
  -t <seconds>    duration in seconds (default: $DURATION)
  -r <rate>       target send rate req/s (default: $RATE)
  -g <fraction>   GET fraction (default: $GET_FRAC)
  -m <limit>      scan limit (default: $SCAN_LIMIT)
  -k <prefix>     key prefix (default: $KEY_PREFIX)
  -N <space>      key space (default: $KEY_SPACE)
  -l <logfile>    client log file (default: $LOG_FILE)
  -w <workers>    concurrent send workers (default: $SEND_WORKERS)
USAGE
}

while getopts ":s:t:r:g:m:k:N:l:w:" opt; do
  case "$opt" in
    s) SERVER="$OPTARG" ;;
    t) DURATION="$OPTARG" ;;
    r) RATE="$OPTARG" ;;
    g) GET_FRAC="$OPTARG" ;;
    m) SCAN_LIMIT="$OPTARG" ;;
    k) KEY_PREFIX="$OPTARG" ;;
    N) KEY_SPACE="$OPTARG" ;;
    l) LOG_FILE="$OPTARG" ;;
    w) SEND_WORKERS="$OPTARG" ;;
    :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
    \?) usage; exit 1 ;;
  esac
done

mkdir -p "$(dirname "$LOG_FILE")"

pushd "$ROOT" >/dev/null

go run ./cmd/workload_client \
  -server "$SERVER" \
  -duration "${DURATION}s" \
  -rate "$RATE" \
  -get-frac "$GET_FRAC" \
  -scan-limit "$SCAN_LIMIT" \
  -key-prefix "$KEY_PREFIX" \
  -key-space "$KEY_SPACE" \
  -send-workers "$SEND_WORKERS" \
  -log "$LOG_FILE"

popd >/dev/null
