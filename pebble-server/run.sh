#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export GOCACHE="$ROOT/.gocache"

THREADS=6
POLICY="agent"
DB_PATH="$ROOT/pebble.data"
NUM_KEYS=100000
VALUE_BYTES=256
DURATION=15
RATE=45000
GET_FRAC=.995
SCAN_LIMIT=1500
SEND_WORKERS=10
KEY_PREFIX="key"
KEY_SPACE=90000
LISTEN="127.0.0.1:9000"
DESTROY_DB="false"
ITERATIONS=3

usage() {
  cat <<USAGE
Usage: $0 [options]
  --threads <n>       worker sockets (default: $THREADS)
  --policy <name>     default|round_robin|agent|scan_split (default: $POLICY)
  --db <path>         Pebble database path (default: $DB_PATH)
  --keys <n>          number of keys to load (default: $NUM_KEYS)
  --value-bytes <n>   value size (default: $VALUE_BYTES)
  --duration <sec>    workload duration seconds (default: $DURATION)
  --rate <rps>        send rate (default: $RATE)
  --get-frac <f>      GET fraction (default: $GET_FRAC)
  --scan-limit <n>    SCAN limit (default: $SCAN_LIMIT)
  --key-prefix <str>  key prefix (default: $KEY_PREFIX)
  --key-space <n>     key space (default: $KEY_SPACE)
  --listen <addr>     UDP listen address (default: $LISTEN)
  --send-workers <n>  concurrent client send goroutines (default: $SEND_WORKERS)
  --iterations <n>    number of workload iterations (default: $ITERATIONS)
  --destroy-db        destroy and rebuild database before load
USAGE
}

OPTS=$(getopt -o '' \
  --long threads:,policy:,db:,keys:,value-bytes:,duration:,rate:,get-frac:,scan-limit:,key-prefix:,key-space:,listen:,send-workers:,iterations:,destroy-db,help \
  -n 'run.sh' -- "$@") || { usage; exit 1; }

eval set -- "$OPTS"

while true; do
  case "$1" in
    --threads) THREADS="$2"; shift 2 ;;
    --policy) POLICY="$2"; shift 2 ;;
    --db) DB_PATH="$2"; shift 2 ;;
    --keys) NUM_KEYS="$2"; shift 2 ;;
    --value-bytes) VALUE_BYTES="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --get-frac) GET_FRAC="$2"; shift 2 ;;
    --scan-limit) SCAN_LIMIT="$2"; shift 2 ;;
    --key-prefix) KEY_PREFIX="$2"; shift 2 ;;
    --key-space) KEY_SPACE="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --send-workers) SEND_WORKERS="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --destroy-db) DESTROY_DB="true"; shift ;;
    --help) usage; exit 0 ;;
    --) shift; break ;;
    *) usage; exit 1 ;;
  esac
done

RUN_ID="run-$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ROOT/results/$RUN_ID"
LOG_DIR="$RUN_DIR/logs"
mkdir -p "$LOG_DIR"

echo "== Building eBPF assets =="
"$ROOT/scripts/build_ebpf.sh"

echo "== Cleaning pinned eBPF maps =="
"$ROOT/scripts/cleanup_ebpf_maps.sh"

echo "== Preparing Pebble dataset =="
if [[ "$DESTROY_DB" == "true" ]]; then
  DESTROY_FLAG="-x"
else
  DESTROY_FLAG=""
fi
"$ROOT/scripts/setup_db.sh" -d "$DB_PATH" -n "$NUM_KEYS" -s "$VALUE_BYTES" -p "$KEY_PREFIX" $DESTROY_FLAG

SERVER_LOG_DIR="$LOG_DIR/server"
CLIENT_LOG_FILE="$LOG_DIR/client.log"
mkdir -p "$SERVER_LOG_DIR"

cat <<META > "$RUN_DIR/experiment.json"
{
  "threads": "$THREADS",
  "policy": "$POLICY",
  "db_path": "${DB_PATH}",
  "keys": "$NUM_KEYS",
  "value_bytes": "$VALUE_BYTES",
  "duration_sec": "$DURATION",
  "rate_rps": "$RATE",
  "get_fraction": "$GET_FRAC",
  "scan_limit": "$SCAN_LIMIT",
  "key_prefix": "$KEY_PREFIX",
  "key_space": "$KEY_SPACE",
  "listen": "$LISTEN",
  "iterations": "$ITERATIONS"
}
META

echo "== Starting server =="
"$ROOT/scripts/launch_server.sh" -t "$THREADS" -p "$POLICY" -d "$DB_PATH" -l "$LISTEN" -o "$SERVER_LOG_DIR" -r "$RUN_DIR" >/dev/null
SERVER_PID=$(cat "$ROOT/run/server.pid")

echo "pprof available at http://127.0.0.1:6060/debug/pprof/"
echo "block/mutex profiling enabled (SetBlockProfileRate=1)"

sleep 2

WORKLOAD_SUMMARY="$LOG_DIR/workload_summary.txt"
> "$WORKLOAD_SUMMARY"

echo "== Running workload iterations ($ITERATIONS) =="
pushd "$ROOT" >/dev/null
ITERATION_LOGS=()
for ((i = 1; i <= ITERATIONS; i++)); do
  ITER_LOG="$LOG_DIR/workload_iteration_${i}.txt"
  ITERATION_LOGS+=("$ITER_LOG")
  echo "-- Iteration $i/$ITERATIONS --"
  go run ./cmd/workload_client \
    -server "$LISTEN" \
    -duration "${DURATION}s" \
    -rate "$RATE" \
    -get-frac "$GET_FRAC" \
    -scan-limit "$SCAN_LIMIT" \
    -key-prefix "$KEY_PREFIX" \
    -key-space "$KEY_SPACE" \
    -send-workers "$SEND_WORKERS" \
    -log "$CLIENT_LOG_FILE" | tee "$ITER_LOG"
done
popd >/dev/null

for idx in "${!ITERATION_LOGS[@]}"; do
  iter=$((idx + 1))
  {
    echo "== Iteration $iter =="
    cat "${ITERATION_LOGS[$idx]}"
    echo
  } >> "$WORKLOAD_SUMMARY"
done

echo "== Aggregating workload metrics =="
LOG_DIR_PATH="$LOG_DIR" RUN_DIR_PATH="$RUN_DIR" python3 - <<'PY'
import json
import os
import pathlib
import re
import statistics

log_dir = pathlib.Path(os.environ["LOG_DIR_PATH"])
iter_files = sorted(log_dir.glob("workload_iteration_*.txt"))
if not iter_files:
    raise SystemExit("no workload iteration logs found")

total_sent_re = re.compile(r"Total sent:\s+(\d+)\s+\(GET=(\d+)\s+SCAN=(\d+)\)")
total_recv_re = re.compile(r"Total received:\s+(\d+)\s+\(GET=(\d+)\s+SCAN=(\d+)\)")
throughput_re = re.compile(r"Throughput:\s+([0-9.]+)\s+req/s")
latency_re = re.compile(r"^(Overall|GET|SCAN) latency (p50|p90|p99|avg):\s+([0-9.]+)\s+ms")

def parse_file(path, iteration):
    metrics = {"iteration": iteration}
    with path.open() as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            m = total_sent_re.match(line)
            if m:
                metrics["total_sent"] = int(m.group(1))
                metrics["total_sent_get"] = int(m.group(2))
                metrics["total_sent_scan"] = int(m.group(3))
                continue
            m = total_recv_re.match(line)
            if m:
                metrics["total_received"] = int(m.group(1))
                metrics["total_received_get"] = int(m.group(2))
                metrics["total_received_scan"] = int(m.group(3))
                continue
            m = throughput_re.match(line)
            if m:
                metrics["throughput"] = float(m.group(1))
                continue
            m = latency_re.match(line)
            if m:
                scope = m.group(1).lower()
                stat = m.group(2).lower()
                key = f"{scope}_latency_{stat}"
                metrics[key] = float(m.group(3))
                continue
    return metrics

iterations = []
for idx, path in enumerate(iter_files, start=1):
    iterations.append(parse_file(path, idx))

summary = {}
numeric_keys = sorted({k for entry in iterations for k in entry.keys() if k != "iteration"})
for key in numeric_keys:
    values = [entry[key] for entry in iterations if isinstance(entry.get(key), (int, float))]
    if not values:
        continue
    avg = statistics.mean(values)
    stddev = statistics.pstdev(values) if len(values) > 1 else 0.0
    summary[key] = {"average": avg, "stddev": stddev}

output = {"iterations": iterations, "summary": summary}
results_dir = pathlib.Path(os.environ["RUN_DIR_PATH"])
(results_dir / "workload_summary.json").write_text(json.dumps(output, indent=2))
PY

echo "== Stopping server =="
if kill "$SERVER_PID" >/dev/null 2>&1; then
  wait "$SERVER_PID" 2>/dev/null || true
fi
rm -f "$ROOT/run/server.pid"

echo "Logs and results stored in $RUN_DIR"
