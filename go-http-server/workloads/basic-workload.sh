#!/usr/bin/env bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <num_clients> <cpu_percent>"
    echo "  <cpu_percent> = 0..100 (percentage of clients hitting /cpu instead of /hello)"
    exit 1
fi

NUM_CLIENTS=$1
CPU_PERCENT=$2
URL_BASE="http://localhost:8080"
LOG_DIR=${LOG_DIR:-wrk_log}

# Sanity check for percentage
if (( CPU_PERCENT < 0 || CPU_PERCENT > 100 )); then
    echo "Error: cpu_percent must be between 0 and 100"
    exit 1
fi

# Get list of CPUs on NUMA node 0 (highest-numbered first)
CPUS_NODE0=$(lscpu -p=CPU,NODE | grep -v '^#' | awk -F, '$2==0 {print $1}' | sort -nr)
NUM_CPUS_NODE0=$(echo "$CPUS_NODE0" | wc -l)

if (( NUM_CLIENTS > NUM_CPUS_NODE0 )); then
    echo "Error: requested $NUM_CLIENTS clients but only $NUM_CPUS_NODE0 CPUs on NUMA node 0"
    exit 1
fi

# Fresh log directory for this run
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

echo "Launching $NUM_CLIENTS wrk2 clients"
echo "Using top $NUM_CLIENTS cores from NUMA node 0"
echo "CPU_PERCENT = $CPU_PERCENT"
echo "Logs will be written to $LOG_DIR"

i=0
for cpu in $CPUS_NODE0; do
    if (( i >= NUM_CLIENTS )); then
        break
    fi

    # Decide whether this client uses /cpu or /hello
    # Evenly assign based on percentage
    rand=$(( (i * 100) / NUM_CLIENTS ))
    if (( rand < CPU_PERCENT )); then
        URL="$URL_BASE/cpu"
    else
        URL="$URL_BASE/hello"
    fi

    echo "Client $i pinned to CPU $cpu hitting $URL"
    LOG_PATH="$LOG_DIR/wrk_client_${i}.log"
    taskset -c "$cpu" wrk2 -t1 -c1 -d20s -R 1000 "$URL" > "$LOG_PATH" 2>&1 &

    ((i++))
done

wait
echo "All clients finished."

if command -v python3 >/dev/null 2>&1; then
    SUMMARY_OUTPUT="${LOG_DIR}/basic-workload-summary.csv"
    METRICS_OUTPUT="${LOG_DIR}/basic-workload-summary-metrics.csv"
    echo "Generating summary CSV at $SUMMARY_OUTPUT"
    python3 "$(dirname "$0")/basic-workload-summary.py" \
        --logs-dir "$LOG_DIR" \
        --output "$SUMMARY_OUTPUT" \
        --metrics-output "$METRICS_OUTPUT"
    echo "Run metrics CSV available at $METRICS_OUTPUT"
else
    echo "python3 not found in PATH; skipping summary generation" >&2
fi
