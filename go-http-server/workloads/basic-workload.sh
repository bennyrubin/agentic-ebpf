#!/usr/bin/env bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <num_clients> <cpu_percent>"
    echo "  <cpu_percent> = 0..100 (percentage of clients hitting /cpu instead of /hello)"
    exit 1
fi

NUM_CLIENTS=$1
CPU_PERCENT=$2
URL_BASE="http://localhost:8080"

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

mkdir -p wrk_log

echo "Launching $NUM_CLIENTS wrk2 clients"
echo "Using top $NUM_CLIENTS cores from NUMA node 0"
echo "CPU_PERCENT = $CPU_PERCENT"

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
    taskset -c "$cpu" wrk2 -t1 -c1 -d20s -R 1000 "$URL" > "wrk_log/wrk_client_${i}.log" 2>&1 &

    ((i++))
done

wait
echo "All clients finished. Logs are in wrk_log/wrk_client_*.log"
