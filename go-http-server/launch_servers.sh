#!/usr/bin/env bash

# ---- Configurable parameters ----
REPORT_INTERVAL=3  # seconds between CPU usage reports
# ---------------------------------

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <num_servers> <policy>"
    exit 1
fi

NUM_SERVERS=$1
POLICY=$2

# Recreate the log directory every run
rm -rf log
mkdir -p log
mkdir -p .gocache

# Get list of CPUs on NUMA node 0
CPUS_NODE0=$(lscpu -p=CPU,NODE | grep -v '^#' | awk -F, '$2==0 {print $1}')
NUM_CPUS_NODE0=$(echo "$CPUS_NODE0" | wc -l)

if (( NUM_SERVERS > NUM_CPUS_NODE0 )); then
    echo "Error: requested $NUM_SERVERS servers but only $NUM_CPUS_NODE0 CPUs on NUMA node 0"
    exit 1
fi

PIDS=()
USED_CPUS=()

cleanup() {
    echo "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
        fi
    done
    if [[ -n "${MONITOR_PID:-}" ]] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        kill "$MONITOR_PID"
    fi
    if [[ -n "${COLLECT_STATS_PID:-}" ]] && kill -0 "$COLLECT_STATS_PID" 2>/dev/null; then
        kill "$COLLECT_STATS_PID"
    fi
}
trap cleanup SIGINT SIGTERM EXIT

# ---- CPU monitor function ----
monitor_cpu() {
    local cpus=("$@")
    declare -A prev_idle prev_total

    while true; do
        sleep "$REPORT_INTERVAL"
        echo "---- CPU usage report ----"

        while read -r cpu user nice system idle iowait irq softirq steal guest guest_nice; do
            [[ "$cpu" =~ ^cpu[0-9]+$ ]] || continue
            id=${cpu:3}   # strip "cpu" prefix

            # skip if not in our list
            if [[ ! " ${cpus[*]} " =~ " $id " ]]; then
                continue
            fi

            idle_time=$((idle + iowait))
            total_time=$((user + nice + system + idle + iowait + irq + softirq + steal))

            if [[ -n "${prev_total[$id]:-}" ]]; then
                diff_idle=$((idle_time - prev_idle[$id]))
                diff_total=$((total_time - prev_total[$id]))
                usage=$((100 * (diff_total - diff_idle) / diff_total))
                echo "CPU$id: $usage% used"
            fi

            prev_idle[$id]=$idle_time
            prev_total[$id]=$total_time
        done < /proc/stat
        echo "--------------------------"
    done
}
# --------------------------------

# Launch servers pinned to the first NUM_SERVERS CPUs on node 0
i=0
for cpu in $CPUS_NODE0; do
    if (( i >= NUM_SERVERS )); then
        break
    fi

    logfile="log/server${i}.log"
    echo "Starting server $i on CPU $cpu with policy '$POLICY' (logging to $logfile)"
    
    # Redirect stdout/stderr to log file
    taskset -c "$cpu" go run ./server_code/ "$i" "$POLICY" >"$logfile" 2>&1 &

    pid=$!
    PIDS+=("$pid")
    USED_CPUS+=("$cpu")

    renice -20 -p "$pid" >/dev/null || true

    sleep .3

    ((i++))
done

# Launch collect_stats to populate BPF maps
if (( ${#USED_CPUS[@]} > 0 )); then
    cpu_arg=$(IFS=' '; echo "${USED_CPUS[*]}")
    collect_log="log/collect_stats.log"
    echo "Starting collect_stats for CPUs: ${cpu_arg} (logging to $collect_log)"
    (
        export GOCACHE="$(pwd)/.gocache"
        exec stdbuf -oL -eL go run ./collect_stats.go -cpus "${cpu_arg}" -logdir log -period "${REPORT_INTERVAL}s"
    ) >>"$collect_log" 2>&1 &
    COLLECT_STATS_PID=$!
fi

# Start CPU monitor in background
monitor_cpu "${USED_CPUS[@]}" &
MONITOR_PID=$!

# Wait for all children
wait
