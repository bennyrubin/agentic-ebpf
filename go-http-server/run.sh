#!/usr/bin/env bash

# Simple orchestrator that launches the Go servers, allows them to warm up,
# runs the basic workload, and then gracefully stops the servers so that
# launch_servers.sh can clean up its children.

set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
    cat <<'EOF'
Usage: ./run.sh <num_servers> <policy> <num_clients> <cpu_percent> [startup_delay]

  num_servers    Number of Go server instances to start.
  policy         Scheduling policy passed through to launch_servers.sh.
  num_clients    Number of wrk2 clients the workload should launch.
  cpu_percent    Percentage of clients that should hit /cpu instead of /hello.
  startup_delay  Optional seconds to wait after starting the servers (default: 3).
EOF
    exit 1
fi

NUM_SERVERS=$1
POLICY=$2
NUM_CLIENTS=$3
CPU_PERCENT=$4
STARTUP_DELAY=${5:-7}

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH_SCRIPT="$SCRIPT_DIR/launch_servers.sh"
WORKLOAD_SCRIPT="$SCRIPT_DIR/workloads/basic-workload.sh"

if [[ ! -x "$LAUNCH_SCRIPT" ]]; then
    echo "Error: expected executable launch script at $LAUNCH_SCRIPT" >&2
    exit 1
fi

if [[ ! -x "$WORKLOAD_SCRIPT" ]]; then
    echo "Error: expected executable workload script at $WORKLOAD_SCRIPT" >&2
    exit 1
fi

LAUNCH_PID=""

cleanup() {
    if [[ -n "$LAUNCH_PID" ]]; then
        if kill -0 "$LAUNCH_PID" 2>/dev/null; then
            echo "Stopping launch_servers.sh (PID $LAUNCH_PID)..."
            kill "$LAUNCH_PID" 2>/dev/null || true
        fi
        wait "$LAUNCH_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Launching servers..."
"$LAUNCH_SCRIPT" "$NUM_SERVERS" "$POLICY" &
LAUNCH_PID=$!
echo "launch_servers.sh PID: $LAUNCH_PID"

echo "Waiting ${STARTUP_DELAY}s for servers to become ready..."
sleep "$STARTUP_DELAY"

set +e
"$WORKLOAD_SCRIPT" "$NUM_CLIENTS" "$CPU_PERCENT"
WORKLOAD_STATUS=$?
set -e

if [[ $WORKLOAD_STATUS -ne 0 ]]; then
    echo "basic-workload.sh exited with status $WORKLOAD_STATUS"
else
    echo "Workload completed successfully."
fi

# cleanup trap will handle stopping launch_servers.sh and its Go servers
exit $WORKLOAD_STATUS
