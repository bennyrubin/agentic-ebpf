#!/usr/bin/env bash
set -euo pipefail

APP_HOME=${APP_HOME:-/opt/app}
WORK_ROOT=${WORK_ROOT:-/opt/work}
RESULTS_ROOT=${OUTPUT_ROOT:-/results}

timestamp() {
  date +%Y%m%d-%H%M%S
}

ensure_bpffs() {
  if command -v findmnt >/dev/null 2>&1; then
    if findmnt -n -t bpf /sys/fs/bpf >/dev/null 2>&1; then
      return
    fi
  elif command -v mountpoint >/dev/null 2>&1 && mountpoint -q /sys/fs/bpf >/dev/null 2>&1; then
    return
  fi

  mkdir -p /sys/fs/bpf
  if ! mount -t bpf bpffs /sys/fs/bpf 2>/dev/null; then
    mount -t bpf bpf /sys/fs/bpf
  fi
}

ensure_bpffs

EXP_ID=${EXP_ID:-exp-$(timestamp)-$RANDOM}
RUN_ID=${RUN_ID:-run-$(timestamp)-$RANDOM}
WORK_DIR="${WORK_ROOT}/${EXP_ID}"
STATE_DIR="${WORK_DIR}/state"

mkdir -p "$RESULTS_ROOT" "$WORK_DIR" "$STATE_DIR"

export OUTPUT_ROOT="$RESULTS_ROOT"
export RUN_ID="$RUN_ID"
export RUN_STATE_DIR="$STATE_DIR"
export SKIP_EBPF_BUILD="${SKIP_EBPF_BUILD:-true}"

cd "$APP_HOME"

echo "[entrypoint] Starting run.sh for $RUN_ID (results -> $RESULTS_ROOT)"
./run.sh "$@"

echo "[entrypoint] Completed run $RUN_ID (exp $EXP_ID)"

if [[ "${PRESERVE_WORKDIR:-false}" != "true" ]]; then
  rm -rf "$WORK_DIR"
fi
