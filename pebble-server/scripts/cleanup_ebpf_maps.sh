#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

PIN_BASE=${BPF_PIN_BASE:-/sys/fs/bpf}

if [[ -n "${BPF_PIN_PATH:-}" ]]; then
  echo "Skipping global eBPF map cleanup; using isolated pin path ${BPF_PIN_PATH}"
  exit 0
fi

MAPS=(
  "$PIN_BASE/pebble_udp_targets"
  "$PIN_BASE/pebble_rr_state"
  "$PIN_BASE/agent_udp_targets"
  "$PIN_BASE/pebble_agent_state"
  "$PIN_BASE/pebble_agent_slots"
)

for map in "${MAPS[@]}"; do
  if [[ -e "$map" ]]; then
    rm -f "$map"
  fi
done
