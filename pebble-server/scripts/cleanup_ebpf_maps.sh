#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

MAPS=(
  "/sys/fs/bpf/pebble_udp_targets"
  "/sys/fs/bpf/pebble_rr_state"
  "/sys/fs/bpf/agent_udp_targets"
)

for map in "${MAPS[@]}"; do
  if [[ -e "$map" ]]; then
    rm -f "$map"
  fi
done
