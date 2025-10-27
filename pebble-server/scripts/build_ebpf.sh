#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required to build eBPF programs" >&2
  exit 1
fi

export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g"

pushd "$ROOT" >/dev/null

go generate ./internal/ebpfutil

popd >/dev/null

echo "eBPF assets generated under internal/ebpfutil"
