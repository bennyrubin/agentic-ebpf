#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ "${SKIP_EBPF_BUILD:-}" == "true" ]]; then
  echo "Skipping eBPF build (SKIP_EBPF_BUILD=true)"
  exit 0
fi

if ! command -v clang >/dev/null 2>&1; then
  echo "clang is required to build eBPF programs" >&2
  exit 1
fi

export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g"

# Ensure libc/linux arch-specific headers are discoverable when targeting BPF.
ARCH_INCLUDE="/usr/include/$(uname -m)-linux-gnu"
if [[ -d "$ARCH_INCLUDE" ]]; then
  BPF_CFLAGS+=" -I${ARCH_INCLUDE}"
fi
if [[ -d "/usr/include" ]]; then
  BPF_CFLAGS+=" -I/usr/include"
fi

pushd "$ROOT" >/dev/null

go generate ./internal/ebpfutil

popd >/dev/null

echo "eBPF assets generated under internal/ebpfutil"
