#!/usr/bin/env bash

set -euo pipefail

PIN_PATH="/sys/fs/bpf/acceptq_bpf"

if [[ ! -e "$PIN_PATH" ]]; then
	echo "Accept queue BPF program is not pinned at ${PIN_PATH}"
	exit 1
fi

if sudo bpftool prog show pinned "$PIN_PATH" >/dev/null 2>&1; then
	echo "Accept queue BPF program is loaded and pinned at ${PIN_PATH}:"
	sudo bpftool prog show pinned "$PIN_PATH"
else
	echo "Failed to read pinned program at ${PIN_PATH}. Ensure bpftool is installed and you have sudo access."
	exit 1
fi
