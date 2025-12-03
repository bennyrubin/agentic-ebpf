#!/bin/bash
set -e

# Copy backup agent to agent.c
cp ebpf/agent_backup.c ebpf/agent.c

# Remove all contents inside results/
rm -rf results/*

# Remove all contents inside openevolve_output (if it exists)
rm -rf new_evolve_output/*

# Kill any python3 process running openevolve-run.py, regardless of intermediate path, using SIGKILL (-9)
pkill -9 -f 'python3.*openevolve-run\.py' || true


