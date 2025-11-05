#!/usr/bin/env python3
"""
OpenEvolve evaluation entry point for the Pebble server playground.

The evaluator receives the path to a candidate eBPF program, swaps it into
``ebpf/agent.c``, runs ``run.sh`` to build and benchmark the system, and
aggregates latency metrics from the freshest ``results/run-*`` directory.

The returned metrics dictionary must include ``combined_score``; OpenEvolve
maximises that value, so we expose the negated overall p99 latency (milliseconds)
as ``combined_score`` and report the raw latency under
``overall_latency_p99``. Higher combined scores therefore mean lower latency.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional


REPO_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = REPO_ROOT / "results"
AGENT_SOURCE = REPO_ROOT / "ebpf" / "agent.c"
RUN_SCRIPT = REPO_ROOT / "run.sh"
NUMA_NODE0_CPULIST = Path("/sys/devices/system/node/node0/cpulist")


def _expand_cpu_spec(spec: str) -> list[int]:
    cleaned = spec.replace("\n", "").replace("\r", "").strip()
    if not cleaned:
        return []
    cpus: list[int] = []
    for token in cleaned.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            try:
                start = int(start_s)
                end = int(end_s)
            except ValueError as exc:
                raise ValueError(f"Invalid CPU range '{token}'") from exc
            if start > end:
                raise ValueError(f"Invalid CPU range '{token}' (start > end)")
            cpus.extend(range(start, end + 1))
        else:
            try:
                cpus.append(int(token))
            except ValueError as exc:
                raise ValueError(f"Invalid CPU token '{token}'") from exc
    return cpus


def _resolve_core_counts() -> tuple[int, int]:
    env_server = os.environ.get("SERVER_CORES") or os.environ.get("EVAL_SERVER_CORES")
    env_client = os.environ.get("CLIENT_CORES") or os.environ.get("EVAL_CLIENT_CORES")

    if env_server and env_client:
        try:
            server = int(env_server)
            client = int(env_client)
        except ValueError as exc:
            raise ValueError(f"Invalid SERVER_CORES/CLIENT_CORES values: {exc}") from exc
        if server <= 0 or client <= 0:
            raise ValueError("SERVER_CORES and CLIENT_CORES must be positive integers.")
        return server, client
    if env_server or env_client:
        raise ValueError("Both SERVER_CORES and CLIENT_CORES must be provided together.")

    if not NUMA_NODE0_CPULIST.exists():
        raise ValueError(
            f"NUMA node 0 CPU list not found at {NUMA_NODE0_CPULIST}; set SERVER_CORES and CLIENT_CORES explicitly."
        )

    raw = NUMA_NODE0_CPULIST.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError(
            f"NUMA node 0 CPU list at {NUMA_NODE0_CPULIST} is empty; set SERVER_CORES and CLIENT_CORES explicitly."
        )
    try:
        cpus = _expand_cpu_spec(raw)
    except ValueError as exc:
        raise ValueError(
            f"Failed to parse NUMA node 0 CPU list '{raw}': {exc}. "
            "Set SERVER_CORES and CLIENT_CORES explicitly."
        ) from exc

    total = len(cpus)
    if total < 2:
        raise ValueError(
            f"NUMA node 0 only exposes {total} CPU(s); specify SERVER_CORES and CLIENT_CORES explicitly."
        )
    server = total // 2
    client = total - server
    if server == 0 or client == 0:
        raise ValueError(
            f"Unable to derive positive server/client core counts from NUMA node 0 cpu list ({cpus}); "
            "set SERVER_CORES and CLIENT_CORES explicitly."
        )
    return server, client

def evaluate(program_path: str) -> Dict[str, float]:
    """
    Evaluate the given program file and return latency metrics.

    Args:
        program_path: Path to the candidate eBPF source file.

    Returns:
        Dictionary of metric name to floating-point score.
    """

    return _evaluate(Path(program_path))


def _evaluate(program_path: Path) -> Dict[str, float]:
    """
    Perform the evaluation while holding the global lock.
    """

    try:
        candidate_source = program_path.read_text()
    except Exception as exc:
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": f"failed to read candidate program: {exc}",
        }

    try:
        AGENT_SOURCE.write_text(candidate_source)
    except Exception as exc:
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": f"failed to write agent.c: {exc}",
        }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    pre_existing_runs = {path.name for path in RESULTS_DIR.glob("run-*") if path.is_dir()}

    try:
        server_cores, client_cores = _resolve_core_counts()
    except ValueError as exc:
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": str(exc),
        }

    run_cmd = [
        "bash",
        str(RUN_SCRIPT),
        "--server-cores",
        str(server_cores),
        "--client-cores",
        str(client_cores),
    ]
    completed = subprocess.run(
        run_cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if completed.returncode != 0:
        # Bubble up the failure with a large (bad) combined score.
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": "run.sh failed",
            "stderr_message": completed.stderr.strip(),
        }

    run_dir = _locate_new_run(pre_existing_runs)
    if run_dir is None:
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": "could not locate new results directory",
        }

    metrics = _extract_metrics(run_dir)
    metrics.setdefault("run_timestamp", run_dir.stat().st_mtime)
    metrics.setdefault("combined_score", float("-inf"))

    return metrics


def _locate_new_run(previous: set[str]) -> Optional[Path]:
    """
    Identify the newest run-* directory created by run.sh.
    """

    candidates = [path for path in RESULTS_DIR.glob("run-*") if path.is_dir()]
    if not candidates:
        return None

    new_dirs = [path for path in candidates if path.name not in previous]
    search_space = new_dirs if new_dirs else candidates
    return max(search_space, key=lambda path: path.stat().st_mtime)


def _extract_metrics(run_dir: Path) -> Dict[str, float]:
    """
    Parse workload_summary.json and convert relevant numbers to metrics.
    """

    summary_path = run_dir / "workload_summary.json"
    if not summary_path.exists():
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": f"missing workload_summary.json in {run_dir}",
        }

    try:
        payload = json.loads(summary_path.read_text())
    except json.JSONDecodeError as exc:
        return {
            "combined_score": float("-inf"),
            "error": 1.0,
            "error_message": f"invalid JSON in workload_summary.json: {exc}",
        }

    summary = payload.get("summary", {})
    metrics: Dict[str, float] = {}

    overall_p99 = _pull_metric(summary, "overall_latency_p99")
    if overall_p99 is not None:
        metrics["overall_latency_p99"] = overall_p99
        metrics["combined_score"] = -overall_p99

    # Add a few extra helpful metrics when present.
    for key in (
        "overall_latency_p90",
        "overall_latency_p50",
        "overall_latency_avg",
        "get_latency_p99",
        "scan_latency_p99",
        "throughput",
    ):
        value = _pull_metric(summary, key)
        if value is not None:
            metrics[key] = value

    return metrics


def _pull_metric(summary: Dict[str, Any], key: str) -> Optional[float]:
    """
    Extract the average value for ``key`` from the summary section.
    """

    entry = summary.get(key)
    if isinstance(entry, dict):
        entry = entry.get("average")

    if entry is None:
        return None

    try:
        return float(entry)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-ebpf-program>", file=sys.stderr)
        sys.exit(1)

    metrics = evaluate(sys.argv[1])
    print(json.dumps(metrics, indent=2))
