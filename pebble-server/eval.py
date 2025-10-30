#!/usr/bin/env python3
"""
OpenEvolve evaluation entry point for the Pebble server playground.

The evaluator receives the path to a candidate eBPF program, swaps it into
``ebpf/agent.c``, runs ``run.sh`` to build and benchmark the system, and
aggregates latency metrics from the freshest ``results/run-*`` directory.

The returned metrics dictionary must include ``combined_score``; per the
project's convention we expose the overall p99 latency (milliseconds) both as
``combined_score`` and under ``overall_latency_p99``.  Lower values therefore
represent better programs.
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
            "combined_score": float("inf"),
            "error": 1.0,
            "error_message": f"failed to read candidate program: {exc}",
        }

    try:
        AGENT_SOURCE.write_text(candidate_source)
    except Exception as exc:
        return {
            "combined_score": float("inf"),
            "error": 1.0,
            "error_message": f"failed to write agent.c: {exc}",
        }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    pre_existing_runs = {path.name for path in RESULTS_DIR.glob("run-*") if path.is_dir()}

    run_cmd = ["bash", str(RUN_SCRIPT)]
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
            "combined_score": float("inf"),
            "error": 1.0,
            "error_message": "run.sh failed",
            "stderr_message": completed.stderr.strip(),
        }

    run_dir = _locate_new_run(pre_existing_runs)
    if run_dir is None:
        return {
            "combined_score": float("inf"),
            "error": 1.0,
            "error_message": "could not locate new results directory",
        }

    metrics = _extract_metrics(run_dir)
    metrics.setdefault("run_timestamp", run_dir.stat().st_mtime)
    metrics.setdefault("combined_score", float("inf"))

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
            "combined_score": float("inf"),
            "error": 1.0,
            "error_message": f"missing workload_summary.json in {run_dir}",
        }

    try:
        payload = json.loads(summary_path.read_text())
    except json.JSONDecodeError as exc:
        return {
            "combined_score": float("inf"),
            "error": 1.0,
            "error_message": f"invalid JSON in workload_summary.json: {exc}",
        }

    summary = payload.get("summary", {})
    metrics: Dict[str, float] = {}

    overall_p99 = _pull_metric(summary, "overall_latency_p99")
    if overall_p99 is not None:
        metrics["combined_score"] = overall_p99
        metrics["overall_latency_p99"] = overall_p99

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
