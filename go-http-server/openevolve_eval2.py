#!/usr/bin/env python3
"""
Simplified OpenEvolve evaluator for the agentic eBPF HTTP server project.

This version delegates orchestration to ``run.sh`` and then collects the
generated workload metrics and logs. It intentionally skips the extra
pre-flight checks that the original evaluator performed.
"""

from __future__ import annotations

import csv
import json
import os
import pprint
import subprocess
import sys
from pathlib import Path
from typing import Dict, Tuple

# Ensure the OpenEvolve package is importable when running this file directly.
REPO_ROOT = Path(__file__).resolve().parents[2]
OPENEVOLVE_DIR = REPO_ROOT / "openevolve"
if OPENEVOLVE_DIR.exists():
    sys.path.insert(0, str(OPENEVOLVE_DIR))

from openevolve.evaluation_result import EvaluationResult

ROOT_DIR = Path(__file__).resolve().parent
SERVER_CODE_DIR = ROOT_DIR / "server_code"
WORKLOADS_DIR = ROOT_DIR / "workloads"
WORKLOAD_LOG_DIR = WORKLOADS_DIR / "wrk_log"
SERVER_LOG_DIR = ROOT_DIR / "log"

# Default invocation for run.sh (can be overridden via environment variable)
DEFAULT_RUN_ARGS = ("4", "agent", "24", "100", "7")  # num_servers, policy, clients, cpu%, delay
RUN_SCRIPT = ROOT_DIR / "run.sh"

RUN_CMD = os.environ.get(
    "OPENEVAL_RUN_SH",
    " ".join(("sudo", "-n", str(RUN_SCRIPT), *DEFAULT_RUN_ARGS)),
).split()

SUMMARY_CSV = WORKLOAD_LOG_DIR / "basic-workload-summary.csv"
METRICS_CSV = WORKLOAD_LOG_DIR / "basic-workload-summary-metrics.csv"

DEFAULT_METRICS: Dict[str, float] = {
    "combined_score": 0.0,
    "average_tput": 0.0,
    "average_latency": 0.0,
    "total_score": 0.0,
    "run_successful": 0.0,
    "compile_successful": 0.0,
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _parse_metrics_csv(path: Path) -> Tuple[float, float, float]:
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            avg_tput = float(row.get("avg_req_per_sec", 0.0))
            avg_latency = float(row.get("avg_latency_ms", 0.0))
            score = float(row.get("score", 0.0))
            return avg_tput, avg_latency, score
    raise ValueError(f"No rows in metrics CSV {path}")


def _gather_logs(pattern: str) -> Dict[str, str]:
    artifacts: Dict[str, str] = {}
    for path in sorted(SERVER_LOG_DIR.glob(pattern)):
        try:
            artifacts[f"log_{path.name}"] = _read_text(path)
        except FileNotFoundError:
            continue
    return artifacts


def _gather_workload_logs() -> Dict[str, str]:
    artifacts: Dict[str, str] = {}
    if not WORKLOAD_LOG_DIR.exists():
        return artifacts
    for path in sorted(WORKLOAD_LOG_DIR.glob("wrk_client_*.log")):
        try:
            artifacts[f"wrk_{path.name}"] = _read_text(path)
        except FileNotFoundError:
            continue
    aggregated = WORKLOAD_LOG_DIR / "basic-workload.log"
    if aggregated.exists():
        artifacts["wrk_basic_workload_log"] = _read_text(aggregated)
    return artifacts


def _run_go_generate() -> Tuple[bool, str]:
    try:
        completed = subprocess.run(
            ("go", "generate", "./..."),
            cwd=SERVER_CODE_DIR,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return False, f"Failed to execute go generate: {exc}"

    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, output


def evaluate(program_path: str = None) -> EvaluationResult:  # pragma: no cover - integration code
    """
    Run ``run.sh`` and translate the resulting artifacts into an EvaluationResult.

    Args:
        program_path: Path to candidate program (copied into agent.c before build).
    """
    metrics = DEFAULT_METRICS.copy()
    artifacts: Dict[str, str] = {}

    if not RUN_SCRIPT.exists():
        artifacts["error"] = f"run.sh not found at {RUN_SCRIPT}"
        return EvaluationResult(metrics=metrics, artifacts=artifacts)

    if program_path:
        program_source = Path(program_path)
        if not program_source.exists():
            artifacts["error"] = f"Program file not found: {program_source}"
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        agent_destination = SERVER_CODE_DIR / "eBPF" / "agent.c"
        try:
            agent_destination.write_text(program_source.read_text(encoding="utf-8"), encoding="utf-8")
            artifacts["copied_program"] = f"Copied {program_source} to {agent_destination}"
        except Exception as exc:
            artifacts["error"] = f"Failed to copy program: {exc}"
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

    go_ok, go_output = _run_go_generate()
    artifacts["go_generate_output"] = go_output
    if not go_ok:
        return EvaluationResult(metrics=metrics, artifacts=artifacts)
    metrics["compile_successful"] = 1.0

    proc = subprocess.run(
        RUN_CMD,
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
        check=False,
    )
    artifacts["run_stdout"] = proc.stdout
    artifacts["run_stderr"] = proc.stderr
    artifacts["run_exit_code"] = str(proc.returncode)

    if proc.returncode != 0:
        artifacts["failure_reason"] = (
            f"run.sh exited with code {proc.returncode}. "
            "See run_stdout/run_stderr for details."
        )
        return EvaluationResult(metrics=metrics, artifacts=artifacts)

    if METRICS_CSV.exists():
        try:
            avg_tput, avg_latency, total_score = _parse_metrics_csv(METRICS_CSV)
            metrics.update(
                {
                    "average_tput": avg_tput,
                    "average_latency": avg_latency,
                    "total_score": total_score,
                    "combined_score": total_score,
                    "run_successful": 1.0,
                }
            )
            artifacts["basic_workload_metrics_csv"] = _read_text(METRICS_CSV)
        except Exception as exc:
            artifacts["metrics_parse_error"] = str(exc)
    else:
        artifacts["metrics_missing"] = str(METRICS_CSV)

    if SUMMARY_CSV.exists():
        artifacts["basic_workload_summary_csv"] = _read_text(SUMMARY_CSV)
    else:
        artifacts["summary_missing"] = str(SUMMARY_CSV)

    # Collect server logs (if any)
    artifacts.update(_gather_logs("*.log"))
    artifacts.update(_gather_workload_logs())

    return EvaluationResult(metrics=metrics, artifacts=artifacts)


__all__ = ["evaluate"]


def _main() -> None:
    result = evaluate()

    print("=== Metrics ===")
    pprint.pp(result.metrics)

    print("\n=== Artifacts (keys) ===")
    pprint.pp(sorted(result.artifacts.keys()))

    serialised = {
        "metrics": result.metrics,
        "artifacts": {
            key: (value[:500] + "..." if isinstance(value, str) and len(value) > 500 else value)
            for key, value in result.artifacts.items()
        },
    }
    print("\n=== Serialized (truncated artifacts) ===")
    print(json.dumps(serialised, indent=2))


if __name__ == "__main__":
    _main()
