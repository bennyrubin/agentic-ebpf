#!/usr/bin/env python3
"""
OpenEvolve evaluation entry point for the Pebble server playground.

This evaluator compiles the project eBPF assets, runs a full experiment sweep
via run_exp.py for the agent policy across a set of request rates, and reports
latency metrics together with a negative area-under-the-curve score suitable for
OpenEvolve's maximisation objective.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent
OPENEVOLVE_ROOT = (REPO_ROOT.parent.parent / "openevolve").resolve()
if str(OPENEVOLVE_ROOT) not in sys.path:
    sys.path.insert(0, str(OPENEVOLVE_ROOT))

from openevolve.evaluation_result import EvaluationResult

SCRIPTS_DIR = REPO_ROOT / "scripts"
BUILD_SCRIPT = SCRIPTS_DIR / "build_ebpf.sh"
RUN_EXP_SCRIPT = REPO_ROOT / "run_exp.py"
DISPATCH_SCRIPT = SCRIPTS_DIR / "dispatch_docker_experiments.py"
SERVER_LOG_RELATIVE = Path("logs") / "server" / "server.log"
SERVER_LOG_RELATIVE_CANDIDATES: Tuple[Path, ...] = (
    SERVER_LOG_RELATIVE,
    Path("logs") / "server.log",
)
CLIENT_LOG_RELATIVE = Path("logs") / "client.log"

SUMMARY_PATTERN = re.compile(r"Wrote experiment summary:\s*(.+)")

DEFAULT_POLICY = "agent"
DEFAULT_RATES: Tuple[int, ...] = (80000, 100000, 140000, 160000, 180000)
#DEFAULT_RATES: Tuple[int, ...] = (50000, 60000)

DEFAULT_THREADS = 6
DEFAULT_SEND_WORKERS = 7
DEFAULT_ITERATIONS = 1
DEFAULT_DURATION = 7

# Flip this flag to run experiments via the Docker dispatcher instead of python run_exp.py.
RUN_EXPERIMENT_VIA_DISPATCH = False
DISPATCH_IMAGE = "pebble-server:latest"
DISPATCH_RESULTS_DIR = REPO_ROOT / "results"
DISPATCH_MAX_PARALLEL = 2

PERSIST_FAILURE_RESULTS = True
FAILURE_RESULTS_DIR = REPO_ROOT / "results" / "eval-failures"

FAIL_SCORE = float("-inf")


def _run_build() -> tuple[bool, str]:
    """Invoke the eBPF build script and capture its output."""
    env = os.environ.copy()
    env.pop("SKIP_EBPF_BUILD", None)
    completed = subprocess.run(
        ("sudo", "-E", str(BUILD_SCRIPT)),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, output.strip()


def _persist_failure_result(result: EvaluationResult, candidate_source: Optional[str]) -> None:
    """Persist failed evaluation output for later inspection."""
    if not PERSIST_FAILURE_RESULTS:
        return

    timestamp = dt.datetime.now().strftime("failure-%Y%m%d-%H%M%S")
    try:
        FAILURE_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        target_dir = FAILURE_RESULTS_DIR / timestamp
        suffix = 1
        while target_dir.exists():
            suffix += 1
            target_dir = FAILURE_RESULTS_DIR / f"{timestamp}-{suffix:02d}"
        target_dir.mkdir()

        payload = {
            "metrics": result.metrics,
            "artifacts": result.artifacts,
        }
        (target_dir / "evaluation_result.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

        program_text: Optional[str] = candidate_source
        if program_text is None:
            try:
                program_text = (REPO_ROOT / "ebpf" / "agent.c").read_text(encoding="utf-8")
            except OSError:
                program_text = None
        if program_text is not None:
            (target_dir / "agent.c").write_text(program_text, encoding="utf-8")
    except OSError:
        pass


def _run_experiment(rates: Sequence[int]) -> tuple[subprocess.CompletedProcess[str], Optional[Path], str]:
    """Invoke run_exp.py for the agent policy and capture its outputs."""
    env = os.environ.copy()
    env["SKIP_EBPF_BUILD"] = "true"

    rate_arg = ",".join(str(rate) for rate in rates)
    if RUN_EXPERIMENT_VIA_DISPATCH:
        python_bin = sys.executable or "python3"
        cmd = [
            "sudo",
            "-E",
            python_bin,
            str(DISPATCH_SCRIPT),
            "--results-dir",
            str(DISPATCH_RESULTS_DIR),
            "--max-parallel",
            str(DISPATCH_MAX_PARALLEL),
            "--server-cores",
            str(DEFAULT_THREADS),
            "--client-cores",
            str(DEFAULT_SEND_WORKERS),
            "--policies",
            DEFAULT_POLICY,
            "--rates",
            rate_arg,
            "--threads",
            str(DEFAULT_THREADS),
            "--iterations",
            str(DEFAULT_ITERATIONS),
            "--duration",
            str(DEFAULT_DURATION),
            "--extra-run-args",
            f"--send-workers {DEFAULT_SEND_WORKERS}",
        ]
    else:
        cmd = [
            "sudo",
            "-E",
            "python3",
            str(RUN_EXP_SCRIPT),
            "--policies",
            DEFAULT_POLICY,
            "--rates",
            rate_arg,
            "--threads",
            str(DEFAULT_THREADS),
            "--iterations",
            str(DEFAULT_ITERATIONS),
            "--duration",
            str(DEFAULT_DURATION),
            "--send-workers",
            str(DEFAULT_SEND_WORKERS),
        ]

    completed = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    combined_output = "\n".join(
        part for part in (completed.stdout or "", completed.stderr or "") if part
    )
    summary_path: Optional[Path] = None
    matches = SUMMARY_PATTERN.findall(combined_output)
    if matches:
        raw_path = matches[-1].strip()
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = (REPO_ROOT / candidate).resolve()
        summary_path = candidate

    return completed, summary_path, combined_output.strip()


def _safe_read_text(path: Path) -> Optional[str]:
    """Best-effort file reader that tolerates missing files."""
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return f"Failed to read {path}: {exc}"


def _check_load_success(run_dir: Path) -> bool:
    """Inspect the server log for a successful agent policy start."""
    log_path = _locate_server_log(run_dir)
    if log_path is None:
        return False

    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    started = False
    for line in content.splitlines():
        if "server starting" in line and f"policy={DEFAULT_POLICY}" in line:
            started = True
        if "initialise server" in line.lower() or "load agent objects" in line.lower():
            return False
    return started


def _locate_server_log(run_dir: Path) -> Optional[Path]:
    """Find the best-effort server log path inside a run directory."""
    for relative in SERVER_LOG_RELATIVE_CANDIDATES:
        candidate = run_dir / relative
        if candidate.is_file():
            return candidate
    return None


def _collect_run_logs(policy: str, rate: object, run_dir: Path) -> Dict[str, str]:
    """Return log contents for a given policy/rate run directory."""
    if isinstance(rate, (int, float)):
        rate_str = str(int(rate)) if float(rate).is_integer() else str(rate)
    else:
        rate_str = str(rate)
    name = f"{policy}-{rate_str}"

    server_log_path = _locate_server_log(run_dir)
    if server_log_path is None:
        server_log_path = run_dir / SERVER_LOG_RELATIVE
    server_log = _safe_read_text(server_log_path)
    if server_log is None:
        server_log = f"[missing server log at {server_log_path}]"

    client_log_path = run_dir / CLIENT_LOG_RELATIVE
    client_log = _safe_read_text(client_log_path)
    if client_log is None:
        client_log = f"[missing client log at {client_log_path}]"

    return {
        "name": name,
        "server_log": server_log,
        "client_log": client_log,
    }


RATE_SCALE = 10000.0


def _compute_negative_auc(points: Sequence[Tuple[float, float]]) -> float:
    """Compute the (negative) area under the latency curve."""
    if not points:
        return FAIL_SCORE

    ordered = sorted(points, key=lambda item: item[0])
    if len(ordered) == 1:
        x, y = ordered[0]
        return -((x / RATE_SCALE) * y)

    area = 0.0
    for (x0, y0), (x1, y1) in zip(ordered, ordered[1:]):
        width = (x1 - x0) / RATE_SCALE
        height = (y0 + y1) / 2.0
        area += width * height
    return -area


def evaluate(program_path: Optional[str] = None) -> EvaluationResult:
    """
    Execute the evaluation workflow and return metrics for OpenEvolve.

    Args:
        _ (Optional[str]): Present for backwards compatibility; ignored.
    """

    metrics: Dict[str, float] = {
        "policy": DEFAULT_POLICY,
        "rates": [],
        "load_p99_curve": [],
        "load_p99_stddev_curve": [],
        "compile": 0.0,
        "load": 0.0,
        "combined_score": FAIL_SCORE,
        "run_success": 0.0,
    }
    artifacts: Dict[str, str] = {}

    candidate_source: Optional[str] = None
    if program_path:
        try:
            candidate_source = Path(program_path).read_text(encoding="utf-8")
            target_path = REPO_ROOT / "ebpf" / "agent.c"
            target_path.write_text(candidate_source, encoding="utf-8")
        except OSError as exc:
            metrics["error"] = f"Failed to prepare candidate program: {exc}"
            result = EvaluationResult(metrics=metrics, artifacts=artifacts)
            _persist_failure_result(result, candidate_source)
            return result

    rates = list(DEFAULT_RATES)
    metrics["rates"] = rates

    build_ok, build_output = _run_build()
    if not build_ok:
        metrics["error"] = "eBPF compilation failed."
        if build_output:
            artifacts["build_output"] = build_output
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    metrics["compile"] = 1.0

    completed, summary_path, run_exp_output = _run_experiment(rates)
    run_exp_stdout = (completed.stdout or "").strip()
    run_exp_stderr = (completed.stderr or "").strip()

    if completed.returncode != 0:
        metrics["error"] = "run_exp.py failed."
        if run_exp_stdout:
            artifacts["run_exp_stdout"] = run_exp_stdout
        if run_exp_stderr:
            artifacts["run_exp_stderr"] = run_exp_stderr
        elif run_exp_output:
            artifacts["run_exp_output"] = run_exp_output
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    if summary_path is None or not summary_path.exists():
        metrics["error"] = "Experiment summary not found."
        if run_exp_output:
            artifacts["run_exp_output"] = run_exp_output
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    experiment_dir = summary_path.parent

    try:
        subprocess.run(
            (
                "sudo",
                "-E",
                "chown",
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                str(experiment_dir),
            ),
            check=False,
            cwd=str(REPO_ROOT),
        )
    except Exception:
        pass

    debug_path = str(summary_path.parent.resolve())
    artifacts["debug_path"] = debug_path

    summary_raw = _safe_read_text(summary_path)
    if summary_raw is None:
        metrics["error"] = "Failed to read experiment summary."
        if run_exp_output:
            artifacts["run_exp_output"] = run_exp_output
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    artifacts["summary"] = summary_raw
    artifacts.setdefault("runs", [])

    try:
        summary_payload = json.loads(summary_raw)
    except json.JSONDecodeError as exc:
        metrics["error"] = f"Invalid JSON in experiment summary: {exc}"
        artifacts["summary"] = summary_raw
        if run_exp_output:
            artifacts.setdefault("run_exp_output", run_exp_output)
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    records = summary_payload.get("records", [])
    agent_records = [record for record in records if record.get("policy") == DEFAULT_POLICY]
    if not agent_records:
        metrics["error"] = "Experiment summary missing agent policy records."
        artifacts["summary"] = summary_raw
        artifacts["runs"] = []
        if run_exp_output:
            artifacts.setdefault("run_exp_output", run_exp_output)
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    curve: List[Tuple[float, float]] = []
    std_curve: List[Tuple[float, float]] = []
    load_ok = True
    error_reason: Optional[str] = None
    run_artifacts: List[Dict[str, str]] = []

    for record in agent_records:
        rate = record.get("rate")
        p99 = record.get("overall_latency_p99_avg_ms")
        p99_stddev = record.get("overall_latency_p99_stddev_ms")
        run_dir_raw = record.get("run_dir")

        run_dir_path: Optional[Path] = None
        if run_dir_raw:
            run_dir_path = Path(run_dir_raw)
            if not run_dir_path.is_absolute():
                run_dir_path = (summary_path.parent / run_dir_path).resolve()

        if (
            rate is None
            or p99 is None
            or p99_stddev is None
            or run_dir_path is None
            or not run_dir_path.exists()
        ):
            load_ok = False
            error_reason = f"Incomplete record data for rate {rate}."
            break

        policy_name = record.get("policy", DEFAULT_POLICY)
        run_artifacts.append(_collect_run_logs(policy_name, rate, run_dir_path))

        if not _check_load_success(run_dir_path):
            load_ok = False
            error_reason = f"Agent policy failed to load at rate {rate}."
            log_path = run_dir_path / SERVER_LOG_RELATIVE
            log_text = _safe_read_text(log_path)
            if log_text:
                artifacts[f"server_log_rate_{rate}"] = log_text
            break

        rate_value = float(rate)
        curve.append((rate_value, float(p99)))
        std_curve.append((rate_value, float(p99_stddev)))

    artifacts["runs"] = run_artifacts

    metrics["load_p99_curve"] = sorted(curve, key=lambda item: item[0])
    metrics["load_p99_stddev_curve"] = sorted(std_curve, key=lambda item: item[0])

    if not metrics["load_p99_curve"] or not load_ok:
        metrics["load"] = 0.0
        metrics["combined_score"] = FAIL_SCORE
        if not error_reason and not metrics["load_p99_curve"]:
            error_reason = "No latency data collected."
        if error_reason:
            metrics["error"] = error_reason
        artifacts["summary"] = summary_raw
        if run_exp_stdout:
            artifacts.setdefault("run_exp_stdout", run_exp_stdout)
        if run_exp_stderr:
            artifacts.setdefault("run_exp_stderr", run_exp_stderr)
        elif run_exp_output:
            artifacts.setdefault("run_exp_output", run_exp_output)
        result = EvaluationResult(metrics=metrics, artifacts=artifacts)
        _persist_failure_result(result, candidate_source)
        return result

    metrics["load"] = 1.0
    metrics["run_success"] = 1.0
    metrics["combined_score"] = _compute_negative_auc(metrics["load_p99_curve"])

    result = EvaluationResult(metrics=metrics, artifacts=artifacts)


    if summary_path is not None and summary_path.exists():
        try:
            output_payload = {
                "metrics": result.metrics,
                "artifacts": result.artifacts,
            }
            result_path = summary_path.parent / "evaluation_result.json"
            result_path.write_text(json.dumps(output_payload, indent=2), encoding="utf-8")
        except OSError as exc:
            print(f"FAILED TO PRINT EVAL RESULT JSON TO SUMMARY PATH: {exc}")
            print(f"Tried to write to: {result_path}")
            import traceback
            traceback.print_exc()
            pass

    if candidate_source and summary_path is not None and summary_path.exists():
        try:
            experiment_dir = summary_path.parent
            experiment_dir.mkdir(parents=True, exist_ok=True)
            (experiment_dir / "agent.c").write_text(candidate_source, encoding="utf-8")
        except OSError:
            pass

    return result


if __name__ == "__main__":
    result = evaluate()
    json.dump(result.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    if result.artifacts:
        sys.stdout.write("\nArtifacts:\n")
        for name, payload in result.artifacts.items():
            if isinstance(payload, bytes):
                try:
                    text_payload = payload.decode("utf-8")
                except UnicodeDecodeError:
                    text_payload = payload.decode("utf-8", errors="replace")
            else:
                text_payload = str(payload)
            sys.stdout.write(f"--- {name} ---\n{text_payload}\n")
