"""
OpenEvolve evaluator for the agentic eBPF HTTP server project.

This evaluator orchestrates the project-specific workflow:
1. Compile the eBPF programs and policy code via `go generate`.
2. Launch the HTTP servers and supporting collectors.
3. Execute the standard workload benchmark.
4. Collect metrics/artifacts and convert them into an EvaluationResult.
"""

from __future__ import annotations

import csv
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

from openevolve.evaluation_result import EvaluationResult

# Project paths
ROOT_DIR = Path(__file__).resolve().parent
SERVER_CODE_DIR = ROOT_DIR / "server_code"
WORKLOADS_DIR = ROOT_DIR / "workloads"
WORKLOAD_LOG_DIR = WORKLOADS_DIR / "wrk_log"
LOG_DIR = ROOT_DIR / "log"

SERVER_LAUNCH_CMD: Sequence[str] = ("sudo", "-n", "./launch_servers.sh", "4", "agent")
WORKLOAD_CMD: Sequence[str] = ("./basic-workload.sh", "20", "10")

ERROR_PATTERN = re.compile(r"\b(error|fail|exit status 1)\b", re.IGNORECASE)
SERVER_LOG_GLOB = "server*.log"

METRICS_DEFAULTS: Dict[str, float] = {
    "average_tput": 0.0,
    "average_latency": 0.0,
    "total_score": 0.0,
    "run_successful": 0.0,
    "compile_successful": 0.0,
}


def _read_stream(stream, buffer: list[str]) -> None:
    """Continuously read lines from a stream into a shared buffer."""
    if stream is None:
        return
    try:
        for line in stream:
            buffer.append(line)
    except Exception as exc:  # pragma: no cover - defensive
        buffer.append(f"[stream read error] {exc}")


def _run_go_generate() -> Tuple[bool, str]:
    """Run `go generate ./...` inside the server_code directory."""
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
    return completed.returncode == 0, output.strip()


def _start_servers() -> Tuple[Optional[subprocess.Popen], list[str], threading.Thread]:
    """Launch the servers with sudo and return process handle plus captured output."""
    output_buffer: list[str] = []
    try:
        proc = subprocess.Popen(
            SERVER_LAUNCH_CMD,
            cwd=ROOT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Failed to launch servers: {exc}") from exc

    reader = threading.Thread(target=_read_stream, args=(proc.stdout, output_buffer), daemon=True)
    reader.start()
    return proc, output_buffer, reader


def _terminate_process(proc: Optional[subprocess.Popen], reader: Optional[threading.Thread]) -> None:
    """Gracefully terminate the launch_servers process group."""
    if proc is None:
        return

    try:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            except ProcessLookupError:
                pass

            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
    finally:
        if reader:
            reader.join(timeout=2)
        if proc.stdout:
            proc.stdout.close()


def _wait_for_server_logs(proc: subprocess.Popen, timeout: float = 30.0) -> bool:
    """
    Wait until at least one server log file appears or the process exits.

    Returns:
        True if logs became available before timeout, False otherwise.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False

        if any(LOG_DIR.glob(SERVER_LOG_GLOB)):
            return True
        time.sleep(1.0)
    return False


def _scan_server_logs_for_errors() -> Dict[str, str]:
    """Scan each server log for lines containing the keyword 'error'."""
    findings: Dict[str, str] = {}
    for path in sorted(LOG_DIR.glob(SERVER_LOG_GLOB)):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except FileNotFoundError:
            continue

        match = ERROR_PATTERN.search(content)
        if match:
            findings[path.name] = content
    return findings


def _run_workload() -> Tuple[bool, subprocess.CompletedProcess[str]]:
    """Execute the basic workload script."""
    try:
        completed = subprocess.run(
            ("sudo", "-n", *WORKLOAD_CMD),
            cwd=WORKLOADS_DIR,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        dummy = subprocess.CompletedProcess(WORKLOAD_CMD, returncode=127, stdout="", stderr=str(exc))
        return False, dummy
    finally:
        # Kill all "launch_servers" and "server_code" processes
        try:
            # Purposefully wait a second before cleanup to allow subprocesses to shut down gracefully
            time.sleep(1)
            subprocess.run(["sudo", "-n", "pkill", "-f", "launch_servers"], cwd=WORKLOADS_DIR, check=False)
            subprocess.run(["sudo", "-n", "pkill", "-f", "server_code"], cwd=WORKLOADS_DIR, check=False)
        except Exception:
            pass  # Ignore errors in cleanup

    return completed.returncode == 0, completed


def _parse_metrics_csv(path: Path) -> Tuple[float, float, float]:
    """Extract throughput, latency, and score from the summary metrics CSV."""
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            avg_tput = float(row.get("avg_req_per_sec", 0.0))
            avg_latency = float(row.get("avg_latency_ms", 0.0))
            score = float(row.get("score", 0.0))
            return avg_tput, avg_latency, score
    raise ValueError(f"No rows found in metrics CSV: {path}")


def _collect_artifact(path: Path) -> Optional[str]:
    """Return file contents if the path exists."""
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:  # pragma: no cover - defensive
        return f"Failed to read {path}: {exc}"


def _latest_log(pattern: str, newer_than: float) -> Optional[Path]:
    """Return the most recent log file matching pattern, preferring files newer than `newer_than`."""
    candidates = [p for p in LOG_DIR.glob(pattern)]
    if not candidates:
        return None

    recent = [p for p in candidates if p.stat().st_mtime >= newer_than]
    if recent:
        candidates = recent

    return max(candidates, key=lambda p: p.stat().st_mtime, default=None)


def evaluate(program_path: str) -> EvaluationResult:
    """
    Run the project-specific evaluation workflow.

    Args:
        program_path: Path to the candidate program (unused here; kept for API compatibility).
    """
    metrics = METRICS_DEFAULTS.copy()
    artifacts: Dict[str, str] = {}

    compile_ok, compile_output = _run_go_generate()
    artifacts["compile_output"] = compile_output
    if not compile_ok:
        return EvaluationResult(metrics=metrics, artifacts=artifacts)

    metrics["compile_successful"] = 1.0

    server_proc: Optional[subprocess.Popen] = None
    server_output: list[str] = []
    server_reader: Optional[threading.Thread] = None
    launch_started_at = time.time()

    try:
        try:
            server_proc, server_output, server_reader = _start_servers()
        except RuntimeError as exc:
            artifacts["launch_failure"] = str(exc)
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        if not _wait_for_server_logs(server_proc):
            # Either the process exited early or logs never appeared.
            exit_code = server_proc.poll()
            artifacts["launch_failure"] = (
                "Server logs did not appear before timeout "
                f"(exit_code={exit_code})."
            )
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        # Check if launch script exited prematurely
        if server_proc.poll() is not None:
            artifacts["launch_failure"] = f"launch_servers.sh exited early with code {server_proc.returncode}"
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        error_logs = _scan_server_logs_for_errors()
        if error_logs:
            for name, content in error_logs.items():
                artifacts[f"log_{name}"] = content
            artifacts["launch_failure"] = "Detected 'error' keyword in server logs."
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        workload_ok, workload_result = _run_workload()
        artifacts["workload_stdout"] = workload_result.stdout
        artifacts["workload_stderr"] = workload_result.stderr
        if not workload_ok:
            artifacts["workload_failure"] = (
                f"basic-workload.sh exited with code {workload_result.returncode}"
            )
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        summary_path = WORKLOAD_LOG_DIR / "basic-workload-summary.csv"
        metrics_path = WORKLOAD_LOG_DIR / "basic-workload-summary-metrics.csv"

        if not summary_path.exists() or not metrics_path.exists():
            artifacts["workload_failure"] = (
                "Expected workload summary files were not generated."
            )
            return EvaluationResult(metrics=metrics, artifacts=artifacts)

        avg_tput, avg_latency, total_score = _parse_metrics_csv(metrics_path)

        metrics.update(
            {
                "average_tput": avg_tput,
                "average_latency": avg_latency,
                "total_score": total_score,
                "run_successful": 1.0,
            }
        )

        # Collect required artifacts
        summary_content = _collect_artifact(summary_path)
        if summary_content is not None:
            artifacts["basic_workload_summary_csv"] = summary_content

        metrics_content = _collect_artifact(metrics_path)
        if metrics_content is not None:
            artifacts["basic_workload_metrics_csv"] = metrics_content

        acceptq_log = _latest_log("acceptq_stats*.log", launch_started_at)
        if acceptq_log:
            acceptq_content = _collect_artifact(acceptq_log)
            if acceptq_content is not None:
                artifacts["acceptq_stats_log"] = acceptq_content

        cpu_log = _latest_log("cpu_stats*.log", launch_started_at)
        if cpu_log:
            cpu_content = _collect_artifact(cpu_log)
            if cpu_content is not None:
                artifacts["cpu_stats_log"] = cpu_content

        return EvaluationResult(metrics=metrics, artifacts=artifacts)

    finally:
        _terminate_process(server_proc, server_reader)
        if server_output and "launch_servers_output" not in artifacts:
            artifacts["launch_servers_output"] = "".join(server_output)
