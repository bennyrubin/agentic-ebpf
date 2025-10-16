#!/usr/bin/env python3

"""Summarize per-connection workload results into CSV outputs."""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


@dataclass
class WorkerSummary:
    worker_id: str
    total_requests: int
    success: int
    failure: int
    duration_sec: float
    throughput_req_per_sec: float
    latency_avg_ms: float
    latency_min_ms: float
    latency_max_ms: float
    summary_path: Path

    def as_row(self) -> dict[str, str]:
        return {
            "worker_id": self.worker_id,
            "total_requests": str(self.total_requests),
            "success": str(self.success),
            "failure": str(self.failure),
            "duration_sec": f"{self.duration_sec:.6f}",
            "throughput_req_per_sec": f"{self.throughput_req_per_sec:.6f}",
            "latency_avg_ms": f"{self.latency_avg_ms:.6f}",
            "latency_min_ms": f"{self.latency_min_ms:.6f}",
            "latency_max_ms": f"{self.latency_max_ms:.6f}",
            "summary_path": str(self.summary_path),
        }


@dataclass
class RunMetrics:
    workers: int
    avg_latency_ms: float
    latency_stddev_ms: float
    avg_req_per_sec: float
    req_per_sec_stddev: float
    score: float

    def as_row(self) -> dict[str, str]:
        return {
            "workers": str(self.workers),
            "avg_latency_ms": f"{self.avg_latency_ms:.6f}",
            "latency_stddev_ms": f"{self.latency_stddev_ms:.6f}",
            "avg_req_per_sec": f"{self.avg_req_per_sec:.6f}",
            "req_per_sec_stddev": f"{self.req_per_sec_stddev:.6f}",
            "score": f"{self.score:.6f}",
        }


def parse_summary_file(path: Path) -> WorkerSummary:
    data: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()

    required_keys = [
        "success",
        "failure",
        "latency_sum_ns",
        "latency_count",
        "latency_min_ns",
        "latency_max_ns",
        "duration_ns",
    ]
    missing = [key for key in required_keys if key not in data]
    if missing:
        raise ValueError(f"{path} missing fields: {', '.join(missing)}")

    success = int(data["success"])
    failure = int(data["failure"])
    total_requests = success + failure

    latency_count = int(data["latency_count"])
    latency_sum_ns = int(data["latency_sum_ns"])
    latency_min_ns = int(data["latency_min_ns"])
    latency_max_ns = int(data["latency_max_ns"])
    duration_ns = int(data["duration_ns"])

    duration_sec = duration_ns / 1e9 if duration_ns > 0 else 0.0
    throughput_req_per_sec = (
        total_requests / duration_sec if duration_sec > 0 else 0.0
    )

    latency_avg_ms = (
        (latency_sum_ns / latency_count) / 1e6 if latency_count > 0 else 0.0
    )
    latency_min_ms = latency_min_ns / 1e6 if latency_min_ns > 0 else 0.0
    latency_max_ms = latency_max_ns / 1e6 if latency_max_ns > 0 else 0.0

    worker_id = _extract_worker_id(path)

    return WorkerSummary(
        worker_id=worker_id,
        total_requests=total_requests,
        success=success,
        failure=failure,
        duration_sec=duration_sec,
        throughput_req_per_sec=throughput_req_per_sec,
        latency_avg_ms=latency_avg_ms,
        latency_min_ms=latency_min_ms,
        latency_max_ms=latency_max_ms,
        summary_path=path,
    )


def write_worker_csv(stats: Iterable[WorkerSummary], output_path: Path) -> None:
    fieldnames = [
        "worker_id",
        "total_requests",
        "success",
        "failure",
        "duration_sec",
        "throughput_req_per_sec",
        "latency_avg_ms",
        "latency_min_ms",
        "latency_max_ms",
        "summary_path",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for entry in stats:
            writer.writerow(entry.as_row())


def compute_run_metrics(stats: Sequence[WorkerSummary]) -> RunMetrics:
    if not stats:
        raise ValueError("No worker stats provided for scoring.")

    latency_values = [entry.latency_avg_ms for entry in stats]
    throughput_values = [entry.throughput_req_per_sec for entry in stats]

    avg_latency_ms = statistics.mean(latency_values)
    avg_req_per_sec = statistics.mean(throughput_values)
    latency_stddev_ms = statistics.pstdev(latency_values) if len(stats) > 1 else 0.0
    req_stddev = statistics.pstdev(throughput_values) if len(stats) > 1 else 0.0

    if avg_latency_ms == 0:
        raise ValueError("Average latency is zero; cannot compute score.")

    score = avg_req_per_sec / avg_latency_ms

    return RunMetrics(
        workers=len(stats),
        avg_latency_ms=avg_latency_ms,
        latency_stddev_ms=latency_stddev_ms,
        avg_req_per_sec=avg_req_per_sec,
        req_per_sec_stddev=req_stddev,
        score=score,
    )


def write_metrics_csv(metrics: RunMetrics, output_path: Path) -> None:
    fieldnames = [
        "workers",
        "avg_latency_ms",
        "latency_stddev_ms",
        "avg_req_per_sec",
        "req_per_sec_stddev",
        "score",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(metrics.as_row())


def _extract_worker_id(path: Path) -> str:
    name = path.stem
    if name.startswith("worker_"):
        return name.split("_", 1)[1]
    return name


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize per-connection workload logs into CSV outputs."
    )
    parser.add_argument(
        "--logs-dir",
        default="per_connection_wrk_log",
        help="Directory containing worker_*.summary files (default: %(default)s).",
    )
    parser.add_argument(
        "--output",
        default="per-connection-workload-summary.csv",
        help="CSV output path (default: %(default)s).",
    )
    parser.add_argument(
        "--metrics-output",
        default="per-connection-workload-metrics.csv",
        help="Run-level metrics CSV output path (default: %(default)s).",
    )
    args = parser.parse_args(argv)

    logs_dir = Path(args.logs_dir)
    if not logs_dir.exists():
        print(f"Logs directory not found: {logs_dir}", file=sys.stderr)
        return 1
    if not logs_dir.is_dir():
        print(f"Logs path is not a directory: {logs_dir}", file=sys.stderr)
        return 1

    summary_files = sorted(logs_dir.glob("worker_*.summary"))
    if not summary_files:
        print(f"No worker summary files found in {logs_dir}", file=sys.stderr)
        return 1

    worker_stats = [parse_summary_file(path) for path in summary_files]
    output_path = Path(args.output)
    write_worker_csv(worker_stats, output_path)
    print(f"Wrote worker CSV: {output_path}")

    metrics_output = Path(args.metrics_output)
    metrics = compute_run_metrics(worker_stats)
    write_metrics_csv(metrics, metrics_output)
    print(f"Wrote metrics CSV: {metrics_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
