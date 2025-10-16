#!/usr/bin/env python3

"""Summarize wrk logs and emit per-worker latency/throughput stats."""

from __future__ import annotations

import argparse
import csv
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


_LATENCY_UNITS_MS = {
    "us": 1e-3,
    "ms": 1.0,
    "s": 1e3,
}

_THROUGHPUT_SUFFIXES = {
    "": 1.0,
    "k": 1e3,
    "m": 1e6,
    "g": 1e9,
}

_WORKER_RE = re.compile(r"wrk_client_(\d+)\.log$")
_SECTION_START_RE = re.compile(r"^===== (.+) START =====$")
_SECTION_END_RE = re.compile(r"^===== (.+) END =====$")


@dataclass
class WorkerStats:
    worker_id: str
    latency_avg_ms: float
    latency_stdev_ms: float
    req_per_sec_avg: float
    req_per_sec_stdev: float
    log_path: Path

    def as_row(self) -> dict[str, str]:
        return {
            "worker_id": self.worker_id,
            "latency_avg_ms": f"{self.latency_avg_ms:.6f}",
            "latency_stdev_ms": f"{self.latency_stdev_ms:.6f}",
            "req_per_sec_avg": f"{self.req_per_sec_avg:.6f}",
            "req_per_sec_stdev": f"{self.req_per_sec_stdev:.6f}",
            "log_path": str(self.log_path),
        }


def _extract_metrics_from_lines(lines: Iterable[str]) -> tuple[float, float, float, float]:
    latency_avg_ms = latency_stdev_ms = None
    req_avg = req_stdev = None

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("Latency"):
            parts = line.split()
            if len(parts) < 3:
                continue
            latency_avg_ms = parse_latency(parts[1])
            latency_stdev_ms = parse_latency(parts[2])
        elif line.startswith("Req/Sec"):
            parts = line.split()
            if len(parts) < 3:
                continue
            req_avg = parse_throughput(parts[1])
            req_stdev = parse_throughput(parts[2])

    missing = [
        name
        for name, value in [
            ("latency_avg", latency_avg_ms),
            ("latency_stdev", latency_stdev_ms),
            ("req_per_sec_avg", req_avg),
            ("req_per_sec_stdev", req_stdev),
        ]
        if value is None
    ]
    if missing:
        raise ValueError(f"Missing fields: {', '.join(missing)}")

    return latency_avg_ms, latency_stdev_ms, req_avg, req_stdev


def parse_latency(token: str) -> float:
    match = re.fullmatch(r"([0-9]*\.?[0-9]+)([a-z]+)", token.lower())
    if not match:
        raise ValueError(f"Unrecognized latency value: {token!r}")
    value = float(match.group(1))
    unit = match.group(2)
    if unit not in _LATENCY_UNITS_MS:
        raise ValueError(f"Unsupported latency unit: {token!r}")
    return value * _LATENCY_UNITS_MS[unit]


def parse_throughput(token: str) -> float:
    token = token.strip()
    if token.lower() in {"nan", "-nan", "+nan"}:
        return 0.0
    match = re.fullmatch(r"([0-9]*\.?[0-9]+)([kmg]?)", token.lower())
    if not match:
        raise ValueError(f"Unrecognized throughput value: {token!r}")
    value = float(match.group(1))
    suffix = match.group(2)
    if suffix not in _THROUGHPUT_SUFFIXES:
        raise ValueError(f"Unsupported throughput suffix: {token!r}")
    return value * _THROUGHPUT_SUFFIXES[suffix]


def parse_wrk_log(path: Path) -> WorkerStats:
    worker_id = _deduce_worker_id(path)
    with path.open("r", encoding="utf-8") as handle:
        try:
            latency_avg_ms, latency_stdev_ms, req_avg, req_stdev = _extract_metrics_from_lines(handle)
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from exc

    return WorkerStats(
        worker_id=worker_id,
        latency_avg_ms=latency_avg_ms,
        latency_stdev_ms=latency_stdev_ms,
        req_per_sec_avg=req_avg,
        req_per_sec_stdev=req_stdev,
        log_path=path,
    )


def _deduce_worker_id(path: Path) -> str:
    match = _WORKER_RE.search(path.name)
    if match:
        return match.group(1)
    return path.stem


def parse_aggregated_log(path: Path) -> list[WorkerStats]:
    stats: list[WorkerStats] = []
    current_name: str | None = None
    current_lines: list[str] = []

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped = raw_line.rstrip("\n")
            start_match = _SECTION_START_RE.match(stripped)
            if start_match:
                if current_name is not None:
                    raise ValueError(
                        f"{path}: encountered nested section start before closing previous section {current_name!r}"
                    )
                current_name = start_match.group(1)
                current_lines = []
                continue

            end_match = _SECTION_END_RE.match(stripped)
            if end_match and current_name is not None:
                if end_match.group(1) != current_name:
                    raise ValueError(
                        f"{path}: section end {end_match.group(1)!r} does not match current section {current_name!r}"
                    )
                worker_id = _deduce_worker_id(Path(current_name))
                try:
                    latency_avg_ms, latency_stdev_ms, req_avg, req_stdev = _extract_metrics_from_lines(
                        current_lines
                    )
                except ValueError as exc:
                    raise ValueError(f"{path} [{current_name}]: {exc}") from exc

                stats.append(
                    WorkerStats(
                        worker_id=worker_id,
                        latency_avg_ms=latency_avg_ms,
                        latency_stdev_ms=latency_stdev_ms,
                        req_per_sec_avg=req_avg,
                        req_per_sec_stdev=req_stdev,
                        log_path=path.parent / current_name,
                    )
                )
                current_name = None
                current_lines = []
                continue

            if current_name is not None:
                current_lines.append(raw_line)

    if current_name is not None:
        raise ValueError(
            f"{path}: reached end of file before closing section {current_name!r}"
        )

    if not stats:
        raise ValueError(f"{path}: no worker sections found in aggregated log")

    return stats


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


def write_csv(stats: Iterable[WorkerStats], output_path: Path) -> None:
    fieldnames = [
        "worker_id",
        "latency_avg_ms",
        "latency_stdev_ms",
        "req_per_sec_avg",
        "req_per_sec_stdev",
        "log_path",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for entry in stats:
            writer.writerow(entry.as_row())


def compute_run_metrics(stats: Sequence[WorkerStats]) -> RunMetrics:
    if not stats:
        raise ValueError("No worker stats provided for scoring.")

    latency_values = [entry.latency_avg_ms for entry in stats]
    req_values = [entry.req_per_sec_avg for entry in stats]

    avg_latency_ms = statistics.mean(latency_values)
    avg_req_per_sec = statistics.mean(req_values)
    latency_stddev_ms = statistics.pstdev(latency_values) if len(stats) > 1 else 0.0
    req_stddev = statistics.pstdev(req_values) if len(stats) > 1 else 0.0

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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize wrk logs into CSV and compute run score."
    )
    parser.add_argument(
        "--logs-dir",
        default="wrk_log",
        help="Directory containing wrk_client_*.log files (default: %(default)s).",
    )
    parser.add_argument(
        "--output",
        default="basic-workload-summary.csv",
        help="CSV output path (default: %(default)s).",
    )
    parser.add_argument(
        "--metrics-output",
        default="basic-workload-summary-metrics.csv",
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

    worker_logs = sorted(logs_dir.glob("wrk_client_*.log"))
    stats: list[WorkerStats] = [parse_wrk_log(path) for path in worker_logs]

    if not stats:
        aggregated_log = logs_dir / "basic-workload.log"
        if aggregated_log.exists():
            stats = parse_aggregated_log(aggregated_log)
        else:
            print(
                f"No wrk_client_*.log files or aggregated basic-workload.log found in {logs_dir}",
                file=sys.stderr,
            )
            return 1

    output_path = Path(args.output)
    write_csv(stats, output_path)
    print(f"Wrote CSV: {output_path}")

    metrics_output = Path(args.metrics_output)
    metrics = compute_run_metrics(stats)
    write_metrics_csv(metrics, metrics_output)
    print(f"Wrote metrics CSV: {metrics_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
