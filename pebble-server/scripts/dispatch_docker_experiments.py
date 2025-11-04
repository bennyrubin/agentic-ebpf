#!/usr/bin/env python3
"""
Launch multiple pebble experiments in parallel using Docker containers.

Each container runs run.sh with its own copy of the Pebble dataset and writes
results into the shared results directory. The script enforces a configurable
level of parallelism and optional CPU pinning via cpusets to minimise cross-run
interference.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import pathlib
import shlex
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent

try:
    # Import defaults so the dispatcher matches run_exp.py.
    from run_exp import DEFAULT_POLICIES as RUN_EXP_POLICIES, RATE_VALUES as RUN_EXP_RATES
except Exception:  # pragma: no cover - fallback if run_exp moves.
    RUN_EXP_POLICIES = ["round_robin", "scan_split"]
    RUN_EXP_RATES = [30000, 40000, 50000, 60000]


def parse_cpu_sets(value: str) -> list[str]:
    if not value:
        return []
    return [token.strip() for token in value.split(",") if token.strip()]


def parse_rates(value: str) -> list[int]:
    result = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        result.append(int(token))
    return result


def parse_policies(value: str) -> list[str]:
    return [token.strip() for token in value.split(",") if token.strip()]


def now_ts() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


@dataclass
class Job:
    index: int
    policy: str
    rate: int
    cpuset: Optional[str]
    run_id: str
    exp_id: str
    container_name: str
    command: list[str]
    log_path: pathlib.Path


def build_jobs(
    *,
    policies: Iterable[str],
    rates: Iterable[int],
    timestamp: str,
    cpu_sets: list[str],
    results_dir: pathlib.Path,
    logs_dir: pathlib.Path,
    image: str,
    base_command: list[str],
    extra_env: list[str],
) -> list[Job]:
    jobs: list[Job] = []
    cpuset_cycle = cpu_sets or [None]
    for idx, (policy, rate) in enumerate(
        ((p, r) for p in policies for r in rates)
    ):
        cpuset = cpuset_cycle[idx % len(cpuset_cycle)]
        suffix = f"{timestamp}-{idx:03d}-{policy}-{rate}"
        run_id = f"run-{suffix}"
        exp_id = f"exp-{suffix}"
        container_name = f"pebble-exp-{suffix}"
        log_path = logs_dir / f"{run_id}.log"

        cmd = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--privileged",
            "-v",
            f"{results_dir}:/results",
            "-v",
            f"{results_dir}/work:/opt/work",
        ]
        if cpuset:
            cmd += ["--cpuset-cpus", cpuset]
        for env_kv in extra_env:
            cmd += ["-e", env_kv]

        cmd += [
            "-e",
            f"EXP_ID={exp_id}",
            "-e",
            f"RUN_ID={run_id}",
            image,
        ]

        run_args = base_command + [
            "--policy",
            policy,
            "--rate",
            str(rate),
        ]
        full_command = cmd + run_args
        jobs.append(
            Job(
                index=idx,
                policy=policy,
                rate=rate,
                cpuset=cpuset,
                run_id=run_id,
                exp_id=exp_id,
                container_name=container_name,
                command=full_command,
                log_path=log_path,
            )
        )
    return jobs


async def run_job(job: Job, *, dry_run: bool, semaphore: asyncio.Semaphore) -> dict:
    meta = {
        "index": job.index,
        "policy": job.policy,
        "rate": job.rate,
        "cpuset": job.cpuset,
        "run_id": job.run_id,
        "exp_id": job.exp_id,
        "container": job.container_name,
        "command": job.command,
        "status": "pending",
    }

    if dry_run:
        print(f"[dry-run] {' '.join(shlex.quote(part) for part in job.command)}")
        meta["status"] = "dry-run"
        return meta

    async with semaphore:
        job.log_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"[dispatch] starting {job.run_id} ({job.policy} @ {job.rate} rps)")
        proc = await asyncio.create_subprocess_exec(
            *job.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        assert proc.stdout is not None
        with job.log_path.open("w", encoding="utf-8") as log_fh:
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                log_fh.write(line + "\n")
                log_fh.flush()
                print(f"[{job.run_id}] {line}")

        returncode = await proc.wait()
        meta["exit_code"] = returncode
        if returncode != 0:
            meta["status"] = "failed"
            raise RuntimeError(f"Container {job.container_name} exited with {returncode}")

        print(f"[dispatch] completed {job.run_id}")
        meta["status"] = "ok"
        return meta


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pebble experiments in parallel using Docker."
    )
    parser.add_argument(
        "--image",
        default="pebble-server:latest",
        help="Docker image to run (default: %(default)s)",
    )
    parser.add_argument(
        "--results-dir",
        default=str(ROOT / "results"),
        help="Host directory where run outputs should be stored (default: %(default)s)",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=2,
        help="Maximum concurrent containers (default: %(default)s)",
    )
    parser.add_argument(
        "--cpu-sets",
        default="",
        help="Comma-separated list of cpuset strings to pin containers (e.g. '0-3,4-7')",
    )
    parser.add_argument(
        "--policies",
        default=",".join(RUN_EXP_POLICIES),
        help="Policies to test (default: %(default)s)",
    )
    parser.add_argument(
        "--rates",
        default=",".join(str(r) for r in RUN_EXP_RATES),
        help="Rates to test (default: %(default)s)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=6,
        help="Worker threads passed to run.sh (default: %(default)s)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=15,
        help="Workload duration seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=4,
        help="Iterations per run (default: %(default)s)",
    )
    parser.add_argument(
        "--extra-run-args",
        default="",
        help="Additional arguments appended to run.sh (shell-split)",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        help="Additional environment variables for docker run (KEY=VALUE)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print docker commands without executing them.",
    )
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> None:
    results_dir = pathlib.Path(args.results_dir).resolve()
    work_dir = results_dir / "work"
    logs_dir = results_dir / "dispatch-logs"
    results_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    timestamp = now_ts()

    policies = parse_policies(args.policies)
    rates = parse_rates(args.rates)
    cpu_sets = parse_cpu_sets(args.cpu_sets)

    if not policies:
        raise SystemExit("No policies specified.")
    if not rates:
        raise SystemExit("No rates specified.")
    if args.max_parallel <= 0:
        raise SystemExit("--max-parallel must be positive.")

    base_command = [
        "--threads",
        str(args.threads),
        "--duration",
        str(args.duration),
        "--iterations",
        str(args.iterations),
        "--skip-db-setup",
    ]

    if args.extra_run_args:
        base_command += shlex.split(args.extra_run_args)

    jobs = build_jobs(
        policies=policies,
        rates=rates,
        timestamp=timestamp,
        cpu_sets=cpu_sets,
        results_dir=results_dir,
        logs_dir=logs_dir,
        image=args.image,
        base_command=base_command,
        extra_env=args.env,
    )

    manifest: list[dict] = []
    sem = asyncio.Semaphore(args.max_parallel)
    tasks = [asyncio.create_task(run_job(job, dry_run=args.dry_run, semaphore=sem)) for job in jobs]

    try:
        for task in asyncio.as_completed(tasks):
            manifest.append(await task)
    except Exception as exc:
        for t in tasks:
            t.cancel()
        print(f"[dispatch] error: {exc}", file=sys.stderr)
        raise
    finally:
        manifest.sort(key=lambda entry: entry.get("index", 0))
        manifest_path = results_dir / f"dispatch-manifest-{timestamp}.json"
        manifest_data = {
            "generated_at": dt.datetime.now().isoformat(),
            "image": args.image,
            "max_parallel": args.max_parallel,
            "policies": policies,
            "rates": rates,
            "threads": args.threads,
            "duration": args.duration,
            "iterations": args.iterations,
            "cpu_sets": cpu_sets,
            "env": args.env,
            "dry_run": args.dry_run,
            "jobs": manifest,
        }
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        print(f"[dispatch] wrote manifest to {manifest_path}")


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[dispatch] interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
