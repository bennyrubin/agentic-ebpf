#!/usr/bin/env python3
"""
Launch multiple synthetic-latency experiments in parallel using Docker containers.

Each container runs run.sh with its own isolated working directory and writes
results into the shared output volume. The script enforces a configurable level
of parallelism and optional CPU pinning via cpusets to minimise cross-run
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
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent

try:
    # Import defaults so the dispatcher matches run_exp.py.
    from run_exp import DEFAULT_POLICIES as RUN_EXP_POLICIES, RATE_VALUES as RUN_EXP_RATES
except Exception:  # pragma: no cover - fallback if run_exp moves.
    RUN_EXP_POLICIES = ["round_robin", "scan_split"]
    RUN_EXP_RATES = [30000, 40000, 50000, 60000]


def parse_cpu_sets(value: str, extras: Optional[list[str]] = None) -> list[str]:
    if not value:
        tokens: list[str] = []
    else:
        tokens = []

        has_group_sep = any(delim in value for delim in (";", "|"))
        grouped: list[str] = []
        for part in value.split(";"):
            grouped.extend(part.split("|"))
        grouped = [item.strip() for item in grouped if item.strip()]

        if has_group_sep and grouped:
            tokens.extend(grouped)
        else:
            for item in grouped or [value.strip()]:
                tokens.extend(part.strip() for part in item.split(",") if part.strip())

    if extras:
        for entry in extras:
            entry = entry.strip()
            if entry:
                tokens.append(entry)

    return tokens


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


def expand_cpu_spec(spec: str) -> list[int]:
    result: list[int] = []
    cleaned = spec.replace("\n", "").replace("\r", "").strip()
    if not cleaned:
        return result
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
            result.extend(range(start, end + 1))
        else:
            try:
                result.append(int(token))
            except ValueError as exc:
                raise ValueError(f"Invalid CPU token '{token}'") from exc
    return result


def read_numa_cpu_map() -> Dict[int, list[int]]:
    node_dir = pathlib.Path("/sys/devices/system/node")
    if not node_dir.is_dir():
        raise SystemExit(f"NUMA node directory missing at {node_dir}")

    cpu_map: Dict[int, list[int]] = {}
    for entry in sorted(node_dir.glob("node[0-9]*"), key=lambda p: int(p.name[4:])):
        cpulist_path = entry / "cpulist"
        try:
            raw = cpulist_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        cleaned = raw.strip()
        if not cleaned:
            continue
        try:
            cpus = expand_cpu_spec(cleaned)
        except ValueError as exc:
            raise SystemExit(
                f"Failed to parse NUMA node {entry.name} CPU list '{cleaned}': {exc}"
            ) from exc
        if cpus:
            cpu_map[int(entry.name[4:])] = cpus

    if not cpu_map:
        raise SystemExit(f"No NUMA nodes with CPUs found under {node_dir}")

    return cpu_map


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
            cmd += ["--cpuset-cpus", cpuset, "-e", f"CPUSET_POOL={cpuset}"]
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


async def run_job(
    job: Job,
    *,
    dry_run: bool,
    semaphore: asyncio.Semaphore,
    cpu_locks: dict[str, asyncio.Lock],
) -> dict:
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

    async def execute_job() -> dict:
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
                raise RuntimeError(
                    f"Container {job.container_name} exited with {returncode}"
                )

            print(f"[dispatch] completed {job.run_id}")
            meta["status"] = "ok"
            return meta

    cpu_lock = cpu_locks.get(job.cpuset) if job.cpuset else None
    if cpu_lock is None:
        return await execute_job()

    async with cpu_lock:
        return await execute_job()


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
        "--server-cores",
        type=int,
        required=True,
        help="Dedicated cores per container for the server (from a single NUMA node).",
    )
    parser.add_argument(
        "--client-cores",
        type=int,
        required=True,
        help="Dedicated cores per container for the client (from the same NUMA node).",
    )
    parser.add_argument(
        "--cpu-sets",
        default="",
        help=(
            "List of cpuset strings. Separate multiple sets with commas as before "
            "(e.g. '0-3,4-7'), or use ';'/'|' when an individual set already contains "
            "commas (e.g. '0,2,4,6,8;10,12,14,16,18')."
        ),
    )
    parser.add_argument(
        "--cpu-set",
        action="append",
        dest="cpu_set",
        default=None,
        help=(
            "Repeatable cpuset string for finer control. Example: "
            "--cpu-set 0,2,4,6,8 --cpu-set 10,12,14,16,18."
        ),
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
        default=10,
        help="Workload duration seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--get-delay",
        default="",
        help="Synthetic GET delay passed to run.sh (--get-delay).",
    )
    parser.add_argument(
        "--scan-delay",
        default="",
        help="Synthetic SCAN delay passed to run.sh (--scan-delay).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
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
    parser.add_argument(
        "--skip-run-exp",
        action="store_true",
        help="Skip invoking run_exp.py after dispatch completes.",
    )
    parser.add_argument(
        "--run-exp-path",
        default=str(ROOT / "run_exp.py"),
        help="Path to run_exp.py (default: %(default)s)",
    )
    parser.add_argument(
        "--run-exp-output-dir",
        default=str(ROOT / "results" / "experiments"),
        help="Output directory passed to run_exp.py (default: %(default)s)",
    )
    parser.add_argument(
        "--run-exp-extra-args",
        default="",
        help="Additional arguments appended to run_exp.py (shell-split).",
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
    manual_cpu_sets = parse_cpu_sets(args.cpu_sets, args.cpu_set)

    if not policies:
        raise SystemExit("No policies specified.")
    if not rates:
        raise SystemExit("No rates specified.")
    if args.max_parallel <= 0:
        raise SystemExit("--max-parallel must be positive.")

    if args.server_cores <= 0 or args.client_cores <= 0:
        raise SystemExit("--server-cores and --client-cores must be positive integers.")

    numa_cpu_map = read_numa_cpu_map()
    cpu_to_node: Dict[int, int] = {
        cpu: node for node, cpus in numa_cpu_map.items() for cpu in cpus
    }

    per_container_total = args.server_cores + args.client_cores
    eligible_nodes: list[Tuple[int, list[int]]] = [
        (node, cpus)
        for node, cpus in sorted(numa_cpu_map.items())
        if len(cpus) >= per_container_total
    ]
    if not eligible_nodes:
        raise SystemExit(
            f"No NUMA node has at least {per_container_total} CPUs to satisfy "
            f"server={args.server_cores}, client={args.client_cores}."
        )

    max_parallel_capacity = len(eligible_nodes)
    if args.max_parallel > max_parallel_capacity:
        raise SystemExit(
            f"--max-parallel={args.max_parallel} exceeds NUMA node capacity of "
            f"{max_parallel_capacity} containers (nodes with sufficient CPUs: "
            f"{[node for node, _ in eligible_nodes]})."
        )

    if manual_cpu_sets:
        validated_sets: list[str] = []
        for cpuset in manual_cpu_sets:
            try:
                cpus = expand_cpu_spec(cpuset)
            except ValueError as exc:
                raise SystemExit(f"Invalid --cpu-set '{cpuset}': {exc}") from exc
            if len(cpus) < per_container_total:
                raise SystemExit(
                    f"cpuset '{cpuset}' contains {len(cpus)} CPUs but "
                    f"{per_container_total} are required (server={args.server_cores}, client={args.client_cores})."
                )
            nodes = {cpu_to_node.get(cpu) for cpu in cpus}
            if None in nodes:
                unknown = [cpu for cpu in cpus if cpu_to_node.get(cpu) is None]
                raise SystemExit(
                    f"cpuset '{cpuset}' references CPUs not present in NUMA topology: {unknown}"
                )
            if len(nodes) != 1:
                raise SystemExit(
                    f"cpuset '{cpuset}' spans multiple NUMA nodes ({sorted(nodes)}); "
                    f"please restrict each container to a single node."
                )
            validated_sets.append(cpuset)
        cpu_sets = validated_sets
    else:
        cpu_sets = []
        for node, node_cpus in eligible_nodes[:args.max_parallel]:
            slice_cpus = node_cpus[:per_container_total]
            if len(slice_cpus) != per_container_total:
                raise SystemExit(
                    f"NUMA node {node} does not have enough CPUs for the requested "
                    f"allocation (needed {per_container_total}, have {len(node_cpus)})."
                )
            cpu_sets.append(",".join(str(cpu) for cpu in slice_cpus))

    numa_summary = {node: cpus for node, cpus in eligible_nodes}

    cpu_locks = {cpuset: asyncio.Lock() for cpuset in {c for c in cpu_sets if c}}

    base_command = [
        "--server-cores",
        str(args.server_cores),
        "--client-cores",
        str(args.client_cores),
        "--threads",
        str(args.threads),
        "--duration",
        str(args.duration),
        "--iterations",
        str(args.iterations),
    ]
    if args.get_delay:
        base_command += ["--get-delay", args.get_delay]
    if args.scan_delay:
        base_command += ["--scan-delay", args.scan_delay]

    if args.extra_run_args:
        base_command += shlex.split(args.extra_run_args)

    quoted_base = " ".join(shlex.quote(part) for part in base_command)
    print(
        "[dispatch] configuration:",
        f"max_parallel={args.max_parallel}",
        f"server_cores={args.server_cores}",
        f"client_cores={args.client_cores}",
        f"get_delay={args.get_delay or '<default>'}",
        f"scan_delay={args.scan_delay or '<default>'}",
        f"policies={policies}",
        f"rates={rates}",
        f"cpu_sets={cpu_sets or ['<none>']}",
        f"numa_nodes={numa_summary}",
        f"base_command={quoted_base}",
        f"extra_env={args.env or ['<none>']}",
    )

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

    print(f"[dispatch] scheduled {len(jobs)} jobs")

    manifest: list[dict] = []
    sem = asyncio.Semaphore(args.max_parallel)
    tasks = [
        asyncio.create_task(
            run_job(
                job,
                dry_run=args.dry_run,
                semaphore=sem,
                cpu_locks=cpu_locks,
            )
        )
        for job in jobs
    ]
    dispatch_failed = False
    try:
        for task in asyncio.as_completed(tasks):
            manifest.append(await task)
    except Exception as exc:
        for t in tasks:
            t.cancel()
        print(f"[dispatch] error: {exc}", file=sys.stderr)
        dispatch_failed = True
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
            "server_cores": args.server_cores,
            "client_cores": args.client_cores,
            "per_container_total_cores": per_container_total,
            "numa_nodes": numa_summary,
            "get_delay": args.get_delay,
            "scan_delay": args.scan_delay,
            "cpu_sets": cpu_sets,
            "env": args.env,
            "dry_run": args.dry_run,
            "jobs": manifest,
        }
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        print(f"[dispatch] wrote manifest to {manifest_path}")
        pointer_path = results_dir / "latest-dispatch-manifest.txt"
        pointer_path.write_text(str(manifest_path), encoding="utf-8")
        print(f"[dispatch] updated manifest pointer {pointer_path}")

        if dispatch_failed:
            print("[dispatch] skipping run_exp.py because one or more jobs failed", file=sys.stderr)
        elif args.dry_run:
            print("[dispatch] dry-run requested; skipping run_exp.py")
        elif args.skip_run_exp:
            print("[dispatch] run_exp.py invocation disabled via --skip-run-exp")
        else:
            run_exp_path = pathlib.Path(args.run_exp_path)
            if not run_exp_path.is_absolute():
                run_exp_path = ROOT / run_exp_path
            run_exp_output_dir = pathlib.Path(args.run_exp_output_dir)
            run_exp_cmd = [
                sys.executable or "python3",
                str(run_exp_path),
                "--manifest",
                str(manifest_path),
                "--runs-root",
                str(results_dir),
                "--output-dir",
                str(run_exp_output_dir),
            ]
            if args.run_exp_extra_args:
                run_exp_cmd += shlex.split(args.run_exp_extra_args)

            print("[dispatch] invoking run_exp.py:", " ".join(shlex.quote(part) for part in run_exp_cmd))
            try:
                subprocess.run(run_exp_cmd, check=True)
            except FileNotFoundError as exc:
                print(f"[dispatch] run_exp.py not found: {exc}", file=sys.stderr)
                raise
            except subprocess.CalledProcessError as exc:
                print(f"[dispatch] run_exp.py exited with {exc.returncode}", file=sys.stderr)
                raise


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[dispatch] interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
