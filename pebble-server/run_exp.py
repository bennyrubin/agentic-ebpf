#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent
RUN_SH = ROOT / "run.sh"
#DEFAULT_POLICIES = ["default", "round_robin", "agent", "scan_split"]
DEFAULT_POLICIES = ["default", "round_robin", "scan_split"]
#RATE_VALUES = [30000, 40000, 50000, 60000]
RATE_VALUES = [50000, 90000, 120000]
RUN_DIR_RE = re.compile(r"Logs and results stored in (.+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run rate sweep experiments and plot overall p99 latency per policy."
    )
    parser.add_argument(
        "--policies",
        default=None,
        help=f"Comma-separated list of policies to test (default: {','.join(DEFAULT_POLICIES)})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=6,
        help="Number of worker threads to pass to run.sh (default: %(default)s)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=4,
        help="Iterations per run.sh invocation (default: %(default)s)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=15,
        help="Duration in seconds for each workload run (default: %(default)s)",
    )
    parser.add_argument(
        "--rates",
        default=None,
        help=f"Comma-separated list of send rates to sweep (default: {','.join(str(v) for v in RATE_VALUES)})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(ROOT / "results" / "experiments"),
        help="Directory where experiment summaries and plots are stored (default: %(default)s)",
    )
    parser.add_argument(
        "--skip-plot", 
        action="store_true",
        help="Skip generating the matplotlib plot (useful for headless environments).",
    )
    parser.add_argument(
        "--manifest",
        help="Reuse existing runs recorded in a dispatch manifest JSON file.",
    )
    parser.add_argument(
        "--runs-root",
        default=str(ROOT / "results"),
        help="Root directory containing run-* directories when using --manifest (default: %(default)s)",
    )
    return parser.parse_args()


def ensure_run_sh() -> None:
    if not RUN_SH.exists():
        sys.exit(f"run.sh not found at expected location {RUN_SH}")
    if not os.access(RUN_SH, os.X_OK):
        sys.exit(f"run.sh is not executable: {RUN_SH}")


def invoke_run_sh(policy: str, rate: int, threads: int, iterations: int, duration: int) -> pathlib.Path:
    cmd = [
        str(RUN_SH),
        "--threads",
        str(threads),
        "--policy",
        policy,
        "--rate",
        str(rate),
        "--iterations",
        str(iterations),
        "--duration",
        str(duration),
    ]
    print(f"\n=== Running experiment policy={policy} rate={rate} iterations={iterations} ===")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(ROOT),
    )

    run_dir = None
    captured_lines = []
    assert process.stdout is not None  # for type checkers
    for line in process.stdout:
        print(line, end="")
        captured_lines.append(line)
        match = RUN_DIR_RE.search(line)
        if match:
            run_dir = match.group(1).strip()

    returncode = process.wait()
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, cmd)

    if not run_dir:
        combined = "".join(captured_lines)
        match = RUN_DIR_RE.search(combined)
        if not match:
            raise RuntimeError(
                "Failed to locate run directory in run.sh output for "
                f"policy={policy}, rate={rate}"
            )
        run_dir = match.group(1).strip()

    run_path = pathlib.Path(run_dir)
    if not run_path.exists():
        raise FileNotFoundError(f"run.sh reported run directory {run_path}, but it does not exist")
    return run_path


def load_summary(run_dir: pathlib.Path) -> dict:
    summary_path = run_dir / "workload_summary.json"
    if not summary_path.exists():
        raise FileNotFoundError(f"Missing workload_summary.json in {run_dir}")
    with summary_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def extract_metric(summary: dict, metric_key: str) -> tuple[float, float, list[float]]:
    summary_block = summary.get("summary", {})
    metric_stats = summary_block.get(metric_key)
    if not metric_stats:
        raise KeyError(f"{metric_key} missing from summary JSON")
    if "average" not in metric_stats:
        raise KeyError(f"{metric_key}.average missing from summary JSON")
    average = float(metric_stats["average"])
    stddev = float(metric_stats.get("stddev", 0.0))

    iteration_vals = []
    for entry in summary.get("iterations", []):
        value = entry.get(metric_key)
        if value is not None:
            iteration_vals.append(float(value))
    return average, stddev, iteration_vals


def write_experiment_summary(
    experiment_dir: pathlib.Path,
    metadata: dict,
    records: list[dict],
) -> None:
    experiment_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": metadata,
        "records": records,
    }
    out_path = experiment_dir / "summary.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nWrote experiment summary: {out_path}")


def _load_matplotlib():
    try:
        import matplotlib.pyplot as plt
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "matplotlib is required to generate plots. Install it (e.g. `pip install matplotlib`) "
            "or rerun with --skip-plot."
        ) from exc
    return plt


def generate_overall_plot(experiment_dir: pathlib.Path, records: list[dict]) -> pathlib.Path:
    plt = _load_matplotlib()

    by_policy = defaultdict(list)
    for record in records:
        by_policy[record["policy"]].append(record)

    plt.figure(figsize=(8, 5))
    for policy, items in by_policy.items():
        items_sorted = sorted(items, key=lambda r: r["rate"])
        rates = [r["rate"] for r in items_sorted]
        p99s = [r["overall_latency_p99_avg_ms"] for r in items_sorted]
        stddevs = [r.get("overall_latency_p99_stddev_ms", 0.0) for r in items_sorted]
        plt.errorbar(
            rates,
            p99s,
            yerr=stddevs,
            marker="o",
            capsize=4,
            label=policy,
        )
    plt.ylim(0, 50)

    plt.xlabel("Send rate (req/s)")
    plt.ylabel("Overall latency p99 (ms)")
    plt.title("Overall p99 latency vs. send rate")
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()

    plot_path = experiment_dir / "overall_p99_vs_rate.png"
    plt.savefig(plot_path, dpi=200)
    plt.close()
    print(f"Wrote plot: {plot_path}")
    return plot_path


def generate_get_scan_plot(experiment_dir: pathlib.Path, records: list[dict]) -> pathlib.Path:
    plt = _load_matplotlib()

    by_policy = defaultdict(list)
    for record in records:
        by_policy[record["policy"]].append(record)

    plt.figure(figsize=(8, 5))
    for policy, items in by_policy.items():
        items_sorted = sorted(items, key=lambda r: r["rate"])
        rates = [r["rate"] for r in items_sorted]
        get_p99s = [r["get_latency_p99_avg_ms"] for r in items_sorted]
        scan_p99s = [r["scan_latency_p99_avg_ms"] for r in items_sorted]
        plt.plot(rates, get_p99s, marker="o", label=f"{policy} GET p99")
        plt.plot(rates, scan_p99s, marker="s", label=f"{policy} SCAN p99")

    plt.xlabel("Send rate (req/s)")
    plt.ylabel("Latency p99 (ms)")
    plt.title("GET vs. SCAN p99 latency vs. send rate")
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()

    plot_path = experiment_dir / "get_scan_p99_vs_rate.png"
    plt.savefig(plot_path, dpi=200)
    plt.close()
    print(f"Wrote plot: {plot_path}")
    return plot_path


def generate_plots(experiment_dir: pathlib.Path, records: list[dict]) -> dict[str, str]:
    plots: dict[str, str] = {}
    plots["overall_p99_vs_rate"] = generate_overall_plot(experiment_dir, records).name
    plots["get_scan_p99_vs_rate"] = generate_get_scan_plot(experiment_dir, records).name
    return plots


def load_manifest_runs(manifest_path: pathlib.Path, runs_root: pathlib.Path) -> tuple[list[dict], dict]:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    jobs = data.get("jobs", [])
    runs: list[dict] = []

    for job in jobs:
        if job.get("status") not in {"ok"}:
            continue
        run_id = job.get("run_id")
        policy = job.get("policy")
        rate = job.get("rate")
        if run_id is None or policy is None or rate is None:
            continue
        run_dir = runs_root / run_id
        if not run_dir.exists():
            raise FileNotFoundError(f"Run directory {run_dir} (from manifest) not found")
        runs.append(
            {
                "run_dir": run_dir,
                "policy": str(policy),
                "rate": int(rate),
            }
        )
    if not runs:
        raise SystemExit(f"No completed runs in manifest {manifest_path}")
    return runs, data


def main() -> None:
    args = parse_args()
    experiment_root = pathlib.Path(args.output_dir).resolve()
    experiment_id = dt.datetime.now().strftime("exp-%Y%m%d-%H%M%S")
    experiment_dir = experiment_root / experiment_id

    records: list[dict] = []

    if args.manifest:
        manifest_path = pathlib.Path(args.manifest).resolve()
        runs_root = pathlib.Path(args.runs_root).resolve()
        run_infos, manifest_meta = load_manifest_runs(manifest_path, runs_root)

        if args.policies:
            selected = {p.strip() for p in args.policies.split(",") if p.strip()}
            run_infos = [info for info in run_infos if info["policy"] in selected]
        if args.rates:
            try:
                rate_filter = {int(val.strip()) for val in args.rates.split(",") if val.strip()}
            except ValueError as exc:
                raise SystemExit(f"Failed to parse --rates: {exc}") from exc
            run_infos = [info for info in run_infos if info["rate"] in rate_filter]

        if not run_infos:
            sys.exit("No runs remain after applying filters.")

        for info in run_infos:
            run_dir = info["run_dir"]
            summary = load_summary(run_dir)
            overall_avg, overall_stddev, overall_iterations = extract_metric(summary, "overall_latency_p99")
            get_avg, get_stddev, get_iterations = extract_metric(summary, "get_latency_p99")
            scan_avg, scan_stddev, scan_iterations = extract_metric(summary, "scan_latency_p99")

            record = {
                "policy": info["policy"],
                "rate": info["rate"],
                "overall_latency_p99_avg_ms": overall_avg,
                "overall_latency_p99_stddev_ms": overall_stddev,
                "overall_latency_p99_iterations_ms": overall_iterations,
                "get_latency_p99_avg_ms": get_avg,
                "get_latency_p99_stddev_ms": get_stddev,
                "get_latency_p99_iterations_ms": get_iterations,
                "scan_latency_p99_avg_ms": scan_avg,
                "scan_latency_p99_stddev_ms": scan_stddev,
                "scan_latency_p99_iterations_ms": scan_iterations,
                "run_dir": str(run_dir.resolve()),
            }
            records.append(record)

        policies = sorted({rec["policy"] for rec in records})
        rates = sorted({rec["rate"] for rec in records})
        metadata = {
            "experiment_id": experiment_id,
            "created_at": dt.datetime.now().isoformat(),
            "policies": policies,
            "rates": rates,
            "source_manifest": str(manifest_path),
            "runs_root": str(runs_root),
            "max_parallel": manifest_meta.get("max_parallel"),
            "threads": manifest_meta.get("threads"),
            "iterations_per_run": manifest_meta.get("iterations"),
            "duration": manifest_meta.get("duration"),
        }
    else:
        ensure_run_sh()
        if args.policies:
            policies = [p.strip() for p in args.policies.split(",") if p.strip()]
        else:
            policies = list(DEFAULT_POLICIES)
        if not policies:
            sys.exit("No policies specified.")
        try:
            if args.rates:
                rates = [int(val.strip()) for val in args.rates.split(",") if val.strip()]
            else:
                rates = list(RATE_VALUES)
        except ValueError as exc:
            raise SystemExit(f"Failed to parse --rates: {exc}") from exc
        if not rates:
            sys.exit("No rates specified.")

        for policy in policies:
            for rate in rates:
                run_dir = invoke_run_sh(policy, rate, args.threads, args.iterations, args.duration)
                summary = load_summary(run_dir)
                overall_avg, overall_stddev, overall_iterations = extract_metric(summary, "overall_latency_p99")
                get_avg, get_stddev, get_iterations = extract_metric(summary, "get_latency_p99")
                scan_avg, scan_stddev, scan_iterations = extract_metric(summary, "scan_latency_p99")

                record = {
                    "policy": policy,
                    "rate": rate,
                    "overall_latency_p99_avg_ms": overall_avg,
                    "overall_latency_p99_stddev_ms": overall_stddev,
                    "overall_latency_p99_iterations_ms": overall_iterations,
                    "get_latency_p99_avg_ms": get_avg,
                    "get_latency_p99_stddev_ms": get_stddev,
                    "get_latency_p99_iterations_ms": get_iterations,
                    "scan_latency_p99_avg_ms": scan_avg,
                    "scan_latency_p99_stddev_ms": scan_stddev,
                    "scan_latency_p99_iterations_ms": scan_iterations,
                    "run_dir": str(run_dir),
                }
                records.append(record)

        metadata = {
            "experiment_id": experiment_id,
            "threads": args.threads,
            "iterations_per_run": args.iterations,
            "policies": policies,
            "rates": rates,
            "duration": args.duration,
            "created_at": dt.datetime.now().isoformat(),
        }

    write_experiment_summary(experiment_dir, metadata, records)

    if not args.skip_plot:
        plots = generate_plots(experiment_dir, records)
        metadata["plots"] = plots
        # Update summary with plot location
        write_experiment_summary(experiment_dir, metadata, records)
    else:
        print("Skipping plot generation (--skip-plot).")


if __name__ == "__main__":
    main()
