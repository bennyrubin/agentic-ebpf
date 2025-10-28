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
DEFAULT_POLICIES = ["default", "round_robin"]
RATE_VALUES = [35000, 40000, 45000, 50000, 55000, 60000, 65000, 70000, 80000]
RUN_DIR_RE = re.compile(r"Logs and results stored in (.+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run rate sweep experiments and plot overall p99 latency per policy."
    )
    parser.add_argument(
        "--policies",
        default=",".join(DEFAULT_POLICIES),
        help="Comma-separated list of policies to test (default: %(default)s)",
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
        default=",".join(str(v) for v in RATE_VALUES),
        help="Comma-separated list of send rates to sweep (default: %(default)s)",
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


def extract_p99(summary: dict) -> tuple[float, float, list[float]]:
    summary_block = summary.get("summary", {})
    overall_stats = summary_block.get("overall_latency_p99")
    if not overall_stats:
        raise KeyError("overall_latency_p99 missing from summary JSON")
    if "average" not in overall_stats:
        raise KeyError("overall_latency_p99.average missing from summary JSON")
    average = float(overall_stats["average"])
    stddev = float(overall_stats.get("stddev", 0.0))

    iteration_vals = []
    for entry in summary.get("iterations", []):
        value = entry.get("overall_latency_p99")
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


def generate_plot(experiment_dir: pathlib.Path, records: list[dict]) -> pathlib.Path:
    try:
        import matplotlib.pyplot as plt
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "matplotlib is required to generate plots. Install it (e.g. `pip install matplotlib`) "
            "or rerun with --skip-plot."
        ) from exc

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
    plt.yscale("log")

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


def main() -> None:
    args = parse_args()
    ensure_run_sh()

    policies = [p.strip() for p in args.policies.split(",") if p.strip()]
    if not policies:
        sys.exit("No policies specified.")
    try:
        rates = [int(val.strip()) for val in args.rates.split(",") if val.strip()]
    except ValueError as exc:
        raise SystemExit(f"Failed to parse --rates: {exc}") from exc
    if not rates:
        sys.exit("No rates specified.")

    experiment_root = pathlib.Path(args.output_dir).resolve()
    experiment_id = dt.datetime.now().strftime("exp-%Y%m%d-%H%M%S")
    experiment_dir = experiment_root / experiment_id

    records: list[dict] = []

    for policy in policies:
        for rate in rates:
            run_dir = invoke_run_sh(policy, rate, args.threads, args.iterations, args.duration)
            summary = load_summary(run_dir)
            avg_p99, stddev_p99, per_iteration = extract_p99(summary)

            record = {
                "policy": policy,
                "rate": rate,
                "overall_latency_p99_avg_ms": avg_p99,
                "overall_latency_p99_stddev_ms": stddev_p99,
                "overall_latency_p99_iterations_ms": per_iteration,
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
        plot_path = generate_plot(experiment_dir, records)
        metadata["plot"] = str(plot_path.name)
        # Update summary with plot location
        write_experiment_summary(experiment_dir, metadata, records)
    else:
        print("Skipping plot generation (--skip-plot).")


if __name__ == "__main__":
    main()
