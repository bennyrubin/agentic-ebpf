#!/usr/bin/env python3
"""
Quick helper script to exercise openevolve_eval.evaluate() manually.
"""

from __future__ import annotations

import json
import pprint
import sys
from pathlib import Path

# Ensure the OpenEvolve package is importable when running from this project.
repo_root = Path(__file__).resolve().parents[2]
openevolve_path = repo_root / "openevolve"
if openevolve_path.exists():
    sys.path.insert(0, str(openevolve_path))
else:
    print(f"Warning: OpenEvolve package not found at {openevolve_path}")

import openevolve_eval


def main() -> None:
    result = openevolve_eval.evaluate("unused")

    print("=== Metrics ===")
    pprint.pp(result.metrics)

    print("\n=== Artifacts (keys) ===")
    artifact_keys = sorted(result.artifacts.keys())
    pprint.pp(artifact_keys)

    # Optionally dump the entire artifacts dict in JSON for easy inspection.
    output = {
        "metrics": result.metrics,
        "artifacts": {k: v[:500] + ("..." if len(v) > 500 else "") for k, v in result.artifacts.items()},
    }
    print("\n=== Serialized (truncated artifacts) ===")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
