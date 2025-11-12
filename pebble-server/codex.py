#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import sys
from typing import List, Optional

def which_or_die(name: str) -> str:
    path = shutil.which(name)
    if not path:
        sys.exit(f"Error: '{name}' not found on PATH.")
    return path

def build_cmd(prompt: str, passthrough: List[str]) -> List[str]:
    # Shape: codex exec [OPTIONS] "<prompt>"
    cmd = ["codex", "exec"]
    if passthrough:
        cmd += passthrough
    cmd.append(prompt)
    return cmd

def pretty_print(possibly_json: str) -> None:
    s = (possibly_json or "").strip()
    if not s:
        return
    try:
        obj = json.loads(s)
        # Common shapes: {"text": "..."} or {"choices":[{"text":"..."}]}
        if isinstance(obj, dict) and "text" in obj and isinstance(obj["text"], str):
            print(obj["text"])
        elif (
            isinstance(obj, dict)
            and "choices" in obj
            and isinstance(obj["choices"], list)
            and obj["choices"]
            and isinstance(obj["choices"][0], dict)
            and "text" in obj["choices"][0]
        ):
            print(obj["choices"][0]["text"])
        else:
            print(json.dumps(obj, indent=2))
    except json.JSONDecodeError:
        print(s)

def run_capture(cmd: List[str], timeout: int) -> int:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        sys.exit("Error: codex exec timed out. Increase --timeout or simplify the prompt.")
    out = (cp.stdout or "") + (cp.stderr or "")
    if not out.strip() and cp.returncode != 0:
        sys.exit(f"codex exec exited with code {cp.returncode} and no output.")
    pretty_print(out)
    return cp.returncode

def run_stream(cmd: List[str]) -> int:
    # Stream stdout/stderr as they arrive (useful when codex prints progress then results)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            print(line, end="")
    finally:
        proc.stdout.close()
    return proc.wait()

def main():
    parser = argparse.ArgumentParser(description="Call 'codex exec' non-interactively and print the response.")
    parser.add_argument("prompt", help="Prompt to send to Codex (positional).")
    parser.add_argument("--stream", action="store_true", help="Stream output as it arrives.")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout (seconds) for non-streaming mode.")
    parser.add_argument("--arg", dest="passthrough", action="append", default=[],
                        help="Pass an extra flag/arg to codex (repeatable). Example: --arg=--model --arg=gpt-4.1")
    args = parser.parse_args()

    which_or_die("codex")

    cmd = build_cmd(args.prompt, args.passthrough)

    rc = run_stream(cmd) if args.stream else run_capture(cmd, args.timeout)
    if rc != 0:
        sys.exit(rc)

if __name__ == "__main__":
    main()
