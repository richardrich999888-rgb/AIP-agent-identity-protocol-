#!/usr/bin/env python3
"""Run one qualification command, retaining its unmodified output and provenance.

An expected exit is a command check, not a workload or enterprise verdict.
Only use public arguments; never pass credentials to this recorder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expect-exit", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    args.out.mkdir(parents=True, exist_ok=False)
    source = {}
    for path in ["aip-standalone/aip-core/src/execution_binding.rs", "aip-standalone/aip-observe/src/probe.rs", "Cargo.lock"]:
        source[path] = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    record = {"command": command, "cwd": str(ROOT), "start_unix": time.time(),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_sha256": source, "kernel": platform.release(),
              "uid": os.getuid(), "expected_exit": args.expect_exit, "timeout_seconds": args.timeout}
    with (args.out / "output.log").open("wb") as log:
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
            record["exit_code"] = result.returncode
        except subprocess.TimeoutExpired:
            record["exit_code"] = None
            record["error"] = "TIMEOUT"
        except OSError as error:
            record["exit_code"] = None
            record["error"] = str(error)
        record["elapsed_seconds"] = time.monotonic() - started
    record["status"] = "PASS" if record["exit_code"] == args.expect_exit else "FAIL"
    record["output_sha256"] = hashlib.sha256((args.out / "output.log").read_bytes()).hexdigest()
    (args.out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"command": command, "status": record["status"], "exit_code": record["exit_code"]}))
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
