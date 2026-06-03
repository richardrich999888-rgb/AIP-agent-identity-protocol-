#!/usr/bin/env python3
"""AEGIS chaos/stress suite.

The default dry-run mode is intentionally safe for macOS and GitHub runners. It
executes the deterministic Rust stress harness and records live kernel checks as
skipped local-scope items. Use --live on a privileged Linux host with AEGIS XDP
loaded to inspect bpftool maps during stress-ng resource pressure.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
AEGIS_ROOT = SCRIPT_DIR.parent
REPO_ROOT = AEGIS_ROOT.parent
DEFAULT_OUTPUT = REPO_ROOT / "pilot-results" / "chaos_stress_report.json"
MAP_NAMES = ("AQ_BLOCKLIST", "AQ_SESSIONS", "AQ_EVENTS", "AQ_COUNTERS")


def tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_command(args: list[str], cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    started_at = time.perf_counter()
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        return {
            "status": "FAIL_MISSING_TOOL",
            "command": args,
            "error": str(exc),
            "duration_ms": int((time.perf_counter() - started_at) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "FAIL_TIMEOUT",
            "command": args,
            "stdout_tail": tail(exc.stdout or ""),
            "stderr_tail": tail(exc.stderr or ""),
            "duration_ms": timeout_seconds * 1000,
        }

    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "command": args,
        "returncode": completed.returncode,
        "stdout_tail": tail(completed.stdout),
        "stderr_tail": tail(completed.stderr),
        "duration_ms": int((time.perf_counter() - started_at) * 1000),
    }


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run_rust_stress_harness(skip: bool, timeout_seconds: int) -> dict[str, Any]:
    if skip:
        return {
            "status": "SKIP_LOCAL_SCOPE",
            "reason": "Rust stress harness execution skipped by caller.",
        }

    return run_command(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(AEGIS_ROOT / "Cargo.toml"),
            "--package",
            "aegis-quantum-stress-tests",
        ],
        cwd=REPO_ROOT,
        timeout_seconds=timeout_seconds,
    )


def start_host_starvation(live: bool, duration: str) -> tuple[dict[str, Any], subprocess.Popen[str] | None]:
    if not live:
        return (
            {
                "status": "SKIP_LOCAL_SCOPE",
                "reason": "stress-ng host starvation is enabled only with --live.",
            },
            None,
        )

    if not is_root():
        return (
            {
                "status": "FAIL_PRIVILEGE",
                "reason": "--live requires root privileges for kernel-map telemetry.",
            },
            None,
        )

    stress_ng = shutil.which("stress-ng")
    if not stress_ng:
        return (
            {
                "status": "SKIP_MISSING_TOOL",
                "tool": "stress-ng",
                "reason": "Install stress-ng on the Linux gateway host for live chaos pressure.",
            },
            None,
        )

    args = [
        stress_ng,
        "--cpu",
        "4",
        "--vm",
        "2",
        "--vm-bytes",
        "1G",
        "--timeout",
        duration,
        "--quiet",
    ]
    started_at = time.perf_counter()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return (
        {
            "status": "RUNNING",
            "command": args,
            "started_epoch_ns": time.time_ns(),
            "startup_duration_ms": int((time.perf_counter() - started_at) * 1000),
        },
        process,
    )


def finish_host_starvation(
    initial_result: dict[str, Any],
    process: subprocess.Popen[str] | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    if process is None:
        return initial_result

    started_at = time.perf_counter()
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {
            **initial_result,
            "status": "FAIL_TIMEOUT",
            "stdout_tail": tail(stdout or ""),
            "stderr_tail": tail(stderr or ""),
            "duration_ms": timeout_seconds * 1000,
        }

    return {
        **initial_result,
        "status": "PASS" if process.returncode == 0 else "FAIL",
        "returncode": process.returncode,
        "stdout_tail": tail(stdout or ""),
        "stderr_tail": tail(stderr or ""),
        "duration_ms": int((time.perf_counter() - started_at) * 1000),
    }


def monitor_ebpf_maps(live: bool) -> dict[str, Any]:
    if not live:
        return {
            "status": "SKIP_LOCAL_SCOPE",
            "reason": "bpftool map inspection requires --live on the Linux gateway host.",
            "maps": list(MAP_NAMES),
        }

    bpftool = shutil.which("bpftool")
    if not bpftool:
        return {
            "status": "SKIP_MISSING_TOOL",
            "tool": "bpftool",
            "reason": "Install bpftool on the Linux gateway host for live map telemetry.",
        }

    map_results = {}
    failed = False
    for map_name in MAP_NAMES:
        result = run_command(
            [bpftool, "map", "show", "name", map_name],
            cwd=AEGIS_ROOT,
            timeout_seconds=10,
        )
        map_results[map_name] = result
        if result["status"] != "PASS":
            failed = True

    return {
        "status": "FAIL" if failed else "PASS",
        "maps": map_results,
    }


def summarize(results: dict[str, dict[str, Any]], live: bool) -> str:
    for result in results.values():
        if str(result.get("status", "")).startswith("FAIL"):
            return "FAIL"
    if live:
        for result in results.values():
            if str(result.get("status", "")).startswith("SKIP"):
                return "INCOMPLETE"
    return "PASS" if live else "PASS_LOCAL_SCOPE"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    live = bool(args.live)
    started_epoch_ns = time.time_ns()
    results: dict[str, dict[str, Any]] = {}

    results["rust_stress_harness"] = run_rust_stress_harness(
        skip=args.skip_rust_stress,
        timeout_seconds=args.rust_timeout_seconds,
    )
    stress_initial, stress_process = start_host_starvation(live=live, duration=args.duration)
    results["ebpf_map_telemetry"] = monitor_ebpf_maps(live=live)
    results["host_starvation"] = finish_host_starvation(
        initial_result=stress_initial,
        process=stress_process,
        timeout_seconds=args.live_timeout_seconds,
    )

    return {
        "metadata": {
            "suite": "aegis-chaos-stress",
            "mode": "live" if live else "dry_run",
            "scope": "bare_metal_live" if live else "local_dry_run",
            "started_epoch_ns": started_epoch_ns,
            "completed_epoch_ns": time.time_ns(),
            "aegis_root": str(AEGIS_ROOT),
        },
        "results": results,
        "overall_status": summarize(results, live=live),
        "claim_boundary": (
            "Dry-run proves deterministic stress harness execution only; live "
            "kernel and line-rate claims require --live on a privileged Linux host."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run AEGIS chaos and stress validation.")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run live Linux checks with stress-ng and bpftool. Requires root.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicitly select safe local dry-run mode. This is the default.",
    )
    parser.add_argument(
        "--skip-rust-stress",
        action="store_true",
        help="Skip cargo test execution and only write live/scope telemetry.",
    )
    parser.add_argument("--duration", default="10s", help="stress-ng duration for --live mode.")
    parser.add_argument(
        "--rust-timeout-seconds",
        type=int,
        default=180,
        help="Timeout for cargo stress harness tests.",
    )
    parser.add_argument(
        "--live-timeout-seconds",
        type=int,
        default=30,
        help="Timeout for live stress-ng completion.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to write chaos_stress_report.json.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.live and args.dry_run:
        print("Choose either --live or --dry-run, not both.", file=sys.stderr)
        return 2

    report = build_report(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"AEGIS chaos stress report written: {args.output}")
    print(f"overall_status={report['overall_status']}")
    return 0 if report["overall_status"] in {"PASS", "PASS_LOCAL_SCOPE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
