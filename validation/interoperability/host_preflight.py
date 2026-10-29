#!/usr/bin/env python3
"""Read-only host prerequisites; no sensor installation or runtime proof.

Run on the authorized isolated host before invoking existing observation labs.
No credential, signing material, environment dump or host identifier is emitted.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile


def process_visible(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        prefix, fields = raw.rsplit(")", 1)
        return (int(prefix.split("(", 1)[0]) == pid and int(fields.split()[19]) > 0
                and Path(f"/proc/{pid}/exe").is_file())
    except (OSError, ValueError, IndexError):
        return False


def inspect_host():
    checks = {"linux": platform.system() == "Linux"}
    checks["self_proc_binding_visible"] = process_visible(os.getpid())
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        checks["child_proc_binding_visible"] = process_visible(child.pid)
    finally:
        child.terminate()
        child.wait(timeout=5)
    try:
        cap = next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
                   if line.startswith("CapEff:"))
        cap = int(cap, 16)
        checks["bpf_perf_capabilities"] = bool(cap & (1 << 21) or
            (cap & (1 << 39) and cap & (1 << 38)))
    except (OSError, ValueError, StopIteration):
        checks["bpf_perf_capabilities"] = False
    checks["kernel_btf_readable"] = os.access("/sys/kernel/btf/vmlinux", os.R_OK)
    checks["exec_tracepoint_readable"] = any(os.access(path, os.R_OK) for path in
        ("/sys/kernel/tracing/events/sched/sched_process_exec/id",
         "/sys/kernel/debug/tracing/events/sched/sched_process_exec/id"))
    checks["unix_socket_available"] = False
    with tempfile.TemporaryDirectory(prefix="vip-") as directory:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(Path(directory) / "p.sock"))
                server.listen(1)
                checks["unix_socket_available"] = True
        except (OSError, AttributeError):
            pass
    return {"schema": "vanian.interop.host-prerequisites.v1",
        "status": "PREREQUISITES_PRESENT_RUNTIME_UNTESTED" if all(checks.values()) else "BLOCKED",
        "checks": checks, "missing": [name for name, value in checks.items() if not value],
        "scope": "Local Linux/SPIRE prerequisites only; no kernel event captured or evidence signed.",
        "not_assessed": ["institutional_authority", "independent_key_custody", "off_host_collector",
                         "revocation", "clock_synchronization", "sensor_coverage", "enterprise_admission"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true", help="Exit nonzero on missing prerequisites")
    args = parser.parse_args()
    report = inspect_host()
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as handle:
            handle.write(serialized)
    print(serialized, end="")
    return int(args.require_ready and report["status"] == "BLOCKED")


if __name__ == "__main__":
    raise SystemExit(main())
