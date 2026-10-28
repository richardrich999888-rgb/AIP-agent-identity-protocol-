#!/usr/bin/env python3
"""Install on the dedicated collector host; invoke over pinned-host-key SSH.

Uses an institution-provisioned systemd service, key and environment file.
Never creates keys, exports secrets, or accepts shell commands from the client.
The service and this config must be inaccessible to the workload's account.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PUBLIC_FILES = ("attested.archive.jsonl", "health.archive.jsonl")


def run(args):
    return subprocess.check_output(args, text=True, timeout=20).strip()


def main():
    config_path = Path(sys.argv[1])
    if os.geteuid() != 0 or config_path.stat().st_uid != 0 or config_path.stat().st_mode & 0o022:
        raise RuntimeError("collector helper requires root and a root-owned non-writable config")
    config = json.loads(config_path.read_text())
    unit = config["unit"]
    if not re.fullmatch(r"aip-collector-validation[-a-zA-Z0-9@.]*\.service", unit):
        raise RuntimeError("a dedicated aip-collector-validation service is required")
    state = Path(config["state_dir"])
    request = json.loads(sys.stdin.read(4096))
    action = request["action"]
    token = request["token"]
    if not re.fullmatch(r"sd-[a-f0-9]{32}", token):
        raise RuntimeError("invalid controller lease token")
    if action not in ("status", "start", "snapshot", "stop"):
        raise RuntimeError("unknown action")
    active = run(["systemctl", "show", "--property=ActiveState", "--value", unit])
    lease = config_path.with_suffix(".lease")
    if action == "start":
        if active != "inactive":
            raise RuntimeError("collector already active or failed; refusing to take it over")
        if any((state / name).exists() for name in PUBLIC_FILES):
            raise RuntimeError("use a fresh per-experiment state directory; never erase evidence")
        if run(["timedatectl", "show", "--property=NTPSynchronized", "--value"]) != "yes":
            raise RuntimeError("collector clock is not synchronized")
        # O_EXCL prevents concurrent controllers from sharing a collector.
        with lease.open("x") as handle:
            handle.write(token)
        subprocess.run(["systemctl", "start", unit], check=True, timeout=30)
    if action in ("snapshot", "stop") and lease.read_text() != token:
        raise RuntimeError("collector belongs to a different run")
    if action == "stop":
        subprocess.run(["systemctl", "stop", unit], check=True, timeout=30)
    active = run(["systemctl", "show", "--property=ActiveState", "--value", unit])
    response = {"machine_id": Path("/etc/machine-id").read_text().strip(),
                "state": active, "clock_synchronized": run([
                    "timedatectl", "show", "--property=NTPSynchronized", "--value"]) == "yes",
                "files": {}, "sha256": {}}
    if action in ("snapshot", "stop"):
        for name in PUBLIC_FILES:
            path = state / name
            if path.is_symlink():
                raise RuntimeError("symlink archive refused")
            with path.open("rb") as source:
                data = source.read(256 * 1024 * 1024 + 1)
            if len(data) > 256 * 1024 * 1024:
                raise RuntimeError("archive exceeds snapshot limit")
            if not data.endswith(b"\n"):
                # Retry live snapshots; never silently trim captured records.
                raise RuntimeError("archive append in progress or truncated; retry snapshot")
            response["files"][name] = base64.b64encode(data).decode()
            response["sha256"][name] = hashlib.sha256(data).hexdigest()
    if action == "stop":
        lease.unlink()
    print(json.dumps(response))


if __name__ == "__main__":
    main()
