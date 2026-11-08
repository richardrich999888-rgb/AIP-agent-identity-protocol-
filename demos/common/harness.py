#!/usr/bin/env python3
"""Shared harness for every SYNTRIASS demo (W0.2). Standard library only.

Four things every demo needs, and needs to be honest about:

* ``offline_status()`` / ``run_offline()`` — prove there is no network route.
  The check reads this network namespace's own ``/proc/net/route`` and
  ``/proc/net/dev`` (``/sys/class/net`` is not namespace-accurate unless sysfs
  is remounted). Offline means: no route at all, and no interface other than
  ``lo`` present. It does *not* probe a public address, because a sandbox
  whose direct egress is blocked would make such a probe "pass" while a route
  still exists.
* ``hardware_report()`` — what the numbers were measured on, read live from the
  machine, never typed in.
* ``write_result()`` — one JSON result file per run with UTC timestamps, the
  exact commit (and whether the tree was dirty), the hardware, and a label for
  every step.
* ``label()`` — every step is ``live`` or ``recorded``; a recorded step must
  name the file it replays, and the on-screen banner says so.

CLI:
  harness.py offline-check            exit 0 only when offline; JSON on stdout
  harness.py run-offline -- CMD ...   run CMD in a fresh user+net namespace
                                      (loopback only), refusing if not offline
  harness.py hardware                 JSON hardware report
  harness.py label live|recorded [--source PATH] TEXT
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LIVE, RECORDED = "live", "recorded"


# ── offline ─────────────────────────────────────────────────────────────────

def _routes(proc_net: Path) -> list[dict]:
    out = []
    for path, family in ((proc_net / "route", "ipv4"), (proc_net / "ipv6_route", "ipv6")):
        try:
            lines = path.read_text().splitlines()
        except FileNotFoundError:
            continue
        if family == "ipv4":
            lines = lines[1:]  # header
        for line in lines:
            f = line.split()
            if not f:
                continue
            iface = f[0] if family == "ipv4" else f[-1]
            if iface == "lo":
                continue
            out.append({"family": family, "iface": iface})
    return out


def _interfaces(proc_net: Path) -> dict[str, dict]:
    ifaces = {}
    for line in (proc_net / "dev").read_text().splitlines()[2:]:
        name, _, data = line.partition(":")
        f = data.split()
        ifaces[name.strip()] = {"rx_bytes": int(f[0]), "tx_bytes": int(f[8])}
    return ifaces


def offline_status(proc_net: Path = Path("/proc/self/net")) -> dict:
    """Offline iff no non-loopback route and no non-loopback interface."""
    routes = _routes(proc_net)
    ifaces = _interfaces(proc_net)
    non_lo = sorted(n for n in ifaces if n != "lo")
    return {
        "offline": not routes and not non_lo,
        "non_loopback_routes": routes,
        "non_loopback_interfaces": non_lo,
        "tx_bytes_non_loopback": sum(v["tx_bytes"] for n, v in ifaces.items() if n != "lo"),
    }


def _loopback_up() -> None:
    import fcntl
    import socket
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flags = struct.unpack("16sH14x", fcntl.ioctl(s, 0x8913, struct.pack("16sH14x", b"lo", 0)))[1]
    fcntl.ioctl(s, 0x8914, struct.pack("16sH14x", b"lo", flags | 0x41))  # IFF_UP|IFF_RUNNING


def run_offline(cmd: list[str]) -> int:
    """Re-exec inside a fresh user+net namespace, bring up loopback, verify
    offline, then exec ``cmd``. Fails closed."""
    if os.environ.get("DEMO_IN_NETNS") != "1":
        env = dict(os.environ, DEMO_IN_NETNS="1")
        return subprocess.call(["unshare", "--user", "--map-root-user", "--net", "--",
                                sys.executable, "-I", __file__, "run-offline", "--", *cmd], env=env)
    _loopback_up()
    status = offline_status()
    if not status["offline"]:
        print(json.dumps({"refused": "network route present", **status}), file=sys.stderr)
        return 3
    os.execvp(cmd[0], cmd)
    return 127  # not reached


# ── hardware ────────────────────────────────────────────────────────────────

def hardware_report() -> dict:
    cpu = "unknown"
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    mem_kb = next(int(l.split()[1]) for l in Path("/proc/meminfo").read_text().splitlines()
                  if l.startswith("MemTotal:"))
    gpus = sorted(p.name for p in Path("/dev").glob("nvidia[0-9]*"))
    gpus += sorted(p.name for p in Path("/dev/dri").glob("renderD*"))
    vcpu = os.cpu_count() or 0
    # Rounded DOWN to whole GiB: a label must never overstate the machine.
    mem_gb = mem_kb // (1024 * 1024)
    return {
        "cpu_model": cpu,
        "vcpu": vcpu,
        "mem_gb": mem_gb,
        "gpu": gpus or None,
        "kernel": platform.release(),
        "label": f"{vcpu} vCPU, {mem_gb} GB RAM, {'GPU: ' + ','.join(gpus) if gpus else 'no GPU'}",
    }


# ── provenance and results ──────────────────────────────────────────────────

def _git(repo: Path, *args: str) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


# Tracked files written by the demo tooling itself. A change to one of these is
# the tooling's output, not a change to the code being demonstrated.
OUTPUT_FILES = frozenset({"docs/demos/REHEARSAL_LOG.md"})


def provenance(repo: Path = REPO) -> dict:
    commit = _git(repo, "rev-parse", "HEAD")
    if commit is None:
        # Run from the offline demo kit (no .git): the kit's MANIFEST.json names
        # the commit it was built from (build_bundle.sh refuses dirty trees) and
        # kit/verify.sh checks every file against it. Working-tree state is not
        # knowable here, so "dirty" is None, not False.
        manifest = repo.parent / "MANIFEST.json"
        try:
            commit = json.loads(manifest.read_text())["commits"].get(repo.name)
        except (OSError, ValueError, KeyError):
            commit = None
        if commit:
            return {"repo": repo.name, "commit": commit, "dirty": None, "source": "kit MANIFEST.json"}
        return {"repo": repo.name, "commit": None, "dirty": None}
    # Tracked files that differ from HEAD, staged or not (untracked files are
    # not part of the commit and are not counted, as before).
    changed = (_git(repo, "diff", "--name-only", "HEAD") or "").splitlines()
    # Files the demos themselves append to (output, not code under test) do not
    # make a run dirty; they are still listed, so nothing is hidden.
    material = [f for f in changed if f not in OUTPUT_FILES]
    return {"repo": str(repo.name), "commit": commit, "dirty": bool(material), "changed_files": changed}


def label(kind: str, text: str, source: str | None = None) -> dict:
    """A step label. ``recorded`` must name an existing replayed file."""
    if kind not in (LIVE, RECORDED):
        raise ValueError(f"label must be {LIVE!r} or {RECORDED!r}, not {kind!r}")
    if kind == RECORDED:
        if not source:
            raise ValueError("a recorded step must name the file it replays")
        if not Path(source).exists():
            raise FileNotFoundError(f"recorded source does not exist: {source}")
    banner = f"[LIVE] {text}" if kind == LIVE else f"[RECORDED — replaying {source}] {text}"
    return {"kind": kind, "text": text, "source": source, "banner": banner}


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def write_result(out_dir: Path, demo: str, steps: list[dict], measurements: dict,
                 started_utc: str, extra_repos: list[Path] = ()) -> Path:
    """Write ``<out_dir>/<demo>-<UTC>.json``. Every step must carry a label."""
    for s in steps:
        if s.get("kind") not in (LIVE, RECORDED):
            raise ValueError(f"unlabelled step: {s}")
    record = {
        "schema": "syntriass.demo.result/v1",
        "demo": demo,
        "started_utc": started_utc,
        "finished_utc": now_utc(),
        "provenance": [provenance()] + [provenance(r) for r in extra_repos],
        "hardware": hardware_report(),
        "offline": offline_status(),
        "steps": steps,
        "measurements": measurements,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = record["finished_utc"].replace(":", "").replace("-", "")
    path = out_dir / f"{demo}-{stamp}.json"
    path.write_text(json.dumps(record, indent=2) + "\n")
    return path


# ── CLI ─────────────────────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "offline-check":
        s = offline_status()
        print(json.dumps(s))
        return 0 if s["offline"] else 1
    if cmd == "run-offline":
        if rest[:1] == ["--"]:
            rest = rest[1:]
        if not rest:
            print("run-offline needs a command", file=sys.stderr)
            return 2
        return run_offline(rest)
    if cmd == "hardware":
        print(json.dumps(hardware_report()))
        return 0
    if cmd == "label":
        kind, source, words = rest[0], None, rest[1:]
        if words[:1] == ["--source"]:
            source, words = words[1], words[2:]
        print(label(kind, " ".join(words), source)["banner"])
        return 0
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
