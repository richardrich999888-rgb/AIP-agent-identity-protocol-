#!/usr/bin/env python3
"""One entry point for every demo (W7.2).

  launch.py check                     readiness of every mode, with the reason
  launch.py run MODE [--out DIR]      run one mode; exit 0 pass, 1 fail, 3 NOT READY
  launch.py rehearse MODE N [--out DIR]
                                      N consecutive runs; appends one row to
                                      docs/demos/REHEARSAL_LOG.md from the results

Modes:
  security         Catch the lying agent (demos/lying-agent/run.sh)
  pq               Post-quantum in one switch, proof of concept (OVERLAY demos/pq-switch/run.sh)
  quantum          Quantum X-ray (OVERLAY demos/quantum-xray/run.sh)
  customer-<sector>, investor-3min
                   NOT READY until W1.4 (Pull the plug on real local models)
  teach            NOT READY until the teaching-demo loop reports ready; this
                   launcher will then call that loop's own script, never a copy

A mode that cannot run says NOT READY and why; it is never faked, and no step
is replayed. Each run writes a result file (demos/common/harness.py) with both
repositories' commits, the hardware and the run's own output folder.
OVERLAY is found at $SYNTRIASS_OVERLAY, else ../overlay beside this repository.
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

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE / "common"))
import harness  # noqa: E402

LOG = REPO / "docs/demos/REHEARSAL_LOG.md"
QUIET = os.environ.get("LAUNCH_QUIET") == "1"  # rehearsals: keep the screen to one line per run
NOT_READY = 3


def overlay() -> Path:
    return Path(os.environ.get("SYNTRIASS_OVERLAY", REPO.parent / "overlay")).resolve()


def _root() -> str | None:
    return None if os.geteuid() == 0 else "run as root"


def _docker() -> str | None:
    if not shutil.which("docker"):
        return "docker is not installed"
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return "docker daemon not running"
    return None


def _files(base: Path, *rel: str) -> str | None:
    missing = [r for r in rel if not (base / r).exists()]
    return f"missing in {base}: {', '.join(missing)}" if missing else None


def _auditd() -> str | None:
    if not shutil.which("auditctl"):
        return "auditd not installed (independent cross-check)"
    s = subprocess.run(["auditctl", "-s"], capture_output=True, text=True).stdout
    return None if "enabled 1" in s else "auditd not running: auditd && auditctl -e 1"


def _first(*checks) -> str | None:
    for c in checks:
        r = c()
        if r:
            return r
    return None


MODES = {
    "security": {
        "title": "Catch the lying agent",
        "ready": lambda: _first(_root, lambda: _files(REPO, "target/release/aip-probe", "target/release/aip-collector",
                                                     "target/release/aip-observe-verify"), _auditd),
        "cmd": lambda out: ["bash", str(HERE / "lying-agent/run.sh"), str(out), "--with-control"],
        "repos": lambda: [],
    },
    "pq": {
        "title": "Post-quantum in one switch (proof of concept)",
        "ready": lambda: _first(_root, _docker, lambda: _files(overlay(), "demos/pq-switch/run.sh",
                                                              "target/release/libsyntriass_overlay.so",
                                                              "target/release/syntriass-identity")),
        "cmd": lambda out: ["bash", str(overlay() / "demos/pq-switch/run.sh"), str(out), "20"],
        "repos": lambda: [overlay()],
    },
    "quantum": {
        "title": "Quantum X-ray",
        "ready": lambda: _first(_root, _docker, lambda: _files(overlay(), "demos/quantum-xray/run.sh",
                                                              "target/release/syntriass-cbom")),
        "cmd": lambda out: ["bash", str(overlay() / "demos/quantum-xray/run.sh"), str(out)],
        "repos": lambda: [overlay()],
    },
    "investor-3min": {
        "title": "Investor, three minutes",
        "ready": lambda: "needs W1.4: Pull the plug on real local models (models not staged; PR #14 not merged)",
    },
    "teach": {
        "title": "The AI asks the teacher",
        "ready": lambda: ("not ready: the teaching-demo loop has not reported ready. When it does, this mode "
                          "will call that loop's own script."),
    },
}


def mode_spec(name: str) -> dict | None:
    if name in MODES:
        return MODES[name]
    if name.startswith("customer-") and len(name) > len("customer-"):
        return {"title": f"Customer ({name[len('customer-'):]})",
                "ready": lambda: ("needs W1.4: Pull the plug on real local models; and the owner has not yet "
                                  "defined what this sector's script shows")}
    return None


def check() -> list[dict]:
    rows = []
    for name in [*MODES, "customer-<sector>"]:
        spec = mode_spec(name if name != "customer-<sector>" else "customer-any")
        why = spec["ready"]()
        rows.append({"mode": name, "ready": why is None, "reason": why})
    return rows


def run(name: str, out: Path) -> tuple[int, Path | None]:
    spec = mode_spec(name)
    if spec is None:
        print(f"unknown mode {name!r}; try: launch.py check", file=sys.stderr)
        return 2, None
    why = spec["ready"]()
    if why:
        print(f"NOT READY: {name}: {why}")
        return NOT_READY, None
    out.mkdir(parents=True, exist_ok=True)
    inner = out / "run"
    started, t0 = harness.now_utc(), time.monotonic()
    print(harness.label(harness.LIVE, spec["title"])["banner"])
    # Stream the demo's output to the screen as it happens (a presenter, and a
    # terminal recording, see it unfold) and keep the same bytes in console.txt.
    with open(out / "console.txt", "wb") as console:
        proc = subprocess.Popen(spec["cmd"](inner), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for chunk in iter(lambda: proc.stdout.read1(4096), b""):
            console.write(chunk)
            if not QUIET:
                sys.stdout.buffer.write(chunk)
                sys.stdout.flush()
        rc = proc.wait()
    wall = round(time.monotonic() - t0, 1)
    step = harness.label(harness.LIVE, spec["title"])
    path = harness.write_result(out, f"launch-{name}", [step],
                                {"mode": name, "exit_code": rc, "passed": rc == 0, "wall_s": wall,
                                 "output_dir": str(inner), "console": str(out / "console.txt")},
                                started, spec["repos"]())
    print(f"{'PASS' if rc == 0 else 'FAIL'}  {name}  {wall} s  result: {path}")
    return (0 if rc == 0 else 1), path


def rehearse(name: str, n: int, out: Path) -> int:
    global QUIET
    QUIET = True
    results = []
    for i in range(1, n + 1):
        rc, path = run(name, out / f"{i:02d}")
        if rc in (2, NOT_READY):
            return rc
        results.append(json.loads(path.read_text()))
        if rc != 0:
            break
    passes = 0
    for r in results:
        if not r["measurements"]["passed"]:
            break
        passes += 1
    walls = sorted(r["measurements"]["wall_s"] for r in results)
    prov = "; ".join(f"{p['repo']} {(p['commit'] or '?')[:7]}{' DIRTY' if p['dirty'] else ''}"
                     for p in results[0]["provenance"])
    verdict = "PASS" if passes == n else f"FAIL at run {passes + 1}"
    where = os.path.relpath(out, REPO) if Path(out).resolve().is_relative_to(REPO) else str(out)
    row = (f"| {results[0]['started_utc'][:16]}Z | {name} | {passes}/{n} consecutive | {verdict} | "
           f"{walls[len(walls) // 2]} s median, {walls[-1]} s max | {prov} | "
           f"{results[0]['hardware']['label']} | `{where}` |\n")
    if not LOG.exists():
        LOG.write_text("# Rehearsal log (W7.3)\n\nWritten by `demos/launch.py rehearse`, one row per "
                       "rehearsal, from the result files. A mode passes only with N consecutive passes.\n\n"
                       "| Started (UTC) | Mode | Passes | Verdict | Wall time | Commits | Hardware | Results |\n"
                       "|---|---|---|---|---|---|---|---|\n")
    with open(LOG, "a") as f:
        f.write(row)
    print(row, end="")
    return 0 if passes == n else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    r = sub.add_parser("run")
    r.add_argument("mode")
    r.add_argument("--out", type=Path)
    h = sub.add_parser("rehearse")
    h.add_argument("mode")
    h.add_argument("n", type=int)
    h.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    if a.cmd == "check":
        for row in check():
            print(f"{'READY    ' if row['ready'] else 'NOT READY'}  {row['mode']:18} {row['reason'] or ''}")
        return 0
    out = a.out or HERE / "results" / f"{a.cmd}-{a.mode}-{stamp}"
    if a.cmd == "run":
        return run(a.mode, out)[0]
    return rehearse(a.mode, a.n, out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
