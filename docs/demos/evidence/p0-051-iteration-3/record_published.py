#!/usr/bin/env python3
"""Record the scoped lifecycle acceptance on a clean checkout, without downloads."""
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import time

ROOT = Path(__file__).resolve().parent
out = ROOT / "published"
out.mkdir(exist_ok=False)
git = lambda *a: subprocess.check_output(["git", *a]).decode().strip()
metadata = {"source": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "dirty": git("status", "--porcelain"), "platform": platform.platform(),
            "logical_cpus": os.cpu_count(), "meminfo": Path("/proc/meminfo").read_text(),
            "network_before": Path("/proc/net/dev").read_text(), "rehearsal_credit": 0,
            "limitation": "Synthetic lifecycle component; no live expert auth, model, sensor, packet capture or clean-machine install."}
assert not metadata["dirty"]
env = {**os.environ, "SYNTRIASS_LIFECYCLE_EVIDENCE": str(out / "originals")}
command = ["cargo", "test", "--locked", "--offline", "-p", "syntriass-runtime", "--test", "lifecycle_isolation"]
t = time.monotonic()
c0 = resource.getrusage(resource.RUSAGE_CHILDREN)
with (out / "command.log").open("wb") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
c1 = resource.getrusage(resource.RUSAGE_CHILDREN)
metadata.update(command=command, exit_status=result.returncode, wall_seconds=time.monotonic()-t,
                child_cpu_seconds=c1.ru_utime+c1.ru_stime-c0.ru_utime-c0.ru_stime,
                child_peak_rss_kib=c1.ru_maxrss, network_after=Path("/proc/net/dev").read_text(),
                binary_sha256=hashlib.sha256(Path("target/debug/syntriass").read_bytes()).hexdigest())
(out / "metadata.json").write_text(json.dumps(metadata, indent=2)+"\n")
assert result.returncode == 0
pins = {p.parent.name: json.loads(p.read_text()) for p in (out/"originals").glob("*/public.json")}
assert len(pins) == 11 and not any(x["test_panicked"] for x in pins.values())
(out/"synthetic-trust-pins.json").write_text(json.dumps(pins,indent=2)+"\n")
print(json.dumps({k:metadata[k] for k in ["source","exit_status","wall_seconds","binary_sha256"]}))
