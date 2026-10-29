#!/usr/bin/env python3
"""Deterministic exec workload with a harness-recorded ground truth.

Launches K executions of K *uniquely named* copies of /bin/true, CONC at a
time, and records for each launch: index, path, pid (from Popen), realtime
launch timestamp, exit status. Unique paths make every exec individually
matchable by filename in kernel evidence; pids make it matchable by pid.

This is the measurement harness's record of what it caused, not an agent's
self-report: it is the experimenter's control, written before any observer
output is read.

Usage: workload.py <workdir> <K> <CONC> <out.json>
"""
import json
import os
import shutil
import subprocess
import sys
import time

workdir, k, conc, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
os.makedirs(workdir, exist_ok=True)
paths = []
for i in range(k):
    p = os.path.join(workdir, f"vgt_{i:05d}")
    shutil.copy2("/bin/true", p)
    paths.append(p)

records = []
t0 = time.time_ns()
i = 0
while i < k:
    batch = []
    for p in paths[i:i + conc]:
        launch = time.time_ns()
        pr = subprocess.Popen([p])
        batch.append((p, pr, launch))
    for p, pr, launch in batch:
        rc = pr.wait()
        records.append({"path": p, "pid": pr.pid, "launch_rt_ns": launch, "exit": rc})
    i += conc
t1 = time.time_ns()
json.dump({"k": k, "conc": conc, "start_rt_ns": t0, "end_rt_ns": t1,
           "wall_ms": (t1 - t0) / 1e6, "execs": records}, open(out, "w"))
print(f"WORKLOAD k={k} conc={conc} wall_ms={(t1 - t0) / 1e6:.1f}")
