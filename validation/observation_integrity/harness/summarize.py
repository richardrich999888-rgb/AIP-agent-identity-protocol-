#!/usr/bin/env python3
"""Print one run's phase counts as a table. Reads result.json, computes nothing."""
import json
import pathlib
import sys

r = json.loads((pathlib.Path(sys.argv[1]) / "result.json").read_text())
print(f"  arm = {r['arm']}   run = {r['metadata']['run_id']}")
print("  phase   sniffdog_exec  sniffdog_fork   audit(truth)   a3s")
for p in ("P1", "P2", "P3"):
    print(f"  {p:6s}  {r['sniffer_dog']['exec_by_phase'][p]:13d}"
          f"  {r['sniffer_dog']['fork_by_phase'][p]:13d}"
          f"   {r['audit_ground_truth']['by_phase'][p]:12d}"
          f"   {r['a3s']['by_phase'][p]:3d}")
print(f"  sniffer dog reported lost: {r['sniffer_dog']['lost_total']}")
print(f"  VERDICT: {r['verdict']}")
print(f"  PER-TRACEPOINT: {r['per_tracepoint_isolation']}")
