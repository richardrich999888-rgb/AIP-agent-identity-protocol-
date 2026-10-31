"""Cold, amortized and break-even cost of the learned capability vs baselines.

usage: economics.py RESULTS_DIR   (reads propose_*/cost.json, run1/report.json,
                                   baselines_q8/summary.json and *.jsonl)

Compute unit: CPU-seconds of the model server and runtime, measured from
/proc. Acquisition cost counts EVERY proposer run actually made (both prompt
variants, all rounds), validation, and the human inputs as counts (human time
was not measured). Per-task cost is measured on the 32 decision items of
test_unseen (false-activation probes are excluded from per-task cost because
they are not tasks; they are reported separately).

Break-even N solves  acq + N * c_cap = N * c_base  ->  N = acq / (c_base - c_cap),
reported only where the capability is at least as accurate as the baseline.
"""
from __future__ import annotations

import glob
import json
import math
import os
import sys

TICK_S = 0.01  # /proc CPU accounting resolution (CLK_TCK = 100)


def main() -> None:
    R = sys.argv[1]
    props = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(R, "propose_*/cost.json")))]
    acq_cpu = sum(p["llama_cpu_s"] for p in props)
    acq_wall = sum(p["total_wall_s"] for p in props)
    rep = json.load(open(os.path.join(R, "run1/report.json")))
    val_us = rep["lifecycle"]["validation"]["wall_micros"]
    dec = [i for i in rep["phaseD_capability"]["items"] if i["label"] != "NOT_APPLICABLE"]
    cap_items = [i for i in dec if "Capability" in json.dumps(i["strategy"])]
    cap_cpu = sum(i["cpu_s"] for i in dec)
    # Capability executions are below /proc resolution; bound them by one tick each.
    c_cap = max(cap_cpu, TICK_S * len(dec)) / len(dec)
    cap_acc = sum(i["ok"] for i in dec) / len(dec)
    base = {}
    for k in ("B1", "B2", "B3"):
        rows = [json.loads(l) for l in open(os.path.join(R, f"baselines_q8/{k}.jsonl"))]
        d = [r for r in rows if r["label"] != "NOT_APPLICABLE"]
        base[k] = {"per_task_cpu_s": round(sum(r["cpu_s"] for r in d) / len(d), 3),
                   "accuracy": round(sum(r["ok"] for r in d) / len(d), 3),
                   "cpu_per_correct_s": round(sum(r["cpu_s"] for r in d) / max(1, sum(r["ok"] for r in d)), 2)}
    out = {
        "acquisition": {"proposer_runs": len(props), "proposer_rounds": sum(len(p["rounds"]) for p in props),
                        "model_cpu_s": round(acq_cpu, 1), "wall_s": round(acq_wall, 1),
                        "validation_wall_us": val_us,
                        "human_inputs": {"demonstrations": 6, "engineer_corrections": 7, "signed_expert_cases": 14,
                                         "approvals": 1, "human_time": "not measured"}},
        "capability": {"decision_items": len(dec), "via_capability": len(cap_items), "accuracy": round(cap_acc, 3),
                       "per_task_cpu_s_upper_bound": round(c_cap, 4),
                       "median_wall_ms": sorted(i["wall_ms"] for i in cap_items)[len(cap_items) // 2]},
        "baselines": base,
        "break_even_uses": {},
        "cost_per_correct_after_n_uses_cpu_s": {},
    }
    for k, b in base.items():
        if cap_acc >= b["accuracy"] and b["per_task_cpu_s"] > c_cap:
            out["break_even_uses"][k] = math.ceil(acq_cpu / (b["per_task_cpu_s"] - c_cap))
    for n in (1, 10, 32, 100, 1000):
        out["cost_per_correct_after_n_uses_cpu_s"][str(n)] = round((acq_cpu + n * c_cap) / (n * cap_acc), 3)
    json.dump(out, open(os.path.join(R, "economics.json"), "w"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
