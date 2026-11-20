#!/usr/bin/env python3
"""Recompute the learning-benchmark table from the recorded result files (W6.2).

Reads only files under research/capability-learning/ (owned by the
teaching-demo session; read, never written). Prints every figure with the
file it came from, so REPRODUCE.md quotes this output, not a hand-copied table.

  correct /40       items with ok == true
  decision /32      ok items among the 32 unseen test requests (test-*)
  false act.        as recorded by the run
  CPU-s per task    total CPU-s / 40 (baselines: summary.json; runtime: sum of items)
  paired delta      mean over the 40 items of ok(system) - ok(candidate),
                    with a paired bootstrap 95 % CI (10,000 resamples, seed 0).
                    The published CIs have no committed script; this is a
                    recomputation with a stated method, compared, not assumed equal.

usage: summarize.py [--root REPO] [--json]
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

R = "research/capability-learning/results"


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def boot_ci(diffs: list[int], n: int = 10_000, seed: int = 0) -> tuple[float, float]:
    rng = random.Random(seed)
    k = len(diffs)
    means = sorted(sum(diffs[rng.randrange(k)] for _ in range(k)) / k for _ in range(n))
    return means[int(0.025 * n)], means[int(0.975 * n) - 1]


def summarize(root: Path) -> dict:
    rep = json.loads((root / R / "run1/report.json").read_text())
    summ = json.loads((root / R / "baselines_q8/summary.json").read_text())
    systems: dict[str, dict] = {}
    for name in ("B1", "B2", "B3"):
        items = load_jsonl(root / R / f"baselines_q8/{name}.jsonl")
        systems[name] = {"items": items, "cpu_per_task": summ[name]["cpu_s_total"] / len(items),
                         "false_activation": summ[name]["false_activation"],
                         "source": f"{R}/baselines_q8/{name}.jsonl, summary.json"}
    for name, key in (("B4", "baseline4_no_capability"), ("candidate", "phaseD_capability")):
        items = rep[key]["items"]
        systems[name] = {"items": items, "cpu_per_task": sum(i["cpu_s"] for i in items) / len(items),
                         "false_activation": rep[key]["false_activation"],
                         "source": f"{R}/run1/report.json:{key}"}
    cand = {i["id"]: int(i["ok"]) for i in systems["candidate"]["items"]}
    out = {"model": summ["model"], "model_sha256": summ["model_sha256"], "systems": {}}
    for name, s in systems.items():
        ok = {i["id"]: int(i["ok"]) for i in s["items"]}
        if set(ok) != set(cand):
            raise SystemExit(f"{name}: item ids differ from the candidate's; cannot pair")
        row = {"n": len(ok), "correct": sum(ok.values()),
               "decision_correct_of_32": sum(v for k, v in ok.items() if k.startswith("test-")),
               "decision_n": sum(1 for k in ok if k.startswith("test-")),
               "false_activation": s["false_activation"],
               "cpu_s_per_task": round(s["cpu_per_task"], 2), "source": s["source"]}
        if name != "candidate":
            d = [ok[k] - cand[k] for k in sorted(ok)]
            lo, hi = boot_ci(d)
            row["paired_delta_vs_candidate"] = round(sum(d) / len(d), 3)
            row["bootstrap_95ci"] = [round(lo, 3), round(hi, 3)]
        out["systems"][name] = row
    lc = rep["lifecycle"]["validation"]
    out["lifecycle"] = {k: lc[k] for k in ("expert_cases", "expert_passed", "counterexamples",
                                            "counterexamples_passed", "suite_signature_ok", "suite_independent")}
    cap = systems["candidate"]["items"]
    out["candidate_model_calls_total"] = sum(i["model_calls"] for i in cap)
    out["candidate_items_with_zero_model_calls"] = sum(1 for i in cap if i["model_calls"] == 0)
    out["unauthorized"] = {"n": rep["unauthorized"]["n"], "capability_used": rep["unauthorized"]["capability_used"]}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    s = summarize(a.root)
    if a.json:
        print(json.dumps(s, indent=2))
        return 0
    print(f"model: {s['model']} sha256 {s['model_sha256'][:16]}…")
    print(f"{'system':10} {'correct/40':>10} {'dec/32':>7} {'false':>6} {'CPU-s/task':>10}  delta [bootstrap 95% CI]")
    for name, r in s["systems"].items():
        d = f"{r['paired_delta_vs_candidate']:+.3f} [{r['bootstrap_95ci'][0]:+.3f}, {r['bootstrap_95ci'][1]:+.3f}]" \
            if "paired_delta_vs_candidate" in r else "—"
        print(f"{name:10} {r['correct']:>10} {r['decision_correct_of_32']:>7} {r['false_activation']:>6} "
              f"{r['cpu_s_per_task']:>10}  {d}")
    print("lifecycle:", s["lifecycle"])
    print(f"candidate: {s['candidate_items_with_zero_model_calls']}/40 items with 0 model calls, "
          f"{s['candidate_model_calls_total']} model calls total")
    print("other tenant / lower clearance:", s["unauthorized"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
