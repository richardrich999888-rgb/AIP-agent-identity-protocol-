#!/usr/bin/env python3
"""Compare a fresh benchmark rerun with the recorded results (W6.3).

usage: compare.py RECORDED_RESULTS_DIR FRESH_DIR   (prints Markdown)

Both directories have the harness layout: run1/report.json,
baselines_q8/{B1,B2,B3}.jsonl + summary.json, phase_e/report.json.
For each system: correct /40, decision /32, false activations, CPU-s per task,
and how many of the 40 items got the same label in both runs. Differences
are listed item by item. Nothing is averaged across the two runs, and a
difference is never widened into a range.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def jl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def load(d: Path) -> dict[str, dict]:
    rep = json.loads((d / "run1/report.json").read_text())
    summ = json.loads((d / "baselines_q8/summary.json").read_text())
    out = {}
    for n in ("B1", "B2", "B3"):
        items = jl(d / f"baselines_q8/{n}.jsonl")
        out[n] = {"items": items, "cpu": summ[n]["cpu_s_total"] / len(items), "fa": summ[n]["false_activation"]}
    for n, k in (("B4", "baseline4_no_capability"), ("candidate", "phaseD_capability")):
        items = rep[k]["items"]
        out[n] = {"items": items, "cpu": sum(i["cpu_s"] for i in items) / len(items), "fa": rep[k]["false_activation"]}
    out["_lifecycle"] = rep["lifecycle"]["validation"]
    pe = d / "phase_e/report.json"
    out["_phase_e"] = json.loads(pe.read_text()) if pe.exists() else None
    out["_model"] = summ.get("model_sha256")
    return out


def row(s: dict) -> tuple[int, int]:
    ok = {i["id"]: bool(i["ok"]) for i in s["items"]}
    return sum(ok.values()), sum(v for k, v in ok.items() if k.startswith("test-"))


def main() -> int:
    rec, new = load(Path(sys.argv[1])), load(Path(sys.argv[2]))
    print("# Benchmark rerun vs recorded\n")
    print(f"Model sha256 (baselines): recorded `{rec['_model'][:12]}…`, fresh `{new['_model'][:12]}…` — "
          f"{'same file' if rec['_model'] == new['_model'] else 'DIFFERENT FILE'}\n")
    print("| System | Correct /40 (rec → fresh) | Decision /32 | False act. | CPU-s/task | Same label on |")
    print("|---|---|---|---|---|---|")
    diffs = []
    for n in ("B1", "B2", "B3", "B4", "candidate"):
        a, b = rec[n], new[n]
        ga = {i["id"]: i["got"] for i in a["items"]}
        gb = {i["id"]: i["got"] for i in b["items"]}
        same = sum(ga[k] == gb.get(k) for k in ga)
        (ca, da), (cb, db) = row(a), row(b)
        print(f"| {n} | {ca} → {cb} | {da} → {db} | {a['fa']} → {b['fa']} | {a['cpu']:.2f} → {b['cpu']:.2f} | {same}/{len(ga)} |")
        diffs += [f"- {n} {k}: recorded `{ga[k]}`, fresh `{gb.get(k)}`" for k in sorted(ga) if ga[k] != gb.get(k)]
    la, lb = rec["_lifecycle"], new["_lifecycle"]
    keys = ("expert_passed", "expert_cases", "counterexamples_passed", "counterexamples", "suite_signature_ok")
    print(f"\nLifecycle: recorded {[la[k] for k in keys]}, fresh {[lb[k] for k in keys]} ({', '.join(keys)})")
    if new["_phase_e"] and rec["_phase_e"]:
        e_rec = {i["id"]: i["got"] for i in rec["_phase_e"]["e1_speed_q8"]["items"]}
        e_new = {i["id"]: i["got"] for i in new["_phase_e"]["e1_speed_q8"]["items"]}
        d_new = {i["id"]: i["got"] for i in new["candidate"]["items"]}
        print(f"\nPhase E (Q4 → Q8): fresh Q8 labels equal fresh Q4 labels on "
              f"{sum(e_new[k] == d_new.get(k) for k in e_new)}/{len(e_new)}; equal recorded Q8 on "
              f"{sum(e_new[k] == e_rec.get(k) for k in e_new)}/{len(e_new)}")
        for part in ("e2_balanced", "e2_speed"):
            r, n = rec["_phase_e"][part], new["_phase_e"][part]
            print(f"  {part}: recorded ran={r.get('ran_capability')} refused_stale={r.get('refused_stale')}; "
                  f"fresh ran={n.get('ran_capability')} refused_stale={n.get('refused_stale')}")
    print("\n## Items whose label changed\n")
    print("\n".join(diffs) if diffs else "None.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
