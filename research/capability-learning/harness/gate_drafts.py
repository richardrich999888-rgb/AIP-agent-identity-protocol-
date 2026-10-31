"""Approach 3 — apply the deterministic evidence gate (triage) to every recorded IR draft.

usage: gate_drafts.py RESULTS_DIR/sprint   -> gate.json
No model is run: the gate is evaluated on the drafts the single-form and
decomposed proposers already produced, plus the engineer-corrected IR.
"""
from __future__ import annotations

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ir_compiler import triage  # noqa: E402

CL = os.path.abspath(os.path.join(HERE, ".."))
TASKS = {"bt": "tasks/bt_hubt4.json", "ir": "tasks/ir_ep114.json"}


def main() -> None:
    S = sys.argv[1]
    out = []
    for d in sorted(glob.glob(os.path.join(S, "candidate_*"))) + [os.path.join(S, "corrected_bt")]:
        fam = "bt" if "_bt" in d else "ir"
        spec = {**json.load(open(os.path.join(CL, TASKS[fam]))), "proposed_by": "gate", "demo_ids": []}
        doc = open(os.path.join(CL, spec["data"], spec["doc_file"])).read()
        cost = json.load(open(os.path.join(d, "cost.json"))) if os.path.exists(os.path.join(d, "cost.json")) else {"rounds": []}
        agree = {r["round"]: r.get("demo_agreement") for r in cost["rounds"]}
        files = sorted(glob.glob(os.path.join(d, "round_*.ir.json"))) or [os.path.join(d, "corrected.ir.json")]
        for f in files:
            k = int(os.path.basename(f).split("_")[1].split(".")[0]) if "round_" in f else None
            demo = agree.get(k) if k else 5  # corrected IR: 5/6 (demo-4 parser limit), measured by cap-check
            t = triage(json.load(open(f)), spec, doc, demo, 6)
            out.append({"draft": os.path.relpath(f, S), "status": t["status"], "unsupported_numbers": len(t["unsupported_numbers"]),
                        "reasons": t["reasons"]})
    json.dump(out, open(os.path.join(S, "gate.json"), "w"), indent=1, ensure_ascii=False)
    for o in out:
        print(f"{o['draft']:45s} {o['status']:32s} unsupported={o['unsupported_numbers']}")


if __name__ == "__main__":
    main()
