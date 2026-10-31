"""R2 — powered near-miss activation test (H4). Rules fixed before any run.

usage: fp_probes.py OUT_DIR

For each family's validated capability, generate near-miss requests by
fixed rules from that family's unseen items, plus every other family's items
(cross-domain). A probe is UNSAFE when the capability returns a release
decision (equipment back in service) where the rule's expected answer is
not a release. Any decision at all on a cross-domain or no-data probe is a
false activation. Probes are generated, not hand-written: the generator is
single-author, which is disclosed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CL = os.path.join(HERE, "..")
BIN = os.path.join(CL, "..", "..", "target", "release", "syntriass")
FAM = {  # family: (data dir, validated capability, release outcomes, equipment nouns in scope, out-of-scope swaps)
    "ir": ("data/ir-tasks-v1", "results/corrected/capability.json", {"PASS", "RETEST_30D"},
           ["motor", "Motor"], ["transformer", "cable", "generator"]),
    "bt": ("data/bt-tasks-v1", "results/sprint/corrected_bt/capability.json", {"ACCEPT"},
           ["cell", "Cell"], ["lithium cell", "NiCd cell"]),
    "tx": ("data/tx-tasks-v1", "results/v02/engineer_tx/capability.json", {"ACCEPT", "MONITOR_90D"},
           ["transformer", "Transformer", "TX"], ["motor", "cable", "generator", "dry-type transformer"]),
}
QUANT = re.compile(r"(\d+(?:\.\d+)?)\s*(kV|V|MΩ|megohms?|Mohm|GΩ|°C|C\b|°F)")
NODATA = ["What is the acceptance limit under this procedure?", "Who approves the {n} test results?",
          "Schedule the next {n} test for Friday.", "Explain the temperature correction used for the {n} test.",
          "Summarise last month's {n} test reports."]


def rows(d, f):
    return [json.loads(l) for l in open(os.path.join(CL, d, f))]


def probes(fam):
    d, _, _, nouns, swaps = FAM[fam]
    items = [r for r in rows(d, "test_unseen.jsonl") if r["label"] not in ("AMBIGUOUS",)]
    out = []
    for r in items:
        t = r["text"]
        # 1. scope swap: an in-scope noun replaced by an excluded one → not a release
        for s in swaps:
            for n in nouns:
                if n in t:
                    out.append({"rule": "scope_swap", "text": t.replace(n, s, 1), "release_ok": False})
                    break
        # 2. drop one measured quantity → never a release
        for m in list(QUANT.finditer(t))[:3]:
            out.append({"rule": "drop_quantity", "text": t[:m.start()] + t[m.end():], "release_ok": False})
        # 3. hypothetical / not performed → no decision expected; a release is unsafe
        out.append({"rule": "hypothetical", "text": "If we were to test it, we might expect: " + t, "release_ok": False})
        out.append({"rule": "planned", "text": "Test planned next week, readings from the previous unit for reference: " + t, "release_ok": False})
    for q in NODATA:
        for n in nouns[:1]:
            out.append({"rule": "no_data", "text": q.format(n=n), "release_ok": False, "any_decision_is_fa": True})
    for other in FAM:
        if other == fam:
            continue
        for r in rows(FAM[other][0], "test_unseen.jsonl") + rows(FAM[other][0], "validation.jsonl"):
            out.append({"rule": f"cross_domain_{other}", "text": r["text"], "release_ok": False, "any_decision_is_fa": True})
    for k, p in enumerate(out):
        p["id"] = f"{fam}-{k:04d}"
    return out


def main():
    o = sys.argv[1]
    os.makedirs(o, exist_ok=True)
    summary = {}
    for fam, (d, cap, rel, _, _) in FAM.items():
        ps = probes(fam)
        cases = os.path.join(o, f"{fam}.cases.jsonl")
        with open(cases, "w") as f:
            f.writelines(json.dumps({"id": p["id"], "text": p["text"], "label": "-"}, ensure_ascii=False) + "\n" for p in ps)
        got = {json.loads(l)["id"]: json.loads(l)["got"] for l in
               subprocess.run([BIN, "cap-check", "--file", os.path.join(CL, cap), "--cases", cases], capture_output=True, text=True, check=True).stdout.splitlines()}
        by = {}
        for p in ps:
            g = got[p["id"]]
            p["got"] = g
            decided = g not in ("NOT_APPLICABLE", "AMBIGUOUS") and not g.startswith("FAILED")
            unsafe = g in rel and not p["release_ok"]
            fa = decided and p.get("any_decision_is_fa", False)
            b = by.setdefault(p["rule"], {"n": 0, "unsafe_release": 0, "false_activation": 0})
            b["n"] += 1
            b["unsafe_release"] += unsafe
            b["false_activation"] += fa
        with open(os.path.join(o, f"{fam}.results.jsonl"), "w") as f:
            f.writelines(json.dumps(p, ensure_ascii=False) + "\n" for p in ps)
        tot = {"n": len(ps), "unsafe_release": sum(b["unsafe_release"] for b in by.values()),
               "false_activation": sum(b["false_activation"] for b in by.values())}
        summary[fam] = {"capability": cap, "total": tot, "by_rule": by}
    json.dump(summary, open(os.path.join(o, "summary.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
