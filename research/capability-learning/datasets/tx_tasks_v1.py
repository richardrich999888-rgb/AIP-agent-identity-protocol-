"""tx-tasks-v1 — fresh holdout family for the v0.2 learning pipeline.

Frozen BEFORE any atomic-claim pipeline code exists (v0.2 phase 0).
Fictional organisation; single author (the system's author). Labels come from
`reference()`, which implements the document sentence by sentence; item texts
are hand-written. Labels must not be edited after any result is seen.

usage: python3 -I tx_tasks_v1.py OUT_DIR
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

DOC = """halvorn-power|hu-tx-2|restricted|HU-TX-2 rev A Distribution transformer insulation acceptance
Halvorn Power procedure HU-TX-2 revision A. Confidential.
Scope: oil-immersed distribution transformers rated up to and including 33 kV. This procedure does not apply to motors, cables, generators or dry-type transformers; such requests are out of scope. Transformers rated above 33 kV are out of scope.
Required inputs: rated high-voltage winding voltage in kV, insulation resistance from the high-voltage winding to earth in megohms, top-oil temperature in degrees Celsius, and dielectric absorption ratio (DAR). If any input is missing the result is insufficient input.
Step 1 validity: the top-oil temperature must be between 0 and 90 degrees Celsius inclusive; otherwise the test is invalid.
Step 2 temperature correction: correct the insulation resistance to 20 degrees Celsius by multiplying it by 2 raised to the power of (top-oil temperature minus 20) divided by 15.
Step 3 minimum: the minimum acceptable corrected resistance is 20 times (rated kV plus 2) megohms.
Step 4 decision: if the corrected resistance is below one third of the minimum, remove the transformer from service. If it is below the minimum, dry out the oil and retest. If DAR is below 1.25, investigate. If DAR is at least 1.25 but below 1.4, monitor and retest in 90 days. Otherwise accept.
"""

LABELS = ["ACCEPT", "MONITOR_90D", "INVESTIGATE", "DRY_OUT_OIL", "REMOVE_FROM_SERVICE", "INVALID_TEST", "OUT_OF_SCOPE",
          "INSUFFICIENT_INPUT"]


def reference(kv, ir, t, dar, out=False) -> str:
    """HU-TX-2 rev A, sentence by sentence (kV, MΩ, °C, DAR)."""
    if out or (kv is not None and kv > 33):
        return "OUT_OF_SCOPE"
    if None in (kv, ir, t, dar):
        return "INSUFFICIENT_INPUT"
    if t < 0 or t > 90:
        return "INVALID_TEST"
    c = ir * 2 ** ((t - 20) / 15)
    m = 20 * (kv + 2)
    if c < m / 3:
        return "REMOVE_FROM_SERVICE"
    if c < m:
        return "DRY_OUT_OIL"
    if dar < 1.25:
        return "INVESTIGATE"
    if dar < 1.4:
        return "MONITOR_90D"
    return "ACCEPT"


# (id, text, kv, ir_MOhm, t_C, dar, out, category)
DEMOS = [
    ("demo-0", "Transformer TX-14, 11 kV: IR 800 megohms at 20 C, DAR 1.6.", 11, 800, 20, 1.6, False, "basic"),
    ("demo-1", "TX-3 rated 11 kV, IR 200 megohms at 20 C, DAR 1.5.", 11, 200, 20, 1.5, False, "dry-out"),
    ("demo-2", "TX-9 (6.6 kV): 40 megohms at 20 C, DAR 1.5.", 6.6, 40, 20, 1.5, False, "remove"),
    ("demo-3", "TX-21 22 kV, IR 1200 megohms at 35 C, DAR 1.3.", 22, 1200, 35, 1.3, False, "monitor"),
    ("demo-4", "TX-5 at 11 kV, 600 megohms at 5 C, DAR 1.2.", 11, 600, 5, 1.2, False, "correction-investigate"),
    ("demo-5", "TX-7, 11 kV, 900 megohms, top oil 95 C, DAR 1.5.", 11, 900, 95, 1.5, False, "validity"),
]
WORKING = {
    "demo-0": "corrected 800; minimum 20*(11+2)=260; DAR 1.6 >= 1.4 -> ACCEPT",
    "demo-1": "corrected 200 < 260 and >= 86.7 -> DRY_OUT_OIL",
    "demo-2": "minimum 20*(6.6+2)=172; corrected 40 < 172/3 = 57.3 -> REMOVE_FROM_SERVICE",
    "demo-3": "corrected 1200*2^(15/15) = 2400 >= 480; DAR 1.3 in [1.25, 1.4) -> MONITOR_90D",
    "demo-4": "corrected 600*2^(-1) = 300 >= 260; DAR 1.2 < 1.25 -> INVESTIGATE",
    "demo-5": "95 C outside 0-90 -> INVALID_TEST",
}
VALIDATION = [
    ("val-00", "TX-30 11 kV, 260 megohms at 20 C, DAR 1.4", 11, 260, 20, 1.4, False, "boundary"),
    ("val-01", "TX-31 11 kV, 259 megohms at 20 C, DAR 1.6", 11, 259, 20, 1.6, False, "boundary"),
    ("val-02", "TX-32 11 kV, 87 megohms at 20 C, DAR 1.6", 11, 87, 20, 1.6, False, "boundary-third"),
    ("val-03", "TX-33 11 kV, 86 megohms at 20 C, DAR 1.6", 11, 86, 20, 1.6, False, "boundary-third"),
    ("val-04", "TX-34 11 kV, 500 megohms at 20 C, DAR 1.25", 11, 500, 20, 1.25, False, "boundary-dar"),
    ("val-05", "TX-35 11 kV, 500 megohms at 20 C, DAR 1.24", 11, 500, 20, 1.24, False, "boundary-dar"),
    ("val-06", "TX-36 11 kV, 150 megohms at 50 C, DAR 1.5", 11, 150, 50, 1.5, False, "correction"),
    ("val-07", "TX-37 11 kV, 700 megohms at 0 C, DAR 1.5", 11, 700, 0, 1.5, False, "validity-edge"),
    ("val-08", "TX-38 11 kV, 700 megohms at -2 C, DAR 1.5", 11, 700, -2, 1.5, False, "validity"),
    ("val-09", "Cable C-4 11 kV, 700 megohms at 20 C, DAR 1.5", 11, 700, 20, 1.5, True, "scope"),
    ("val-10", "TX-40 66 kV, 3000 megohms at 20 C, DAR 1.5", 66, 3000, 20, 1.5, False, "scope-numeric"),
    ("val-11", "TX-41 11 kV, 700 megohms at 30 C, DAR not measured", 11, 700, 30, None, False, "missing"),
]
COUNTEREX = {"validity", "validity-edge", "scope", "scope-numeric", "missing"}
UNSEEN = [
    ("t-00", "Can TX-50 (11 kV) go back into service? Megger HV-earth 1.1 GΩ, top oil 28 °C, DAR 1.52.", 11, 1100, 28, 1.52, False, "wording-GOhm"),
    ("t-01", "TX-51 22 kV: IR 350 megohms at 20 C, DAR 1.6.", 22, 350, 20, 1.6, False, "dry-out"),
    ("t-02", "Pole transformer TX-52, 11 kV, 60 MΩ at 20 °C, DAR 1.45.", 11, 60, 20, 1.45, False, "remove"),
    ("t-03", "TX-53 at 33 kV, 900 megohms at 20 C, DAR 1.5.", 33, 900, 20, 1.5, False, "scope-edge"),
    ("t-04", "TX-54 at 33 kV, 600 megohms at 20 C, DAR 1.5.", 33, 600, 20, 1.5, False, "dry-out-edge"),
    ("t-05", "TX-55 11 kV, 200 megohms at 50 C, DAR 1.35.", 11, 200, 50, 1.35, False, "correction-monitor"),
    ("t-06", "TX-56 11 kV, 1500 megohms at 2 C, DAR 1.3.", 11, 1500, 2, 1.3, False, "correction-down"),
    ("t-07", "TX-57 11 kV, 400 megohms at 68 °F, DAR 1.1.", 11, 400, 20, 1.1, False, "unit-F"),
    ("t-08", "TX-58 11 kV, 0.5 GΩ at 104 °F, DAR 1.5.", 11, 500, 40, 1.5, False, "unit-F-GOhm"),
    ("t-09", "TX-59 6.6 kV, 3000 kΩ at 20 C, DAR 1.5.", 6.6, 3, 20, 1.5, False, "unit-kOhm"),
    ("t-10", "TX-60, IR 700 megohms at 25 C, DAR 1.5 (rating plate unreadable).", None, 700, 25, 1.5, False, "missing-kv"),
    ("t-11", "TX-61 11 kV, 700 megohms, DAR 1.5; oil thermometer broken.", 11, 700, None, 1.5, False, "missing-temp"),
    ("t-12", "Dry-type transformer DT-2, 11 kV, 900 megohms at 20 C, DAR 1.6.", 11, 900, 20, 1.6, True, "scope-dry"),
    ("t-13", "Generator G-2 stator, 11 kV, 900 megohms at 30 C, DAR 1.6.", 11, 900, 30, 1.6, True, "scope-gen"),
    ("t-14", "TX-62 rated 132 kV, 5 GΩ at 20 C, DAR 1.6.", 132, 5000, 20, 1.6, False, "scope-numeric"),
    ("t-15", "TX-63 11 kV, 700 megohms at 92 C, DAR 1.5.", 11, 700, 92, 1.5, False, "validity"),
    ("t-16", "TX-64 11 kV, 700 megohms at -5 °C, DAR 1.5.", 11, 700, -5, 1.5, False, "validity-negative"),
    ("t-17", "TX-65 11 kV, 270 megohms at 21 C, DAR 1.41.", 11, 270, 21, 1.41, False, "boundary-near"),
    ("t-18", "TX-66 11 kV, 250 megohms at 20 C, DAR 1.6.", 11, 250, 20, 1.6, False, "dry-out"),
    ("t-19", "TX-67 11 kV, 90 megohms at 20 C, DAR 1.6.", 11, 90, 20, 1.6, False, "third-near"),
    ("t-20", "TX-68 11 kV, 80 megohms at 20 C, DAR 1.6.", 11, 80, 20, 1.6, False, "remove"),
    ("t-21", "TX-69 11 kV, 1000 megohms at 20 C, DAR 1.2.", 11, 1000, 20, 1.2, False, "investigate"),
    ("t-22", "TX-70 11 kV, 1000 megohms at 20 C, DAR 1.3 — repeat test gave 850 megohms.", None, None, 20, 1.3, False, "contradictory"),
    ("t-23", "TX-71 and TX-72, both 11 kV: 900 and 120 megohms at 20 C, DAR 1.5.", None, None, 20, 1.5, False, "multi-entity"),
    ("t-24", "TX-73 11 kV, 1000 megohms at 20 C, DAR 1.5, DAR 1.2 on second instrument.", 11, 1000, 20, None, False, "contradictory-dar"),
    ("t-25", "Monitor or accept? TX-74 is 11 kV with 300 megohms at 20 C and a DAR of 1.39.", 11, 300, 20, 1.39, False, "wording"),
    ("t-26", "TX-75: 11kV, 900 megohms at 20 C, DAR 1.5", 11, 900, 20, 1.5, False, "unit-fused"),
    ("t-27", "TX-76 at 11 kV gave 1,200 megohms at 20 C, DAR 1.5", 11, 1200, 20, 1.5, False, "thousands-separator"),
    ("t-28", "TX-77 11 kV 900 megohms 20 C DAR 1.5", 11, 900, 20, 1.5, False, "terse"),
    ("t-29", "Not a cable — transformer TX-78, 11 kV, 900 megohms at 20 C, DAR 1.5.", 11, 900, 20, 1.5, False, "wording-negation"),
]
EXPLICIT = {"t-22": "AMBIGUOUS", "t-23": "AMBIGUOUS", "t-24": "AMBIGUOUS"}
FALSE_ACTIVATION = [
    ("fa-0", "Who signs off transformer oil sampling?"),
    ("fa-1", "When was the last DGA report for substation 4?"),
    ("fa-2", "What PPE is needed for insulation testing at 11 kV?"),
    ("fa-3", "Cell 7 floats at 2.22 V at 25 C with SG 1.215."),
    ("fa-4", "Explain what the dielectric absorption ratio measures."),
    ("fa-5", "List the transformers due for maintenance this quarter."),
]


def rows(spec, with_working=False):
    out = []
    for i, text, kv, ir, t, dar, o, cat in spec:
        r = {"id": i, "text": text, "category": cat, "inputs": {"kv": kv, "ir": ir, "t": t, "dar": dar},
             "label": EXPLICIT.get(i, reference(kv, ir, t, dar, o))}
        if with_working:
            r["expert_working"] = WORKING[i]
        out.append(r)
    return out


def main() -> None:
    out = sys.argv[1]
    os.makedirs(os.path.join(out, "corpus"), exist_ok=True)
    files = {"corpus/halvorn-hu-tx-2.txt": DOC}
    data = {"demos.jsonl": rows(DEMOS, True),
            "validation.jsonl": [{**r, "counterexample": r["category"] in COUNTEREX} for r in rows(VALIDATION)],
            "test_unseen.jsonl": rows(UNSEEN),
            "false_activation.jsonl": [{"id": i, "text": t, "label": "NOT_APPLICABLE"} for i, t in FALSE_ACTIVATION]}
    for f, rs in data.items():
        files[f] = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rs)
    sha = {}
    for f, body in files.items():
        open(os.path.join(out, f), "w").write(body)
        sha[f] = hashlib.sha256(body.encode()).hexdigest()
    counts = {f: {} for f in data}
    for f, rs in data.items():
        for r in rs:
            counts[f][r["label"]] = counts[f].get(r["label"], 0) + 1
    json.dump({"version": "tx-tasks-v1", "provenance": "hand-authored in v0.2 phase 0, before any atomic-claim pipeline code; single author; fictional organisation",
               "sha256": sha, "label_counts": counts}, open(os.path.join(out, "MANIFEST.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
