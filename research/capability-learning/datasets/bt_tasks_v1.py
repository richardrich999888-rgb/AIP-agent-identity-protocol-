"""bt-tasks-v1 — fresh task family for the constrained capability compiler.

Frozen BEFORE any compiler code exists (sprint iteration 1). Single author
(the system's author), fictional organisations. Labels are computed by
`reference()` below, which implements the procedure text sentence by
sentence; every item's text was written by hand.

usage: python3 -I bt_tasks_v1.py OUT_DIR
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

DOC = """halvorn-power|hu-bt-4|restricted|HU-BT-4 rev B Stationary battery cell float acceptance
Halvorn Power procedure HU-BT-4 revision B. Confidential.
Scope: vented lead-acid cells in substation and UPS battery banks. This procedure does not apply to lithium, nickel-cadmium or NiCd batteries; such requests are out of scope. A voltage above 3 volts is a block or string voltage, not a cell voltage, and is out of scope.
Required inputs: cell float voltage in volts, electrolyte temperature in degrees Celsius, and specific gravity (SG) of the electrolyte. If any input is missing the result is insufficient input.
Step 1 validity: the electrolyte temperature must be between 5 and 45 degrees Celsius inclusive; otherwise the reading is invalid and must be repeated.
Step 2 temperature correction: correct the cell voltage to 25 degrees Celsius by adding 0.003 volts for every degree Celsius above 25 and subtracting 0.003 volts for every degree below 25.
Step 3 decision: if the corrected voltage is below 2.10 volts, replace the cell. If it is below 2.17 volts, equalize charge the bank. If it is above 2.30 volts, reduce the float voltage (overcharge). Otherwise, if the specific gravity is below 1.200, equalize charge. Otherwise accept.
"""

OTHER = """tarvel-grid|tg-bt-01|restricted|TG-BT-01 Battery float limits
Tarvel Grid procedure TG-BT-01. Confidential. All cells must float between 2.20 and 2.27 volts with no temperature correction; specific gravity is not used.
"""

LABELS = ["ACCEPT", "EQUALIZE", "REPLACE_CELL", "REDUCE_FLOAT", "INVALID_TEST", "OUT_OF_SCOPE", "INSUFFICIENT_INPUT"]


def reference(v: float | None, t: float | None, sg: float | None, chem_out: bool = False) -> str:
    """HU-BT-4 rev B, sentence by sentence (volts, °C, SG)."""
    if chem_out:
        return "OUT_OF_SCOPE"
    if v is not None and v > 3:
        return "OUT_OF_SCOPE"
    if v is None or t is None or sg is None:
        return "INSUFFICIENT_INPUT"
    if t < 5 or t > 45:
        return "INVALID_TEST"
    c = v + 0.003 * (t - 25)
    if c < 2.10:
        return "REPLACE_CELL"
    if c < 2.17:
        return "EQUALIZE"
    if c > 2.30:
        return "REDUCE_FLOAT"
    if sg < 1.200:
        return "EQUALIZE"
    return "ACCEPT"


# (id, text, v, t, sg, chem_out, category) — expected label from reference(), or explicit.
DEMOS = [
    ("demo-0", "Cell 7, UPS bank A: float 2.22 V at 25 C, SG 1.215. Decision?", 2.22, 25, 1.215, False, "basic"),
    ("demo-1", "Substation battery cell 12 reads 2.15 volts, electrolyte 25 C, SG 1.210.", 2.15, 25, 1.210, False, "basic"),
    ("demo-2", "Cell 3: 2.20 V at 15 C, specific gravity 1.220.", 2.20, 15, 1.220, False, "correction"),
    ("demo-3", "Cell 30 float 2.33 V, 35 C electrolyte, SG 1.225.", 2.33, 35, 1.225, False, "overcharge"),
    ("demo-4", "Cell 9: 2.24 V at 26 C but SG only 1.185.", 2.24, 26, 1.185, False, "sg"),
    ("demo-5", "Cell 2 at 2.21 V, electrolyte 52 C, SG 1.215.", 2.21, 52, 1.215, False, "validity"),
]
WORKING = {
    "demo-0": "corrected 2.22; 2.17 <= 2.22 <= 2.30; SG 1.215 >= 1.200 -> ACCEPT",
    "demo-1": "corrected 2.15 < 2.17 -> EQUALIZE",
    "demo-2": "corrected 2.20 + 0.003*(15-25) = 2.17; not below 2.17 -> SG 1.220 -> ACCEPT",
    "demo-3": "corrected 2.33 + 0.03 = 2.36 > 2.30 -> REDUCE_FLOAT",
    "demo-4": "corrected 2.243; SG 1.185 < 1.200 -> EQUALIZE",
    "demo-5": "52 C outside 5-45 -> INVALID_TEST",
}
VALIDATION = [  # the expert's suite (counterexample = designed to break a naive procedure)
    ("val-00", "Cell 1, 2.17 V at 25 C, SG 1.200", 2.17, 25, 1.200, False, "boundary"),
    ("val-01", "Cell 1, 2.169 V at 25 C, SG 1.230", 2.169, 25, 1.230, False, "boundary"),
    ("val-02", "Cell 4: 2.10 V at 25 C, SG 1.210", 2.10, 25, 1.210, False, "boundary"),
    ("val-03", "Cell 5: 2.099 V, 25 C, SG 1.210", 2.099, 25, 1.210, False, "boundary"),
    ("val-04", "Cell 6 floats at 2.30 V, 25 C, SG 1.220", 2.30, 25, 1.220, False, "boundary"),
    ("val-05", "Cell 8: 2.26 V at 40 C, SG 1.215", 2.26, 40, 1.215, False, "correction"),
    ("val-06", "Cell 10: 2.25 V at 5 C, SG 1.215", 2.25, 5, 1.215, False, "validity-edge"),
    ("val-07", "Cell 11: 2.25 V at 4 C, SG 1.215", 2.25, 4, 1.215, False, "validity"),
    ("val-08", "NiCd cell 2: 1.42 V at 25 C, SG 1.200", 1.42, 25, 1.200, True, "scope"),
    ("val-09", "UPS string reads 26.8 V at 25 C, SG 1.215", 26.8, 25, 1.215, False, "scope-numeric"),
    ("val-10", "Cell 12 at 2.23 V and 24 C; SG not recorded", 2.23, 24, None, False, "missing"),
    ("val-11", "Cell 13: 2.21 V at 25 C, SG 1.199", 2.21, 25, 1.199, False, "sg-boundary"),
]
COUNTEREX = {"validity", "scope", "scope-numeric", "missing", "validity-edge"}
UNSEEN = [
    ("t-00", "Battery room check: cell 21 sits at 2.23 V, electrolyte 22 °C, SG 1.218 — OK to leave in service?", 2.23, 22, 1.218, False, "wording"),
    ("t-01", "Is UPS-B cell 4 acceptable? 2.19 volts at 18 deg C, specific gravity 1.215.", 2.19, 18, 1.215, False, "correction"),
    ("t-02", "Cell 16 dropped to 2.06 V (electrolyte 25 C, SG 1.190).", 2.06, 25, 1.190, False, "replace"),
    ("t-03", "Cell 17: 2.12 V, 30 C, SG 1.205", 2.12, 30, 1.205, False, "equalize"),
    ("t-04", "Cell 18 float 2.29 V at 38 °C, SG 1.230", 2.29, 38, 1.230, False, "overcharge-corrected"),
    ("t-05", "Cell 19 float 2.28 V at 12 C, SG 1.230", 2.28, 12, 1.230, False, "correction-down"),
    ("t-06", "Cell 20: 2.22 V, 25 C, SG 1.195", 2.22, 25, 1.195, False, "sg"),
    ("t-07", "Cell 22 reading 2.22 V at 68 °F, SG 1.215", 2.22, 20, 1.215, False, "unit-F"),
    ("t-08", "Cell 23 reading 2.22 V at 113 °F, SG 1.215", 2.22, 45, 1.215, False, "unit-F-edge"),
    ("t-09", "Cell 24: 2.25V at 25C, SG 1.215", 2.25, 25, 1.215, False, "unit-fused"),
    ("t-10", "Cell 25 float 2.24 volts, SG 1.220", 2.24, None, 1.220, False, "missing-temp"),
    ("t-11", "Cell 26 electrolyte 26 C, SG 1.212, voltage not taken", None, 26, 1.212, False, "missing-voltage"),
    ("t-12", "Lithium UPS module 3 shows 3.32 V at 25 C, SG n/a", 3.32, 25, None, True, "scope"),
    ("t-13", "Nickel-cadmium cell 6: 1.38 V at 20 C, SG 1.190", 1.38, 20, 1.190, True, "scope"),
    ("t-14", "Bank voltage 129.6 V at 25 C, SG 1.215", 129.6, 25, 1.215, False, "scope-numeric"),
    ("t-15", "Cell 27: 2.21 V at 2 C, SG 1.220 (outdoor enclosure in winter)", 2.21, 2, 1.220, False, "validity"),
    ("t-16", "Cell 28 at 2.20 V and 47 C, SG 1.215", 2.20, 47, 1.215, False, "validity"),
    ("t-17", "Cell 29: 2.18 V at 22 C, SG 1.210", 2.18, 22, 1.210, False, "boundary-corrected"),
    ("t-18", "Cell 31: 2.27 V at 35 C, SG 1.215", 2.27, 35, 1.215, False, "boundary-corrected"),
    ("t-19", "Cell 32 shows 2.31 V at 20 C, SG 1.230", 2.31, 20, 1.230, False, "overcharge-correction-down"),
    ("t-20", "Cell 33: 2.08 V at 40 C, SG 1.200", 2.08, 40, 1.200, False, "correction-up"),
    ("t-21", "Cell 34, float 2.23 V, 25 °C, specific gravity 1.180", 2.23, 25, 1.180, False, "sg"),
    ("t-22", "Cell 35 2.24 V at 25 C, SG 1.212 — remeasured 2.16 V ten minutes later", None, 25, 1.212, False, "contradictory"),
    ("t-23", "Cells 36 and 37: 2.21 V and 2.09 V at 25 C, SG 1.215 and 1.205", None, 25, None, False, "multi-entity"),
    ("t-24", "Cell 38: 2.23 V at 25 C, SG 1.215, SG 1.198 on second hydrometer", 2.23, 25, None, False, "contradictory-sg"),
    ("t-25", "Equalize or not? Cell 39 is at 2.165 V, electrolyte 25 C, SG 1.230", 2.165, 25, 1.230, False, "wording"),
    ("t-26", "Cell 40 at 2,23 V, 25 C, SG 1.215", 2.23, 25, 1.215, False, "unit-decimal-comma"),
    ("t-27", "Cell 41: float 2.21 V, 77 °F electrolyte, specific gravity 1.205", 2.21, 25, 1.205, False, "unit-F"),
    ("t-28", "Cell 42 2.26 V 30 C SG 1.212", 2.26, 30, 1.212, False, "terse"),
    ("t-29", "VRLA? No — vented cell 43, 2.22 V at 25 C, SG 1.220", 2.22, 25, 1.220, False, "wording-negation"),
]
# Explicit labels where the request itself is not a single clean reading.
EXPLICIT = {"t-22": "AMBIGUOUS", "t-23": "AMBIGUOUS", "t-24": "AMBIGUOUS"}
FALSE_ACTIVATION = [
    ("fa-0", "Who maintains the battery room key register?"),
    ("fa-1", "When is the next UPS battery replacement scheduled?"),
    ("fa-2", "What PPE is required when topping up electrolyte?"),
    ("fa-3", "Transformer T-3 oil temperature 92 C, is that a concern?"),
    ("fa-4", "Explain how specific gravity relates to state of charge."),
    ("fa-5", "List the battery banks in substation 4."),
]


def rows(spec, with_working=False):
    out = []
    for i, text, v, t, sg, chem, cat in spec:
        r = {"id": i, "text": text, "category": cat, "inputs": {"v": v, "t": t, "sg": sg},
             "label": EXPLICIT.get(i, reference(v, t, sg, chem))}
        if with_working:
            r["expert_working"] = WORKING[i]
        out.append(r)
    return out


def main() -> None:
    out = sys.argv[1]
    os.makedirs(os.path.join(out, "corpus"), exist_ok=True)
    files = {"corpus/halvorn-hu-bt-4.txt": DOC, "corpus/tarvel-tg-bt-01.txt": OTHER}
    data = {"demos.jsonl": rows(DEMOS, True), "validation.jsonl": [{**r, "counterexample": r["category"] in COUNTEREX} for r in rows(VALIDATION)],
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
    json.dump({"version": "bt-tasks-v1", "provenance": "hand-authored in sprint iteration 1, before any compiler code; single author; fictional organisations",
               "sha256": sha, "label_counts": counts}, open(os.path.join(out, "MANIFEST.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
