"""Hand-authored held-out set v5 — written BEFORE the live runtime
controller (feature/syntriass-intelligence-runtime-v01) existed, after v3 and
v4 had both been inspected. v5 is the only unseen set for validating the
controller's routing; it must not be used to design routing rules.

Same schema and policy as v3/v4. Provenance: authored 2026-10-31 by the
system builder, item by item (single author: a stated limitation). Compared
with v4 it carries more multi-reading reports (the case routing targets),
new phrasings, and new must-abstain cases.

Usage: python3 -I hard_reports_v5.py OUT_DIR
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datasets.hard_reports_v3 import decision  # noqa: E402
from datasets.maintenance_priority import METRICS  # noqa: E402

VERSION = "hard-reports-v5"
KEYS = {m.key for m in METRICS}

ITEMS = [
    # single reading, descriptive or terse
    ("descriptive", "Cooling water pump P-7, drive end, 5.2 mm/s overall vibration.", [("p7_vib", 5.2)]),
    ("descriptive", "Standby genset day tank is down to 38 percent.", [("g2_tank", 38)]),
    ("descriptive", "Fire pump weekly flow test came in at 71 percent of rated discharge.", [("fp1_press", 71)]),
    ("descriptive", "Chiller CH-5 condenser approach is sitting at 4.4 C.", [("ch5_app", 4.4)]),
    ("descriptive", "Isolation valve V-12 took 10.4 seconds to stroke fully.", [("v12_stroke", 10.4)]),
    ("no_unit", "T-3 top oil 99.", [("t3_oil", 99)]),
    ("no_unit", "FP-1 discharge 58.", [("fp1_press", 58)]),
    ("noisy", "p7 vib 2.9 mms, fine", [("p7_vib", 2.9)]),
    ("noisy", "TX3 oil temp 107c !!", [("t3_oil", 107)]),
    ("noisy", "gen2 tnk 84pct", [("g2_tank", 84)]),
    ("noisy", "V12 strk 14.6 sec", [("v12_stroke", 14.6)]),
    ("mixed_lang", "G-2 day tank lo 45 percent undi.", [("g2_tank", 45)]),
    ("mixed_lang", "CH-5 approach 2.4 C hai, theek hai.", [("ch5_app", 2.4)]),
    ("distractor", "Job card JC-4410: P-7 bearing 88 C at 14:30.", [("p7_bear", 88)]),
    ("distractor", "Loop LT-08 calibrated; G-2 day tank 61 percent.", [("g2_tank", 61)]),
    ("distractor", "MCC-3 feeder isolated. V-12 stroke 11.8 s.", [("v12_stroke", 11.8)]),
    ("distractor", "Sample bottle SB-19 taken; T-3 top-oil 93 C.", [("t3_oil", 93)]),
    ("conversion", "T-3 top oil 221 F.", [("t3_oil", 105)]),  # 221 F = 105 C
    ("conversion", "V-12 full stroke 9800 ms.", [("v12_stroke", 9.8)]),
    # multiple readings in one report
    ("multi", "P-7 vibration 3.1 mm/s and bearing 91 C.", [("p7_vib", 3.1), ("p7_bear", 91)]),
    ("multi", "V-12 stroke 13.1 s; G-2 day tank 72 percent.", [("v12_stroke", 13.1), ("g2_tank", 72)]),
    ("multi", "CH-5 approach 3.4 C, FP-1 flow test 77 percent of rated.", [("ch5_app", 3.4), ("fp1_press", 77)]),
    ("multi", "Round 2: T-3 oil 88 C, P-7 seal 6 drops/min.", [("t3_oil", 88), ("p7_seal", 6)]),
    ("multi", "P-7 vib 7.6 mm/s, seal leak 25 drops/min, bearing 70 C.", [("p7_vib", 7.6), ("p7_seal", 25), ("p7_bear", 70)]),
    ("multi", "G-2 day tank 55 percent and V-12 closing 10.0 s.", [("g2_tank", 55), ("v12_stroke", 10.0)]),
    # abstain: unknown equipment
    ("abstain_unknown_equipment", "Pump P-8 vibration 6.0 mm/s.", []),
    ("abstain_unknown_equipment", "Transformer T-4 top oil 101 C.", []),
    ("abstain_unknown_equipment", "Chiller CH-55 approach 3.9 C.", []),
    ("abstain_unknown_equipment", "Condensate extraction pump CEP-1 bearing 92 C.", []),
    ("abstain_unknown_equipment", "Air compressor discharge temp 104 C.", []),
    ("abstain_unknown_equipment", "Valve V-2 stroke 16 s.", []),
    # abstain: no value / ambiguous
    ("abstain_no_value", "G-2 test run completed, no alarms.", []),
    ("abstain_no_value", "CH-5 tubes brushed during shutdown.", []),
    ("abstain_no_value", "V-12 actuator grease topped up.", []),
    ("abstain_ambiguous", "T-3 around 90-100 today.", []),
    ("abstain_ambiguous", "Pump reading 5.", []),
    ("abstain_ambiguous", "FP-1 pressure fine, maybe 60s.", []),
]


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for i, (cat, text, gold) in enumerate(ITEMS):
        assert all(k in KEYS for k, _ in gold), text
        rows.append({"id": f"hold-{i:03d}", "category": cat, "text": text,
                     "gold_readings": [[k, v] for k, v in gold], "label": decision(gold)})
    texts = [r["text"] for r in rows]
    assert len(set(texts)) == len(texts)
    here = os.path.dirname(out_dir)
    seen = set()
    for d in ("maintenance-priority-v2", "hard-reports-v3", "hard-reports-v4"):
        p = os.path.join(here, d)
        if os.path.isdir(p):
            seen |= {json.loads(l)["text"] for f in os.listdir(p) if f.endswith(".jsonl") for l in open(os.path.join(p, f))}
    path = os.path.join(out_dir, "test_hard.jsonl")
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    cats, labels = {}, {}
    for r in rows:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
        labels[r["label"]] = labels.get(r["label"], 0) + 1
    m = {"version": VERSION, "n": len(rows), "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
         "categories": cats, "label_counts": labels, "text_overlap_with_v2_v3_v4": sum(t in seen for t in texts),
         "provenance": "hand-authored before the live runtime controller existed; held-out for routing"}
    json.dump(m, open(os.path.join(out_dir, "MANIFEST.json"), "w"), indent=2, sort_keys=True)
    print(json.dumps(m, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
