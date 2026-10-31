"""Hand-authored held-out set v4 — written BEFORE any iteration-2b method
(equipment gate, hybrid) was designed, after v3 results were seen. v3 is
therefore a development set from iteration 2b onward; v4 is the held-out set.

Same schema and policy as v3. Provenance: authored 2026-10-31 by the system
builder, item by item. Deliberately includes code-like tokens that are NOT
equipment (work orders, panel and tag numbers, part numbers) so that a gate
based on code patterns is tested for false abstentions.

Usage: python3 -I hard_reports_v4.py OUT_DIR
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datasets.hard_reports_v3 import decision  # noqa: E402
from datasets.maintenance_priority import METRICS  # noqa: E402

VERSION = "hard-reports-v4"
KEYS = {m.key for m in METRICS}

ITEMS = [
    # answerable, language-heavy
    ("descriptive", "Outboard end of the coolant circulation pump is vibrating at 7.9 mm/s.", [("p7_vib", 7.9)]),
    ("descriptive", "Our main power transformer's top oil hit 106 C after the load transfer.", [("t3_oil", 106)]),
    ("descriptive", "Emergency diesel set: day tank at 77 percent.", [("g2_tank", 77)]),
    ("descriptive", "HVAC chiller condenser approach measured 2.6 C.", [("ch5_app", 2.6)]),
    ("descriptive", "The firewater pump's flow test discharge was 68 percent of rated.", [("fp1_press", 68)]),
    ("no_unit", "P-7 seal drip count 22.", [("p7_seal", 22)]),
    ("no_unit", "V-12 closing time 12.9.", [("v12_stroke", 12.9)]),
    ("no_unit", "G-2 tank level 49.", [("g2_tank", 49)]),
    ("noisy", "cp7 brg 83c ok", [("p7_bear", 83)]),
    ("noisy", "T3 toil 95C hmm", [("t3_oil", 95)]),
    ("noisy", "ch-5 apprch 3.0c", [("ch5_app", 3.0)]),
    ("noisy", "fp-1 dischrg 64 pct rated", [("fp1_press", 64)]),
    ("mixed_lang", "Coolant pump P-7 ka vibration 4.6 mm/s hai.", [("p7_vib", 4.6)]),
    ("mixed_lang", "V-12 close avvadaniki 11.0 seconds pattindi.", [("v12_stroke", 11.0)]),
    ("mixed_lang", "Transformer T-3 oil 94 C undi, normal.", [("t3_oil", 94)]),
    # code-like distractors that are not equipment
    ("distractor", "WO-7781 closed: P-7 vibration 3.3 mm/s after alignment.", [("p7_vib", 3.3)]),
    ("distractor", "Panel PNL-12, breaker CB-4: T-3 top-oil 97 C.", [("t3_oil", 97)]),
    ("distractor", "Part SK-220 fitted; P-7 seal leakage now 8 drops/min.", [("p7_seal", 8)]),
    ("distractor", "Tag TI-305 on G-2 reads day tank 52 percent.", [("g2_tank", 52)]),
    ("distractor", "Permit PTW-0912 issued; V-12 stroke time 12.2 s.", [("v12_stroke", 12.2)]),
    ("distractor", "Ref drawing DWG-3301: CH-5 approach 3.6 C.", [("ch5_app", 3.6)]),
    # multi
    ("multi", "P-7 vibration 7.3 mm/s, seal 15 drops/min.", [("p7_vib", 7.3), ("p7_seal", 15)]),
    ("multi", "G-2 day tank 90 percent; FP-1 flow-test discharge 60 percent of rated.", [("g2_tank", 90), ("fp1_press", 60)]),
    ("multi", "T-3 top oil 91 C, CH-5 approach 2.1 C.", [("t3_oil", 91), ("ch5_app", 2.1)]),
    # conversion
    ("conversion", "P-7 bearing 176 F.", [("p7_bear", 80)]),  # 176 F = 80 C
    ("conversion", "V-12 stroke 13500 ms.", [("v12_stroke", 13.5)]),
    # abstain: unknown equipment
    ("abstain_unknown_equipment", "Pump P-17 vibration 9.0 mm/s.", []),
    ("abstain_unknown_equipment", "Transformer T-30 top oil 108 C.", []),
    ("abstain_unknown_equipment", "Generator G-12 day tank 25 percent.", []),
    ("abstain_unknown_equipment", "Boiler feed pump BFP-2 bearing 95 C.", []),
    ("abstain_unknown_equipment", "Chiller CH-6 approach 5.0 C.", []),
    ("abstain_unknown_equipment", "Valve V-120 stroke 18 s.", []),
    ("abstain_unknown_equipment", "Instrument air dryer vibration 8.4 mm/s.", []),
    # abstain: no value / ambiguous
    ("abstain_no_value", "P-7 seal looks wet, will monitor.", []),
    ("abstain_no_value", "T-3 Buchholz relay tested OK.", []),
    ("abstain_no_value", "FP-1 churn test done, sounded fine.", []),
    ("abstain_ambiguous", "P-7 value 22 this morning.", []),
    ("abstain_ambiguous", "Reading on the transformer: 3.", []),
    ("abstain_ambiguous", "G-2 at 70 something.", []),
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
    for d in ("maintenance-priority-v2", "hard-reports-v3"):
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
         "categories": cats, "label_counts": labels, "text_overlap_with_v2_v3": sum(t in seen for t in texts),
         "provenance": "hand-authored before iteration-2b methods were designed; held-out"}
    json.dump(m, open(os.path.join(out_dir, "MANIFEST.json"), "w"), indent=2, sort_keys=True)
    print(json.dumps(m, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
