"""Hand-authored hard operator reports (v3). NOT template-generated.

Each item is written individually. Gold annotation is the list of readings the
report actually states, as (metric_key, value in the policy's unit), or an
empty list when the report contains no reading the policy covers. The decision
label is the SOP policy applied to the gold readings (the policy *is* the
organisation's rule); an empty gold list means the correct output is ABSTAIN.

Categories (each item has one primary category):
  no_unit        value given without a unit
  descriptive    equipment described, not coded ("the coolant pump")
  noisy          typos / abbreviations / shorthand
  mixed_lang     Hinglish / Telugu-English phrasing
  distractor     other numbers present (times, work orders, counts)
  conversion     value in another unit; gold value is converted
  multi          several readings; decision = most urgent
  abstain_unknown_equipment   equipment the policy does not cover
  abstain_no_value            no numeric reading at all
  abstain_ambiguous           cannot tell which quantity

Provenance: authored 2026-10-31 by the system builder (Claude), so this is
*independent of the generator and rule table*, not independent of the
builder. A human-authored set remains a gap.

Usage: python3 -I hard_reports_v3.py OUT_DIR   (writes test_hard.jsonl + MANIFEST.json)
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datasets.maintenance_priority import METRICS, priority  # noqa: E402

VERSION = "hard-reports-v3"
M = {m.key: m for m in METRICS}

# (category, text, gold readings)
ITEMS = [
    # ── no_unit ─────────────────────────────────────────────────────────
    ("no_unit", "P-7 vibration is 8.3 now, getting worse since morning.", [("p7_vib", 8.3)]),
    ("no_unit", "Checked P-7 bearing temp, reads 79.", [("p7_bear", 79)]),
    ("no_unit", "P-7 seal is leaking about 26 per minute.", [("p7_seal", 26)]),
    ("no_unit", "T-3 top oil at 98 on the dial.", [("t3_oil", 98)]),
    ("no_unit", "V-12 took 14.2 to stroke fully closed.", [("v12_stroke", 14.2)]),
    ("no_unit", "G-2 day tank shows 64.", [("g2_tank", 64)]),
    ("no_unit", "CH-5 approach is 2.4 today.", [("ch5_app", 2.4)]),
    ("no_unit", "FP-1 flow test outlet came out at 71 of rated.", [("fp1_press", 71)]),
    ("no_unit", "P-7 vib 3.9, all normal.", [("p7_vib", 3.9)]),
    ("no_unit", "T-3 oil top reading 107, alarm panel flashing.", [("t3_oil", 107)]),
    # ── descriptive ─────────────────────────────────────────────────────
    ("descriptive", "The main coolant pump is shaking at 7.4 mm/s on the outboard bearing housing.", [("p7_vib", 7.4)]),
    ("descriptive", "Bearing on the coolant circulation pump measured 88 degrees with the IR gun.", [("p7_bear", 88)]),
    ("descriptive", "The big transformer in the yard has hot oil at the top, 93 C.", [("t3_oil", 93)]),
    ("descriptive", "The isolation valve on the main header needed 11.5 s to go fully shut.", [("v12_stroke", 11.5)]),
    ("descriptive", "Standby diesel genset day tank is down to 46 percent.", [("g2_tank", 46)]),
    ("descriptive", "The chiller's condenser approach crept up to 3.4 C.", [("ch5_app", 3.4)]),
    ("descriptive", "During the fire pump flow test the outlet pressure only reached 61 percent of rated.", [("fp1_press", 61)]),
    ("descriptive", "Packing on the coolant pump is dripping 12 drops per minute.", [("p7_seal", 12)]),
    ("descriptive", "Yard transformer top oil steady at 89 C.", [("t3_oil", 89)]),
    # ── noisy ───────────────────────────────────────────────────────────
    ("noisy", "p7 vibr 5.2mms pls chk", [("p7_vib", 5.2)]),
    ("noisy", "brg tmp p-7 = 86C!!", [("p7_bear", 86)]),
    ("noisy", "P7 sel leek 18 dpm", [("p7_seal", 18)]),
    ("noisy", "TX3 tp oil 104c", [("t3_oil", 104)]),
    ("noisy", "v-12 strk tme 12.6sec", [("v12_stroke", 12.6)]),
    ("noisy", "gen2 dy tnk 79pct", [("g2_tank", 79)]),
    ("noisy", "ch5 aprch 2.9 deg", [("ch5_app", 2.9)]),
    ("noisy", "fp1 flw tst disch 66%", [("fp1_press", 66)]),
    ("noisy", "P-7 vibs ~7.0 mm/s rms", [("p7_vib", 7.0)]),
    ("noisy", "tranformer T-3 oil temprature 96 C", [("t3_oil", 96)]),
    # ── mixed_lang ──────────────────────────────────────────────────────
    ("mixed_lang", "P-7 pump bahut vibrate kar raha hai, 7.8 mm/s aa raha hai.", [("p7_vib", 7.8)]),
    ("mixed_lang", "T-3 ka top oil 101 C ho gaya hai, dekh lo.", [("t3_oil", 101)]),
    ("mixed_lang", "G-2 day tank lo diesel 55 percent undi.", [("g2_tank", 55)]),
    ("mixed_lang", "FP-1 test lo discharge pressure 63 percent of rated vachindi.", [("fp1_press", 63)]),
    ("mixed_lang", "P-7 bearing garam hai, 91 degree dikha raha.", [("p7_bear", 91)]),
    ("mixed_lang", "CH-5 approach 3.1 C undi, condenser clean cheyyali emo.", [("ch5_app", 3.1)]),
    ("mixed_lang", "V-12 band hone mein 9.8 second laga.", [("v12_stroke", 9.8)]),
    ("mixed_lang", "P-7 seal se 31 drops per minute tapak raha hai.", [("p7_seal", 31)]),
    # ── distractor ──────────────────────────────────────────────────────
    ("distractor", "At 14:30 on WO-55821, P-7 vibration read 6.8 mm/s; 3 technicians present.", [("p7_vib", 6.8)]),
    ("distractor", "Shift 2 of 3: T-3 top-oil 92 C, ambient 41 C, load 75 percent.", [("t3_oil", 92)]),
    ("distractor", "Ticket 4471: G-2 day tank 83 percent after the 2,000 litre delivery.", [("g2_tank", 83)]),
    ("distractor", "V-12 stroke time 13.4 s measured on 12 March, valve tag 12-B.", [("v12_stroke", 13.4)]),
    ("distractor", "Round 7 at 06:15 - CH-5 approach 2.2 C, chilled water 6.5 C.", [("ch5_app", 2.2)]),
    ("distractor", "FP-1 flow test #2 of 2: discharge 58 percent of rated at 150 percent flow.", [("fp1_press", 58)]),
    ("distractor", "Bay 9, panel 4: P-7 bearing 84 C, motor current 37 A.", [("p7_bear", 84)]),
    ("distractor", "P-7 seal leakage 21 drops/min, last replaced 18 months ago.", [("p7_seal", 21)]),
    ("distractor", "2 readings taken 5 minutes apart; final P-7 vibration 4.4 mm/s.", [("p7_vib", 4.4)]),
    # ── conversion ──────────────────────────────────────────────────────
    ("conversion", "P-7 vibration 0.3 in/s on the handheld.", [("p7_vib", 7.6)]),  # 0.3 in/s = 7.62 mm/s
    ("conversion", "T-3 top-oil 225 F on the old gauge.", [("t3_oil", 107)]),  # 225 F = 107.2 C
    ("conversion", "V-12 full stroke took 900 ms.", [("v12_stroke", 0.9)]),
    ("conversion", "P-7 bearing 194 F by thermography.", [("p7_bear", 90)]),  # 194 F = 90 C
    # ── multi ───────────────────────────────────────────────────────────
    ("multi", "P-7: vibration 3.2 mm/s, bearing 82 C, seal 24 drops/min.", [("p7_vib", 3.2), ("p7_bear", 82), ("p7_seal", 24)]),
    ("multi", "Walkdown: T-3 top oil 90 C and G-2 day tank 45 percent.", [("t3_oil", 90), ("g2_tank", 45)]),
    ("multi", "CH-5 approach 3.3 C; V-12 stroke 10.1 s.", [("ch5_app", 3.3), ("v12_stroke", 10.1)]),
    ("multi", "FP-1 outlet 70 percent of rated, P-7 vibration 7.5 mm/s.", [("fp1_press", 70), ("p7_vib", 7.5)]),
    ("multi", "G-2 tank 81 percent, T-3 oil 99 C.", [("g2_tank", 81), ("t3_oil", 99)]),
    ("multi", "P-7 seal 10 drops/min and bearing 87 C.", [("p7_seal", 10), ("p7_bear", 87)]),
    # ── abstain: unknown equipment ──────────────────────────────────────
    ("abstain_unknown_equipment", "P-9 vibration 9.1 mm/s, very rough.", []),
    ("abstain_unknown_equipment", "Transformer T-4 top-oil 110 C.", []),
    ("abstain_unknown_equipment", "Valve V-21 stroke time 15 s.", []),
    ("abstain_unknown_equipment", "Generator G-5 day tank 30 percent.", []),
    ("abstain_unknown_equipment", "Chiller CH-2 approach 4.2 C.", []),
    ("abstain_unknown_equipment", "Air compressor AC-7 discharge 115 C.", []),
    ("abstain_unknown_equipment", "Cooling tower fan CT-1 vibration 8.0 mm/s.", []),
    ("abstain_unknown_equipment", "Fire pump FP-2 outlet 50 percent of rated.", []),
    # ── abstain: no value ───────────────────────────────────────────────
    ("abstain_no_value", "P-7 sounds rough today, please send someone.", []),
    ("abstain_no_value", "T-3 oil looks dark, sample taken.", []),
    ("abstain_no_value", "G-2 day tank gauge is broken, could not read.", []),
    ("abstain_no_value", "CH-5 running fine, nothing to report.", []),
    ("abstain_no_value", "V-12 stroked normally.", []),
    ("abstain_no_value", "FP-1 flow test postponed to next week.", []),
    # ── abstain: ambiguous quantity ─────────────────────────────────────
    ("abstain_ambiguous", "P-7 reading 85.", []),
    ("abstain_ambiguous", "P-7 is at 20 now.", []),
    ("abstain_ambiguous", "Pump reading 7.3.", []),
    ("abstain_ambiguous", "Something on the coolant pump is at 6.", []),
]


def decision(gold: list) -> str:
    if not gold:
        return "ABSTAIN"
    return str(min(priority(M[k], v) for k, v in gold))


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for i, (cat, text, gold) in enumerate(ITEMS):
        for k, _ in gold:
            assert k in M, k
        rows.append({"id": f"hard-{i:03d}", "category": cat, "text": text,
                     "gold_readings": [[k, v] for k, v in gold], "label": decision(gold)})
    texts = [r["text"] for r in rows]
    assert len(set(texts)) == len(texts), "duplicate text"
    p = os.path.join(out_dir, "test_hard.jsonl")
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    cats, labels = {}, {}
    for r in rows:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
        labels[r["label"]] = labels.get(r["label"], 0) + 1
    # Contamination check against every v2 split.
    v2 = os.path.join(os.path.dirname(out_dir), "maintenance-priority-v2")
    overlap = 0
    if os.path.isdir(v2):
        seen = {json.loads(l)["text"] for f in os.listdir(v2) if f.endswith(".jsonl") for l in open(os.path.join(v2, f))}
        overlap = sum(t in seen for t in texts)
    manifest = {"version": VERSION, "n": len(rows), "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(),
                "categories": cats, "label_counts": labels, "text_overlap_with_v2": overlap,
                "provenance": "hand-authored item by item by the system builder; not template-generated; frozen before any method was run on it"}
    with open(os.path.join(out_dir, "MANIFEST.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
