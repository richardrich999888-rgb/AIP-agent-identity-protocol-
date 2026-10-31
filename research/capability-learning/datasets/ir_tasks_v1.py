"""Learning-without-fine-tuning task family v1: motor insulation-resistance
(IR) acceptance at a synthetic organisation.

Frozen BEFORE any capability learner, proposer or controller code existed
(2026-10-31). Single author (the system builder) — a stated limitation; the
unseen set was written in a different session pass from the demonstrations
and with deliberately different phrasing, value ranges and unit spellings.

Organisation and content are fictional ("Koravi Process Industries",
"Tarvel Grid"). Nothing here describes a real company or a real standard;
the thresholds are invented and differ on purpose from IEEE 43.

The REFERENCE ORACLE below (`reference_decision`) exists only to label data.
The capability learner must never import this module (enforced by
tests/test_isolation.py in the runtime). The learner sees only what an
organisation would give it: the procedure document text, the expert
demonstrations and the expert-authored validation suite.

Usage: python3 -I ir_tasks_v1.py OUT_DIR
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass

VERSION = "ir-tasks-v1"
DECISIONS = ("PASS", "RETEST_30D", "DRY_OUT", "REJECT", "INVALID_TEST", "OUT_OF_SCOPE", "INSUFFICIENT_INPUT")

# ── Organisation documents (Sovereign ingest format: tenant|doc_id|class|title) ──

KORAVI_EP114 = """koravi-process|ep-114|restricted|EP-114 rev C Motor winding insulation resistance acceptance
Koravi Process Industries engineering procedure EP-114 revision C. Confidential.
Scope: induction motors rated up to and including 11 kV. This procedure does not apply to transformers, cables, generators or motors rated above 11 kV; such requests are out of scope and must be referred to the electrical authority.
Required inputs: motor rated voltage in kV, measured insulation resistance in megohms, winding temperature in degrees Celsius at the time of test, and polarization index (PI). If any input is missing the result is insufficient input and the test must be repeated with full records.
Step 1 validity: the winding temperature must be between 10 and 75 degrees Celsius inclusive. Outside that range the test is invalid and must be repeated.
Step 2 temperature correction: correct the measured resistance to 40 degrees Celsius by multiplying it by two raised to the power of (winding temperature minus 40) divided by 10.
Step 3 minimum: the minimum acceptable corrected resistance is 10 times (rated kV plus 1) megohms.
Step 4 decision: if the corrected resistance is below half of the minimum, reject the motor for rewind. If it is below the minimum, dry out the winding and retest. If the resistance is acceptable but PI is below 1.5, dry out. If PI is at least 1.5 but below 2.0, accept for service with a retest in 30 days. Otherwise pass.
"""

KORAVI_OTHER = """koravi-process|ep-090|internal|EP-090 Motor storage and handling
Koravi Process Industries procedure EP-090. Motors in storage must have space heaters energised and shafts rotated monthly. Insulation resistance testing instruments are calibrated annually by the instrument workshop. Test records are kept in the maintenance system for ten years.
"""

# A second tenant with a conflicting procedure: used to test that neither its
# document nor any capability learned from it reaches Koravi principals, and
# vice versa.
TARVEL_IR = """tarvel-grid|tg-ir-02|restricted|TG-IR-02 Insulation resistance limits
Tarvel Grid procedure TG-IR-02. Confidential. Minimum insulation resistance is 100 megohms for all motors regardless of voltage, with no temperature correction. PI below 2.5 requires dry out.
"""


@dataclass(frozen=True)
class Case:
    """One task. Values are the physical inputs; None = absent from the text."""
    text: str
    kv: float | None
    ir_mohm: float | None
    temp_c: float | None
    pi: float | None
    equipment: str = "motor"  # motor | transformer | cable | generator


def reference_decision(c: Case) -> str:
    """Oracle for EP-114 rev C. Labels only; never imported by the learner."""
    if c.equipment != "motor" or (c.kv is not None and c.kv > 11.0):
        return "OUT_OF_SCOPE"
    if None in (c.kv, c.ir_mohm, c.temp_c, c.pi):
        return "INSUFFICIENT_INPUT"
    if not (10.0 <= c.temp_c <= 75.0):
        return "INVALID_TEST"
    ir40 = c.ir_mohm * 2 ** ((c.temp_c - 40.0) / 10.0)
    ir_min = 10.0 * (c.kv + 1.0)
    if ir40 < 0.5 * ir_min:
        return "REJECT"
    if ir40 < ir_min:
        return "DRY_OUT"
    if c.pi < 1.5:
        return "DRY_OUT"
    if c.pi < 2.0:
        return "RETEST_30D"
    return "PASS"


# ── Phase B: expert demonstrations (with the expert's working) ──────────────
DEMOS = [
    (Case("Motor M-101 rated 6.6 kV: IR 220 megohms at 40 C, PI 2.4. Decision?", 6.6, 220, 40, 2.4),
     "corrected 220; minimum 76; PI 2.4 >= 2.0 -> PASS"),
    (Case("M-114, 3.3 kV. Megger 30 megohm, winding 50 C, PI 2.1.", 3.3, 30, 50, 2.1),
     "corrected 30*2^1 = 60; minimum 43; PI 2.1 -> PASS"),
    (Case("Motor M-122 (11 kV) IR 70 megohms at 30 C, PI 1.8.", 11, 70, 30, 1.8),
     "corrected 70*2^-1 = 35; minimum 120; 35 < 60 -> REJECT"),
    (Case("M-131 at 0.415 kV: 15 megohms, 40 C, PI 1.7", 0.415, 15, 40, 1.7),
     "corrected 15; minimum 14.15; PI 1.7 in [1.5, 2.0) -> RETEST_30D"),
    (Case("6.6 kV motor M-140, insulation 60 megohms at 45 C, PI 2.2", 6.6, 60, 45, 2.2),
     "corrected 60*2^0.5 = 84.9; minimum 76; PI 2.2 -> PASS"),
    (Case("Motor M-150 rated 3.3 kV measured 40 megohms at 80 C with PI 2.0", 3.3, 40, 80, 2.0),
     "80 C is outside 10..75 -> INVALID_TEST"),
]

# ── Phase C: expert-authored validation suite (boundaries + counterexamples) ──
VALIDATION = [
    Case("M-201 6.6 kV, 76 megohms at 40 C, PI 2.0", 6.6, 76, 40, 2.0),         # exactly minimum, PI exactly 2.0
    Case("M-202 6.6 kV, 75.9 megohms at 40 C, PI 2.5", 6.6, 75.9, 40, 2.5),     # just below minimum
    Case("M-203 6.6 kV, 38 megohms at 40 C, PI 2.5", 6.6, 38, 40, 2.5),         # exactly half minimum -> DRY_OUT
    Case("M-204 6.6 kV, 37.9 megohms at 40 C, PI 2.5", 6.6, 37.9, 40, 2.5),     # below half -> REJECT
    Case("M-205 3.3 kV, 100 megohms at 40 C, PI 1.5", 3.3, 100, 40, 1.5),       # PI exactly 1.5
    Case("M-206 3.3 kV, 100 megohms at 40 C, PI 1.49", 3.3, 100, 40, 1.49),
    Case("M-207 3.3 kV, 100 megohms at 75 C, PI 2.2", 3.3, 100, 75, 2.2),       # temp exactly 75
    Case("M-208 3.3 kV, 100 megohms at 9 C, PI 2.2", 3.3, 100, 9, 2.2),
    Case("M-209 11 kV, 500 megohms at 40 C, PI 2.3", 11, 500, 40, 2.3),         # exactly 11 kV
    Case("M-210 13.8 kV, 900 megohms at 40 C, PI 2.6", 13.8, 900, 40, 2.6),     # out of scope
    Case("Transformer TR-3 HV winding 400 megohms at 40 C, PI 2.2", None, 400, 40, 2.2, "transformer"),
    Case("M-211 6.6 kV, 150 megohms at 40 C, PI not recorded", 6.6, 150, 40, None),
    Case("M-212 0.415 kV, 6 megohms at 20 C, PI 2.1", 0.415, 6, 20, 2.1),       # corrected 1.5 < 7.07 -> REJECT
    Case("M-213 3.3 kV, 25 megohms at 60 C, PI 1.9", 3.3, 25, 60, 1.9),         # corrected 100 -> RETEST
]

# ── Phase D: unseen test set (different phrasing, values, unit spellings) ──
TEST = [
    Case("Can we put the 6.6 kV ID fan motor back in service? Megger gave 180 MΩ at 35 °C, PI 2.6.", 6.6, 180, 35, 2.6),
    Case("Cooling tower fan motor CT-F2, 0.415 kV: 9 MΩ measured, winding at 28 °C, PI 2.3.", 0.415, 9, 28, 2.3),
    Case("BFW pump motor 3.3kV — IR 18 Mohm @ 55C, polarisation index 2.4", 3.3, 18, 55, 2.4),
    Case("Agitator motor 0.69 kV insulation 12 Mohm at 41 C PI 1.6", 0.69, 12, 41, 1.6),
    Case("HT motor 11kV crusher drive: 300 megohm, 42 degC, PI 1.9", 11, 300, 42, 1.9),
    Case("Conveyor motor 3.3 kV IR 21 Mohm at 30 C, PI 2.2", 3.3, 21, 30, 2.2),
    Case("6.6 kV compressor motor: 33 megohms at 40 C, PI 2.7 - accept?", 6.6, 33, 40, 2.7),
    Case("Motor feeding mill 2, 6.6 kV, 120 MΩ at 62 °C, PI 1.4", 6.6, 120, 62, 1.4),
    Case("LV motor 0.415 kV, 4 megohm at 33 C, PI 2.0", 0.415, 4, 33, 2.0),
    Case("Primary air fan motor 11 kV, IR 95 Mohm at 48 C, PI 2.3", 11, 95, 48, 2.3),
    Case("Ash slurry pump motor 3.3 kV: 46 MΩ, 40 °C, PI 1.5", 3.3, 46, 40, 1.5),
    Case("Kiln drive motor 6.6 kV 70 megohms 52C PI 2.1", 6.6, 70, 52, 2.1),
    Case("Boiler feed motor at 6.6 kV: megger 25 MΩ, winding temperature 70 °C, PI 2.2", 6.6, 25, 70, 2.2),
    Case("Spare motor from store, 3.3 kV, 8 megohms at 15 C, PI 2.5", 3.3, 8, 15, 2.5),
    Case("Raw water pump motor 0.415 kV, 30 Mohm at 12 C, PI 2.8", 0.415, 30, 12, 2.8),
    Case("Induced draft fan motor, 11 kV rating, 61 MΩ at 40 °C, PI 2.0", 11, 61, 40, 2.0),
    Case("Motor M-7 3.3 kV after flooding: 5 megohms at 30 C, PI 1.1", 3.3, 5, 30, 1.1),
    Case("Coal mill motor 6.6kV IR 160Mohm temp 78C PI 2.4", 6.6, 160, 78, 2.4),
    Case("Sea water pump motor 3.3 kV, 52 megohms at 8 C, PI 2.2", 3.3, 52, 8, 2.2),
    Case("15 kV synchronous motor: 2000 megohms at 40 C, PI 3.0", 15, 2000, 40, 3.0),
    Case("Generator G-2 stator: IR 500 megohms at 40 C, PI 2.5", None, 500, 40, 2.5, "generator"),
    Case("HV cable to feeder 4: 1200 MΩ at 30 °C, PI 2.1", None, 1200, 30, 2.1, "cable"),
    Case("Transformer T-3 LV winding megger 350 megohm at 45 C, PI 1.8", None, 350, 45, 1.8, "transformer"),
    Case("Motor 6.6 kV, IR 140 megohms at 40 C — PI test not done yet", 6.6, 140, 40, None),
    Case("Motor 3.3 kV PI 2.3 at 40 C, resistance reading lost", 3.3, None, 40, 2.3),
    Case("Fan motor IR 80 megohms at 40 C, PI 2.2 (rating plate unreadable)", None, 80, 40, 2.2),
    Case("Pump motor 0.415 kV, 1.2 GΩ at 40 °C, PI 2.4", 0.415, 1200, 40, 2.4),
    Case("Blower motor 415 V: 10 megohms at 40 C, PI 1.8", 0.415, 10, 40, 1.8),
    Case("Motor 3.3 kV: 60 MΩ at 104 °F, PI 2.1", 3.3, 60, 40, 2.1),
    Case("Mixer motor 6.6 kV IR 0.09 GΩ at 50 °C PI 1.7", 6.6, 90, 50, 1.7),
    Case("Condensate pump motor 3.3 kV, 43 megohms at 40 C, PI 1.99", 3.3, 43, 40, 1.99),
    Case("Stacker motor 6.6 kV, IR 37 megohms at 39 C, PI 2.2", 6.6, 37, 39, 2.2),
]

# ── False-activation probes: mention IR testing but are not an EP-114 decision ──
FALSE_ACTIVATION = [
    "Which instrument do we use for insulation resistance testing?",
    "How long are IR test records kept?",
    "Who calibrates the megger?",
    "When is the next insulation test due for motor M-101?",
    "Explain what polarization index means.",
    "What is the vibration limit for coolant pump P-7?",
    "Summarise EP-090 for a new technician.",
    "Is the 6.6 kV motor on the crusher drive running hot today?",
]


def _rows(cases, prefix):
    out = []
    for i, c in enumerate(cases):
        out.append({"id": f"{prefix}-{i:03d}", "text": c.text, "equipment": c.equipment,
                    "inputs": {"kv": c.kv, "ir_mohm": c.ir_mohm, "temp_c": c.temp_c, "pi": c.pi},
                    "label": reference_decision(c)})
    return out


def main(out_dir: str) -> None:
    os.makedirs(os.path.join(out_dir, "corpus"), exist_ok=True)
    files = {}
    for name, body in (("koravi-ep-114.txt", KORAVI_EP114), ("koravi-ep-090.txt", KORAVI_OTHER), ("tarvel-tg-ir-02.txt", TARVEL_IR)):
        p = os.path.join(out_dir, "corpus", name)
        open(p, "w").write(body)
        files[f"corpus/{name}"] = p
    demos = _rows([c for c, _ in DEMOS], "demo")
    for r, (_, work) in zip(demos, DEMOS):
        r["expert_working"] = work
    sets = {"demos.jsonl": demos, "validation.jsonl": _rows(VALIDATION, "val"), "test_unseen.jsonl": _rows(TEST, "test"),
            "false_activation.jsonl": [{"id": f"fa-{i:03d}", "text": t, "label": "NOT_APPLICABLE"} for i, t in enumerate(FALSE_ACTIVATION)]}
    texts = [r["text"] for rows in sets.values() for r in rows]
    assert len(set(texts)) == len(texts), "duplicate task text"
    for name, rows in sets.items():
        p = os.path.join(out_dir, name)
        with open(p, "w") as f:
            for r in rows:
                assert r["label"] in DECISIONS + ("NOT_APPLICABLE",)
                f.write(json.dumps(r, sort_keys=True) + "\n")
        files[name] = p
    manifest = {"version": VERSION, "sha256": {k: hashlib.sha256(open(p, "rb").read()).hexdigest() for k, p in sorted(files.items())},
                "counts": {k: len(v) for k, v in sets.items()},
                "label_counts": {k: {d: sum(r["label"] == d for r in v) for d in sorted({r["label"] for r in v})} for k, v in sets.items()},
                "provenance": "hand-authored before any learner/controller code; single author; fictional organisations"}
    json.dump(manifest, open(os.path.join(out_dir, "MANIFEST.json"), "w"), indent=2, sort_keys=True)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
