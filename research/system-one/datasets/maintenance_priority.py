"""Synthetic maintenance-priority decision dataset (versioned, seeded).

Task: given a free-text operator report, output the priority the plant SOPs
require:
    1 = immediate shutdown / isolate      (P1)
    2 = act within 48 hours               (P2)
    3 = act within one week / inspect     (P3)
    4 = no action                         (P4)

Ground truth is computed from the SOP threshold table below, never by a model.
A report with several readings takes the most urgent one (minimum priority
number).

Splits
------
train / val / test_id  : templates T_ID, single reading per report, values
                         drawn from the same distribution, disjoint seeds.
test_para              : metric names replaced by paraphrases that occur nowhere
                         else (not in SOP_TEXT, train or val); single reading.
test_ood               : templates T_OOD (never used in train/val/test_id),
                         compact/abbreviated equipment names, numbers written
                         without spaces before units, irrelevant chatter, and
                         2–3 readings per report. Measures generalisation,
                         not memorisation.

Values are drawn with 50 % mass within ±15 % of a threshold so that the task
cannot be solved by coarse magnitude alone.

Usage: python3 -I maintenance_priority.py OUT_DIR
Writes {train,val,test_id,test_ood}.jsonl and MANIFEST.json (sha256 per file,
generator version, seed, class counts, contamination checks).
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
from dataclasses import dataclass

VERSION = "maintenance-priority-v2"
SEED = 20261031
SIZES = {"train": 1200, "val": 300, "test_id": 300, "test_ood": 300, "test_para": 300}


@dataclass(frozen=True)
class Metric:
    """One monitored quantity and its SOP rule.

    `bands` is an ordered list of (upper_bound_exclusive, priority); the last
    band's bound is +inf. `aliases` are the equipment spellings used in
    in-distribution text; `ood_aliases` appear only in test_ood.
    """

    key: str
    equipment: str
    name: str
    unit: str
    lo: float
    hi: float
    decimals: int
    bands: tuple
    aliases: tuple
    ood_aliases: tuple
    ood_unit: str


INF = float("inf")
METRICS = (
    Metric("p7_vib", "P-7", "vibration", "mm/s", 1.0, 10.0, 1, ((4.5, 4), (7.1, 3), (INF, 1)), ("coolant pump P-7", "pump P-7"), ("P7 pump", "cp-7"), "mm/s rms"),
    Metric("p7_bear", "P-7", "bearing temperature", "C", 50, 110, 0, ((85.0001, 4), (INF, 1)), ("coolant pump P-7", "pump P-7"), ("P7 brg", "cp-7 bearing"), "degC"),
    Metric("p7_seal", "P-7", "seal leakage", "drops/min", 0, 40, 0, ((20.0001, 4), (INF, 2)), ("coolant pump P-7", "pump P-7"), ("P7 seal", "cp-7 gland"), "dpm"),
    Metric("t3_oil", "T-3", "top-oil temperature", "C", 60, 120, 0, ((95, 4), (105, 2), (INF, 1)), ("transformer T-3", "T-3"), ("xfmr T3", "TX-3 unit"), "degC"),
    Metric("v12_stroke", "V-12", "full stroke time", "s", 5, 20, 1, ((12.0001, 4), (INF, 3)), ("valve V-12", "isolation valve V-12"), ("V12", "iso vlv 12"), "sec"),
    Metric("g2_tank", "G-2", "day tank level", "%", 20, 100, 0, ((50, 1), (80, 2), (INF, 4)), ("generator G-2", "standby generator G-2"), ("gen 2", "G2 genset"), "pct"),
    Metric("ch5_app", "CH-5", "condenser approach", "C", 1.0, 6.0, 1, ((3.0, 4), (INF, 3)), ("chiller CH-5", "CH-5"), ("ch5", "chiller 5"), "degC"),
    Metric("fp1_press", "FP-1", "flow-test discharge pressure", "% of rated", 40, 100, 0, ((65, 1), (INF, 4)), ("fire pump FP-1", "FP-1"), ("FP1", "fire pmp 1"), "pct rated"),
)

# The SOP text a model may read. Equivalent to METRICS; kept as prose so a
# language model receives the same knowledge a technician would.
SOP_TEXT = """SOP thresholds:
- Coolant pump P-7 vibration: below 4.5 mm/s no action; 4.5 to 7.1 mm/s inspect within one week; above 7.1 mm/s immediate shutdown.
- Coolant pump P-7 bearing temperature: above 85 C immediate shutdown; otherwise no action.
- Coolant pump P-7 seal leakage: above 20 drops/min replace seal within 48 hours; otherwise no action.
- Transformer T-3 top-oil temperature: below 95 C no action; 95 to 105 C act within 48 hours; 105 C or above immediate trip/isolate.
- Valve V-12 full stroke time: above 12 s actuator inspection within one week; otherwise no action.
- Generator G-2 day tank level: below 50 % immediate action; 50 to 80 % refill within 48 hours; 80 % or above no action.
- Chiller CH-5 condenser approach: 3.0 C or above clean condenser within one week; below 3.0 C no action.
- Fire pump FP-1 flow-test discharge pressure: below 65 % of rated immediate action (pump impaired); 65 % or above no action.
Priorities: 1 = immediate, 2 = within 48 hours, 3 = within one week, 4 = no action."""

T_ID = (
    "Operator round: {eq} {name} reading {val} {unit}.",
    "Shift log entry - {eq} {name} measured at {val} {unit}.",
    "During the walkdown the {name} on {eq} was {val} {unit}.",
    "{eq}: {name} = {val} {unit} recorded by the field technician.",
    "Routine check of {eq}. {name} {val} {unit}. No other remarks.",
    "Reported by control room: {name} of {eq} now {val} {unit}.",
)
T_OOD = (
    "fyi {eq} {name} at {val}{unit}, {chatter}",
    "{chatter} also noticed {eq} {name} {val}{unit} on the local gauge",
    "Night shift handover. {chatter} {eq} -> {name} {val}{unit}. pls review",
)
# Paraphrases of each metric name, used ONLY in test_para. They never occur
# in train/val/test_id/test_ood or in SOP_TEXT, so keyword matching on the
# SOP vocabulary cannot succeed by construction.
PARAPHRASE = {
    "p7_vib": ("shake level", "vibration velocity reading", "how hard it is shaking"),
    "p7_bear": ("brg temp", "bearing housing heat", "bearing running hot at"),
    "p7_seal": ("leak rate at the gland", "drip count from the packing", "gland weeping at"),
    "t3_oil": ("oil temp at the top of the tank", "hot oil reading", "upper oil temp"),
    "v12_stroke": ("open-to-close time", "time to travel fully", "close-off duration"),
    "g2_tank": ("fuel in the day tank", "diesel day tank fill", "day tank contents"),
    "ch5_app": ("condenser approach delta", "approach temp", "condenser temp difference"),
    "fp1_press": ("outlet pressure during the flow test", "discharge head on test", "test outlet pressure"),
}
T_PARA = (
    "Field note: {eq} {name} {val} {unit}.",
    "{eq} - {name} came in at {val} {unit} this morning.",
)

CHATTER = (
    "coffee machine on level 2 still broken.",
    "visitor badge printer jammed again.",
    "rain expected tonight, check drains.",
    "safety walk completed, no findings.",
)


def priority(m: Metric, v: float) -> int:
    """SOP rule for one reading. Bands are [prev_bound, bound)."""
    for bound, p in m.bands:
        if v < bound:
            return p
    raise AssertionError("unreachable: last band is +inf")


def thresholds(m: Metric) -> list:
    return [b for b, _ in m.bands if b != INF]


def sample_value(m: Metric, rng: random.Random) -> float:
    """Half the mass near a threshold (±15 %), half uniform in range."""
    if rng.random() < 0.5:
        t = rng.choice(thresholds(m))
        v = rng.uniform(t * 0.85, t * 1.15)
    else:
        v = rng.uniform(m.lo, m.hi)
    v = min(max(v, m.lo), m.hi)
    return round(v, m.decimals)


def fmt(v: float, decimals: int) -> str:
    return f"{v:.{decimals}f}" if decimals else str(int(round(v)))


def make_id_example(rng: random.Random) -> dict:
    m = rng.choice(METRICS)
    v = sample_value(m, rng)
    text = rng.choice(T_ID).format(eq=rng.choice(m.aliases), name=m.name, val=fmt(v, m.decimals), unit=m.unit)
    return {"text": text, "label": priority(m, v), "readings": [[m.key, v]]}


def make_ood_example(rng: random.Random) -> dict:
    ms = rng.sample(METRICS, rng.choice((1, 2, 3)))
    parts, readings, labels = [], [], []
    for m in ms:
        v = sample_value(m, rng)
        parts.append(rng.choice(T_OOD).format(eq=rng.choice(m.ood_aliases), name=m.name, val=fmt(v, m.decimals), unit=m.ood_unit, chatter=rng.choice(CHATTER)))
        readings.append([m.key, v])
        labels.append(priority(m, v))
    return {"text": " ".join(parts), "label": min(labels), "readings": readings}


def make_para_example(rng: random.Random) -> dict:
    m = rng.choice(METRICS)
    v = sample_value(m, rng)
    text = rng.choice(T_PARA).format(eq=rng.choice(m.aliases), name=rng.choice(PARAPHRASE[m.key]), val=fmt(v, m.decimals), unit=m.unit)
    return {"text": text, "label": priority(m, v), "readings": [[m.key, v]]}


def generate() -> dict:
    """Deterministically generate all splits. Exact-text duplicates within a
    split are allowed to arise naturally; across splits they are removed from
    the later split (train has priority) so no test text is seen in training."""
    seen: set = set()
    out = {}
    for i, (split, n) in enumerate(SIZES.items()):
        rng = random.Random(SEED * 10 + i)
        rows = []
        while len(rows) < n:
            if split == "test_ood":
                ex = make_ood_example(rng)
            elif split == "test_para":
                ex = make_para_example(rng)
            else:
                ex = make_id_example(rng)
            if ex["text"] in seen:
                continue
            rows.append({"id": f"{split}-{len(rows):04d}", **ex})
        seen.update(r["text"] for r in rows)
        out[split] = rows
    return out


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    data = generate()
    manifest = {"version": VERSION, "seed": SEED, "sizes": SIZES, "files": {}, "class_counts": {}, "checks": {}}
    for split, rows in data.items():
        p = os.path.join(out_dir, f"{split}.jsonl")
        with open(p, "w") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        manifest["files"][split] = sha256_file(p)
        counts = {str(k): sum(r["label"] == k for r in rows) for k in (1, 2, 3, 4)}
        manifest["class_counts"][split] = counts
    texts = {s: {r["text"] for r in rows} for s, rows in data.items()}
    manifest["checks"]["cross_split_text_overlap"] = {
        f"{a}&{b}": len(texts[a] & texts[b]) for a in texts for b in texts if a < b
    }
    manifest["checks"]["ood_templates_disjoint_from_id"] = not (set(T_ID) & set(T_OOD))
    para_words = {w for names in PARAPHRASE.values() for w in names}
    manifest["checks"]["paraphrases_absent_from_sop_and_training"] = not any(
        w in SOP_TEXT or any(w in r["text"] for r in data["train"] + data["val"]) for w in para_words
    )
    manifest["sop_text_sha256"] = hashlib.sha256(SOP_TEXT.encode()).hexdigest()
    with open(os.path.join(out_dir, "MANIFEST.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
