"""Interpretation-only extractors. Each returns a list of (metric_key, value)
readings, or [] to abstain. The SOP policy is applied afterwards, identically
for every extractor, so only interpretation differs between methods.

E1  rules_vocab   SOP metric names + first standalone number (iteration-1 symbolic)
E1b rules_equnit  equipment code + exact unit string → metric (P0 audit baseline)
E2  tfidf_clf     TF-IDF+LR quantity classifier trained on v2 train
E3  bge_clf       frozen BAAI/bge-small-en-v1.5 (ONNX, 33M params) + LR head, v2 train
E4  llm_json      Qwen2.5 JSON extraction with an explicit empty-list abstention
                  (see llm_extract_v2)

E2/E3 are single-label classifiers trained only on single-reading template
text: they cannot represent "no covered reading" or several readings. Their
abstention rule (fixed before evaluation, not tuned): abstain when the top
class probability < ABSTAIN_BELOW or when the value picker finds no number.
"""
from __future__ import annotations

import re

import numpy as np

from datasets.maintenance_priority import METRICS
from methods import symbolic

ABSTAIN_BELOW = 0.5
KEYS = [m.key for m in METRICS]
BY_KEY = {m.key: m for m in METRICS}

# Unit spellings per metric family for the value picker. Deliberately the
# spellings a technician writes; used identically by E2 and E3.
UNIT_WORDS = {
    "p7_vib": ("mm/s", "mms", "mm"),
    "p7_bear": ("c", "degc", "deg", "degree", "degrees"),
    "p7_seal": ("drops", "dpm", "drops/min", "per"),
    "t3_oil": ("c", "degc", "deg", "degree", "degrees"),
    "v12_stroke": ("s", "sec", "secs", "second", "seconds"),
    "g2_tank": ("%", "pct", "percent"),
    "ch5_app": ("c", "degc", "deg", "degree", "degrees"),
    "fp1_press": ("%", "pct", "percent"),
}
_NUM_UNIT = re.compile(r"(?<![\w.:-])(\d+(?:\.\d+)?)(?![:\d])\s*([a-zA-Z%/]+)?")


def pick_value(text: str, key: str) -> float | None:
    """The reading's value for metric `key`: the only standalone number, or
    the number followed by a unit word of that metric's family. Times (hh:mm)
    and numbers glued to codes are excluded by the pattern."""
    cands = [(float(n), (u or "").lower()) for n, u in _NUM_UNIT.findall(text)]
    if len(cands) == 1:
        return cands[0][0]
    fam = UNIT_WORDS[key]
    hits = [v for v, u in cands if u and any(u == w or u.startswith(w) for w in fam)]
    return hits[0] if len(hits) == 1 else None


# ── E1 / E1b ────────────────────────────────────────────────────────────

def rules_vocab(text: str) -> list:
    return [(m.key, v) for m, v in symbolic.extract(text)]


_EQUNIT = {(m.equipment, m.unit): m.key for m in METRICS}
_UNITS = sorted({m.unit for m in METRICS}, key=len, reverse=True)
_EU = re.compile(r"(?<![\w.:-])(\d+(?:\.\d+)?)\s*(" + "|".join(re.escape(u) for u in _UNITS) + r")(?![\w/])")


def rules_equnit(text: str) -> list:
    """Exact equipment code present + number followed by an exact SOP unit."""
    eqs = [m.equipment for m in METRICS if re.search(r"(?<![\w-])" + re.escape(m.equipment) + r"(?![\w-])", text)]
    out = []
    for n, u in _EU.findall(text):
        keys = {_EQUNIT[(e, u)] for e in set(eqs) if (e, u) in _EQUNIT}
        if len(keys) == 1:
            out.append((keys.pop(), float(n)))
    return out


# ── E2 / E3 classifiers ─────────────────────────────────────────────────

class QuantityClassifier:
    """Text → metric key, trained on v2 train (single-reading texts)."""

    def __init__(self, kind: str, embed_cache: str | None = None):
        self.kind = kind
        self.embed_cache = embed_cache
        self._emb = None

    def _features(self, texts: list):
        if self.kind == "tfidf":
            return self.vec.transform(texts)
        return np.array(list(self._embedder().embed(texts)))

    def _embedder(self):
        if self._emb is None:
            from fastembed import TextEmbedding

            self._emb = TextEmbedding("BAAI/bge-small-en-v1.5", cache_dir=self.embed_cache, threads=2)
        return self._emb

    def fit(self, texts: list, keys: list) -> "QuantityClassifier":
        from sklearn.linear_model import LogisticRegression

        if self.kind == "tfidf":
            from sklearn.feature_extraction.text import TfidfVectorizer

            self.vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)
            X = self.vec.fit_transform(texts)
        else:
            X = self._features(texts)
        self.clf = LogisticRegression(max_iter=4000, C=4.0, random_state=0).fit(X, keys)
        return self

    def __call__(self, text: str) -> tuple:
        """Return (readings, top_probability)."""
        p = self.clf.predict_proba(self._features([text]))[0]
        i = int(np.argmax(p))
        key = self.clf.classes_[i]
        if p[i] < ABSTAIN_BELOW:
            return [], float(p[i])
        v = pick_value(text, key)
        return ([] if v is None else [(key, v)]), float(p[i])


# ── Iteration 2b: deterministic equipment-registry gate ─────────────────
#
# Designed on hard-reports-v3 (development set). A learned quantity
# classifier has no "not covered" class, so it maps "P-9 vibration" onto
# P-7. The gate abstains whenever the text names an equipment-style code
# whose family prefix belongs to the policy's equipment families but which is
# not a registered asset. Codes with other prefixes (WO-, PNL-, TI-, ...) are
# not equipment and are ignored. The registry is organisational data, like
# the policy itself; it is not learned.
#
# Known blind spots, stated before held-out evaluation: an unknown asset whose
# prefix is outside the families (e.g. "BFP-2"), or an unknown asset named
# without any code ("instrument air dryer"), passes the gate.
EQUIPMENT_FAMILIES = ("p", "cp", "t", "tx", "v", "g", "gen", "ch", "fp")
REGISTERED = {
    # canonical code → accepted spellings after normalisation (lowercase, no '-' or space)
    "P-7": {"p7", "cp7"},
    "T-3": {"t3", "tx3"},
    "V-12": {"v12"},
    "G-2": {"g2", "gen2"},
    "CH-5": {"ch5"},
    "FP-1": {"fp1"},
}
_REG_NORM = {s for v in REGISTERED.values() for s in v}
_CODE = re.compile(r"(?<![a-z0-9])([a-z]{1,3})[- ]?(\d{1,3})(?![0-9.])", re.IGNORECASE)


def unregistered_equipment(text: str) -> list:
    """Equipment-family codes in the text that are not registered assets."""
    out = []
    for pre, num in _CODE.findall(text):
        p = pre.lower()
        if p in EQUIPMENT_FAMILIES and f"{p}{num}" not in _REG_NORM:
            out.append(f"{pre}-{num}")
    return out
