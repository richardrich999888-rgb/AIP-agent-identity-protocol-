"""Deterministic baseline: keyword extraction over SOP vocabulary + the SOP
rule table. No learning, no neural inference.

It recognises a reading only when a metric's SOP name appears in the text,
then takes the first number after it. Unrecognised reports ABSTAIN (uniform
probabilities). This is deliberately the naive symbolic system: it shows what
exact rules achieve when the input uses the expected vocabulary, and how they
fail when it does not.
"""
from __future__ import annotations

import re

import numpy as np

from datasets.maintenance_priority import METRICS, priority

# Metric SOP names, longest first so "flow-test discharge pressure" wins over
# shorter overlaps.
_NAMES = sorted(((m.name.lower(), m) for m in METRICS), key=lambda x: -len(x[0]))
# A standalone number: not preceded by a letter, digit, '-' or '.', so the 7 in
# "P-7" or "CH-5" is never read as a measurement.
_NUM = re.compile(r"(?<![\w.-])(\d+(?:\.\d+)?)")


def extract(text: str) -> list:
    """[(metric, value)] for every SOP metric name followed by a number."""
    low = text.lower()
    out = []
    for name, m in _NAMES:
        start = 0
        while (i := low.find(name, start)) >= 0:
            mnum = _NUM.search(low, i + len(name))
            if mnum:
                out.append((m, float(mnum.group(1))))
            start = i + len(name)
    return out


def predict(text: str) -> tuple:
    """Return (probs[4], abstained)."""
    readings = extract(text)
    if not readings:
        return np.full(4, 0.25), True
    label = min(priority(m, v) for m, v in readings)
    p = np.zeros(4)
    p[label - 1] = 1.0
    return p, False


def standalone_numbers(text: str) -> list:
    """Every standalone number in the text (not part of a code like P-7)."""
    return [float(x) for x in _NUM.findall(text)]
