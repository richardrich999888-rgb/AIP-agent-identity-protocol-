"""Symbolic baseline: rule correctness and the equipment-code regression."""
import numpy as np

from methods import symbolic
from datasets.maintenance_priority import METRICS, priority


def label(text):
    p, abst = symbolic.predict(text)
    return None if abst else int(np.argmax(p)) + 1


def test_code_digit_is_not_a_measurement():
    # Regression: "P-7" was read as vibration 7 (in-distribution acc 0.813).
    assert label("During the walkdown the vibration on coolant pump P-7 was 4.2 mm/s.") == 4
    assert label("During the walkdown the vibration on coolant pump P-7 was 7.5 mm/s.") == 1


def test_band_edges_follow_sop():
    vib = next(m for m in METRICS if m.key == "p7_vib")
    assert priority(vib, 4.49) == 4 and priority(vib, 4.5) == 3 and priority(vib, 7.1) == 1


def test_multi_reading_takes_most_urgent():
    assert label("vibration 3.0 mm/s and seal leakage 25 drops/min") == 2


def test_unknown_vocabulary_abstains():
    p, abst = symbolic.predict("pump is shaking a lot, 9.0 mm/s")
    assert abst and np.allclose(p, 0.25)
