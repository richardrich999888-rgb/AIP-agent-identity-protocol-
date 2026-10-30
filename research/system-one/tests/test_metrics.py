"""Unit tests for harness.metrics: happy path, edge cases, known values."""
import numpy as np
import pytest

from harness import metrics as M


def onehot(pred, k=4):
    return np.eye(k)[np.asarray(pred) - 1]


def test_perfect_predictions():
    y = np.array([1, 2, 3, 4])
    p = onehot(y)
    assert M.accuracy(y, y) == 1.0
    assert M.macro_f1(y, y) == 1.0
    assert M.brier(y, p) == 0.0
    assert M.ece(y, p) == 0.0
    assert M.aurc(y, p) == 0.0


def test_always_certain_wrong_has_ece_equal_error_rate():
    y = np.array([1, 1, 1, 1])
    pred = np.array([1, 1, 2, 2])
    assert M.ece(y, onehot(pred)) == pytest.approx(0.5)
    assert M.brier(y, onehot(pred)) == pytest.approx(1.0)  # two items * 2 / 4


def test_uniform_probs_known_values():
    y = np.array([1, 2, 3, 4])
    p = np.full((4, 4), 0.25)
    # argmax picks class 1 for every row → 1/4 correct, confidence 0.25.
    assert M.ece(y, p) == pytest.approx(0.0)
    assert M.brier(y, p) == pytest.approx(0.75)


def test_macro_f1_skips_absent_classes():
    y = np.array([1, 1, 2])
    pred = np.array([1, 1, 2])
    assert M.macro_f1(y, pred) == 1.0


def test_risk_coverage_monotone_for_well_ordered_confidence():
    y = np.array([1, 1, 1, 1])
    probs = np.array([[0.9, 0.1, 0, 0], [0.8, 0.2, 0, 0], [0.4, 0.6, 0, 0], [0.3, 0.7, 0, 0]])
    rc = M.risk_coverage(y, probs)
    assert rc[-1] == (1.0, 0.5)
    assert rc[4][1] == 0.0  # 50 % coverage keeps only the two correct items


def test_temperature_fit_recovers_known_temperature():
    rng = np.random.default_rng(1)
    true_logits = rng.normal(size=(4000, 4)) * 3
    probs = M.softmax(true_logits)
    y = np.array([rng.choice(4, p=p) + 1 for p in probs])
    t = M.temperature_fit(true_logits * 2.0, y)  # logits inflated 2×
    assert t == pytest.approx(2.0, rel=0.1)


def test_bootstrap_is_deterministic_and_brackets_point_estimate():
    y = np.array([1, 2, 3, 4] * 25)
    pred = np.array([1, 2, 3, 1] * 25)
    a = M.bootstrap_ci(M.accuracy, y, pred, seed=7)
    b = M.bootstrap_ci(M.accuracy, y, pred, seed=7)
    assert a == b
    assert a[0] <= 0.75 <= a[1]


def test_paired_diff_identical_predictions_is_zero():
    y = np.array([1, 2, 3, 4] * 10)
    r = M.paired_bootstrap_diff(y, y, y)
    assert r["diff"] == 0.0 and r["p_a_not_better"] == 1.0


def test_latency_summary_percentiles():
    s = M.latency_summary([0.001] * 99 + [1.0])
    assert s["p50_ms"] == pytest.approx(1.0)
    assert s["p99_ms"] > 1.0
