"""Decision-quality and latency metrics. Pure functions over numpy arrays.

Conventions
-----------
- `probs`: (n, K) rows summing to 1; class index k ↔ label k+1.
- `y`: (n,) integer labels in 1..K.
- A method that gives no probabilities supplies one-hot rows (confidence 1);
  its ECE then equals its error rate, which is the honest calibration of a
  system that is always certain.
- ECE uses equal-width confidence bins on max-probability (Guo et al. 2017).
- Bootstrap: percentile intervals from `n_boot` resamples with a fixed seed.
"""
from __future__ import annotations

import numpy as np

K_DEFAULT = 4


def accuracy(y: np.ndarray, pred: np.ndarray) -> float:
    return float(np.mean(y == pred))


def macro_f1(y: np.ndarray, pred: np.ndarray, k: int = K_DEFAULT) -> float:
    """Unweighted mean of per-class F1; a class absent from both y and pred is skipped."""
    f1s = []
    for c in range(1, k + 1):
        tp = np.sum((pred == c) & (y == c))
        fp = np.sum((pred == c) & (y != c))
        fn = np.sum((pred != c) & (y == c))
        if tp + fp + fn == 0:
            continue
        f1s.append(2 * tp / (2 * tp + fp + fn))
    return float(np.mean(f1s)) if f1s else 0.0


def brier(y: np.ndarray, probs: np.ndarray) -> float:
    """Multiclass Brier score: mean over items of sum_k (p_k - 1[y=k])^2. Range [0, 2]."""
    onehot = np.eye(probs.shape[1])[y - 1]
    return float(np.mean(np.sum((probs - onehot) ** 2, axis=1)))


def ece(y: np.ndarray, probs: np.ndarray, bins: int = 15) -> float:
    """Expected calibration error on top-label confidence."""
    conf = probs.max(axis=1)
    pred = probs.argmax(axis=1) + 1
    correct = (pred == y).astype(float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        # Right-closed bins; the first bin also includes 0.
        m = (conf > lo) & (conf <= hi) if lo > 0 else (conf >= lo) & (conf <= hi)
        if m.any():
            total += m.mean() * abs(correct[m].mean() - conf[m].mean())
    return float(total)


def risk_coverage(y: np.ndarray, probs: np.ndarray) -> list:
    """Selective prediction: sort by confidence descending; for each coverage
    level report the error rate among accepted items. Returns
    [(coverage, risk)] at 10 %, 20 %, …, 100 %."""
    conf = probs.max(axis=1)
    pred = probs.argmax(axis=1) + 1
    order = np.argsort(-conf, kind="stable")
    err = (pred[order] != y[order]).astype(float)
    out = []
    n = len(y)
    for c in range(1, 11):
        k = max(1, int(round(n * c / 10)))
        out.append((c / 10, float(err[:k].mean())))
    return out


def aurc(y: np.ndarray, probs: np.ndarray) -> float:
    """Area under the risk–coverage curve over every coverage level (lower is better)."""
    conf = probs.max(axis=1)
    pred = probs.argmax(axis=1) + 1
    order = np.argsort(-conf, kind="stable")
    err = (pred[order] != y[order]).astype(float)
    return float(np.mean(np.cumsum(err) / np.arange(1, len(err) + 1)))


def latency_summary(seconds: list) -> dict:
    a = np.asarray(seconds, dtype=float)
    return {
        "p50_ms": float(np.percentile(a, 50) * 1000),
        "p95_ms": float(np.percentile(a, 95) * 1000),
        "p99_ms": float(np.percentile(a, 99) * 1000),
        "mean_ms": float(a.mean() * 1000),
        "decisions_per_s": float(len(a) / a.sum()) if a.sum() > 0 else None,
    }


def bootstrap_ci(fn, y: np.ndarray, x: np.ndarray, n_boot: int = 1000, seed: int = 0, alpha: float = 0.05) -> tuple:
    """Percentile CI for fn(y_sample, x_sample)."""
    rng = np.random.default_rng(seed)
    n = len(y)
    vals = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        vals.append(fn(y[idx], x[idx]))
    lo, hi = np.percentile(vals, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(lo), float(hi)


def paired_bootstrap_diff(y: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray, n_boot: int = 2000, seed: int = 0) -> dict:
    """Accuracy(A) - Accuracy(B) on the same items, with a percentile CI and
    the share of resamples where A ≤ B (one-sided bootstrap p-value)."""
    rng = np.random.default_rng(seed)
    n = len(y)
    ca, cb = (pred_a == y).astype(float), (pred_b == y).astype(float)
    diffs = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        diffs.append(ca[idx].mean() - cb[idx].mean())
    diffs = np.asarray(diffs)
    return {
        "diff": float(ca.mean() - cb.mean()),
        "ci95": [float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))],
        "p_a_not_better": float(np.mean(diffs <= 0)),
    }


def temperature_fit(logits: np.ndarray, y: np.ndarray) -> float:
    """Fit a single temperature T>0 minimising NLL of softmax(logits/T) by a
    deterministic golden-section search on log T in [log 0.05, log 20]."""

    def nll(log_t: float) -> float:
        z = logits / np.exp(log_t)
        z = z - z.max(axis=1, keepdims=True)
        lp = z - np.log(np.exp(z).sum(axis=1, keepdims=True))
        return float(-lp[np.arange(len(y)), y - 1].mean())

    a, b = np.log(0.05), np.log(20.0)
    g = (np.sqrt(5) - 1) / 2
    c, d = b - g * (b - a), a + g * (b - a)
    for _ in range(80):
        if nll(c) < nll(d):
            b, d = d, c
            c = b - g * (b - a)
        else:
            a, c = c, d
            d = a + g * (b - a)
    return float(np.exp((a + b) / 2))


def softmax(logits: np.ndarray, t: float = 1.0) -> np.ndarray:
    z = logits / t
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)
