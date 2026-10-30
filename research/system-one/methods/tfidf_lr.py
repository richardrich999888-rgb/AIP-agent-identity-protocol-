"""Conventional cheap text classifier: TF-IDF (word 1–2 grams + char 2–5
grams) → multinomial logistic regression. Trained on `train` only.

It receives no SOP thresholds; it can only learn them implicitly from labelled
examples. Numbers are tokens to it, so threshold comparisons are learned as
string patterns — the expected weak point this baseline exists to expose.
"""
from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, make_pipeline

SEED = 0


def build():
    feats = FeatureUnion([
        ("w", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)),
    ])
    clf = LogisticRegression(max_iter=4000, C=4.0, random_state=SEED)
    return make_pipeline(feats, clf)


def fit(texts: list, labels: list):
    model = build()
    model.fit(texts, labels)
    return model


def logits(model, texts: list) -> np.ndarray:
    """Per-class decision values in label order 1..4 (multinomial logits)."""
    d = model.decision_function(texts)
    order = np.argsort(model.classes_)
    return d[:, order]
