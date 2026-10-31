"""Interpretation sidecar for the SYNTRIASS runtime (JSON lines over stdin/stdout).

The runtime (Rust) owns routing, decisions, authorization and every model
call. This process only performs model-free interpretation with the System
One reference code, so the interpreters used in production are byte-for-byte
the ones evaluated in REPORT_ITER2.md:

  {"op": "interpret", "text": T}
      -> {"rules": [[key, value], ...],              # rules_equnit
          "interp": [[key, value], ...],             # TF-IDF quantity classifier
          "interp_top_prob": p,
          "unregistered": ["P-9", ...],              # equipment-registry gate
          "registered_codes": n}                     # distinct registered assets named
  {"op": "slm_request", "text": T}
      -> {"messages": [...], "max_tokens": 120, "schema": {...}}   # System One extract v2, verbatim
  {"op": "slm_parse", "raw": R}
      -> {"readings": [[key, value], ...] | null}
  {"op": "health"} -> {"ok": true, "train_seconds": s, "train_rows": n}

No sockets are opened; the process reads only local training data. Invalid
requests return {"error": "..."} and the process keeps running.
"""
from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from methods import extractors as X  # noqa: E402
from methods import llm  # noqa: E402
from datasets.maintenance_priority import METRICS  # noqa: E402

sys.path.insert(0, os.path.join(HERE, "..", "compute-memory", "tools"))
from cascade import registered_codes  # noqa: E402

MAX_TEXT = 4096


def _train():
    path = os.path.join(HERE, "data/maintenance-priority-v2/train.jsonl")
    rows = [json.loads(l) for l in open(path)]
    t0 = time.perf_counter()
    clf = X.QuantityClassifier("tfidf")
    clf.fit([r["text"] for r in rows], [r["readings"][0][0] for r in rows])
    return clf, time.perf_counter() - t0, len(rows)


def handle(req: dict, clf, meta: dict) -> dict:
    op = req.get("op")
    if op == "health":
        return {"ok": True, **meta}
    if op == "interpret":
        t = req.get("text")
        if not isinstance(t, str) or len(t) > MAX_TEXT:
            return {"error": "text must be a string <= 4096 chars"}
        rd, p = clf(t)
        return {"rules": [[k, v] for k, v in X.rules_equnit(t)], "interp": [[k, v] for k, v in rd],
                "interp_top_prob": round(float(p), 4), "unregistered": X.unregistered_equipment(t),
                "registered_codes": len(registered_codes(t))}
    if op == "slm_request":
        t = req.get("text")
        if not isinstance(t, str) or len(t) > MAX_TEXT:
            return {"error": "text must be a string <= 4096 chars"}
        return {"messages": [{"role": "system", "content": llm.EXTRACT_SYSTEM},
                             {"role": "user", "content": f"Report: {t}\n{llm.EXTRACT_V2_INSTRUCTION}"}],
                "max_tokens": 120, "schema": llm.EXTRACT_SCHEMA_V2}
    if op == "slm_parse":
        raw = req.get("raw")
        try:
            rd = [[METRICS[llm.METRIC_LETTERS.index(r["quantity"])].key, float(r["value"])] for r in json.loads(raw)["readings"]]
        except (ValueError, KeyError, TypeError, IndexError):
            rd = None
        return {"readings": rd}
    return {"error": f"unknown op {op!r}"}


def main() -> None:
    clf, secs, n = _train()
    meta = {"train_seconds": round(secs, 3), "train_rows": n}
    for line in sys.stdin:
        try:
            out = handle(json.loads(line), clf, meta)
        except (ValueError, TypeError) as e:
            out = {"error": f"bad request: {e}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
