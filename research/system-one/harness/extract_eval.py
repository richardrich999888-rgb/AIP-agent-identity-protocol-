"""Evaluate one interpretation-only extractor on the hard set and v2 splits.

usage: extract_eval.py METHOD OUT_DIR [--endpoint IP:PORT --server-pid PID --model NAME]
METHOD: rules_vocab | rules_equnit | tfidf_clf | bge_clf | llm_json_v2

Every method's readings go through the same SOP policy; ABSTAIN when no
covered reading. Writes OUT_DIR/<split>.jsonl (raw readings, decision,
latency) and OUT_DIR/run.json (settings, peak memory, training time).
Scoring is done by extract_report.py from these files.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datasets.maintenance_priority import METRICS, priority  # noqa: E402
from methods import extractors as X  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS = {
    "hard_v3": os.path.join(HERE, "data/hard-reports-v3/test_hard.jsonl"),
    "hard_v4": os.path.join(HERE, "data/hard-reports-v4/test_hard.jsonl"),
    "v2_test_para": os.path.join(HERE, "data/maintenance-priority-v2/test_para.jsonl"),
    "v2_test_ood": os.path.join(HERE, "data/maintenance-priority-v2/test_ood.jsonl"),
}
BY_KEY = {m.key: m for m in METRICS}


def load(path: str) -> list:
    rows = [json.loads(l) for l in open(path)]
    # Optional cap for expensive methods on the v2 reference splits only;
    # generator order is random, so the first N rows are a random sample.
    cap = int(os.environ.get("V2_LIMIT", "0"))
    if cap and "maintenance-priority-v2/test_" in path:
        rows = rows[:cap]
    for r in rows:  # normalise v2 rows to the v3 schema
        if "gold_readings" not in r:
            r["gold_readings"] = r["readings"]
            r["label"] = str(r["label"])
            r["category"] = "v2"
    return rows


def decide(readings: list) -> str:
    covered = [(k, v) for k, v in readings if k in BY_KEY]
    return "ABSTAIN" if not covered else str(min(priority(BY_KEY[k], v) for k, v in covered))


def build(method: str, a, meta: dict):
    if method == "rules_vocab":
        return lambda t: (X.rules_vocab(t), {})
    if method == "rules_equnit":
        return lambda t: (X.rules_equnit(t), {})
    if method in ("tfidf_clf", "bge_clf"):
        tr = load(os.path.join(HERE, "data/maintenance-priority-v2/train.jsonl"))
        t0 = time.perf_counter()
        clf = X.QuantityClassifier("tfidf" if method == "tfidf_clf" else "bge", embed_cache=a.embed_cache)
        clf.fit([r["text"] for r in tr], [r["gold_readings"][0][0] for r in tr])
        meta["train_seconds"] = time.perf_counter() - t0
        meta["train_rows"] = len(tr)

        def f(t):
            rd, p = clf(t)
            return rd, {"top_prob": round(p, 4)}

        return f
    if method == "llm_json_v2":
        from methods import llm

        def g(t):
            rd, dt, ntok, raw = llm.extract_json_v2(a.endpoint, t)
            return (rd or []), {"completion_tokens": ntok, "parsed": rd is not None, "raw": raw}

        return g
    raise SystemExit(f"unknown method {method}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method")
    ap.add_argument("out")
    ap.add_argument("--endpoint")
    ap.add_argument("--server-pid", type=int)
    ap.add_argument("--model", default="")
    ap.add_argument("--embed-cache", default=os.environ.get("EMBED_CACHE"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    meta = {"method": a.method, "model": a.model, "abstain_below": X.ABSTAIN_BELOW,
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    t0 = time.perf_counter()
    f = build(a.method, a, meta)
    meta["load_seconds"] = time.perf_counter() - t0
    only = [x for x in os.environ.get("SPLITS", "").split(",") if x]
    for split, path in SPLITS.items():
        if only and split not in only:
            continue
        with open(os.path.join(a.out, f"{split}.jsonl"), "w") as out:
            for r in load(path):
                t = time.perf_counter()
                rd, extra = f(r["text"])
                dt = time.perf_counter() - t
                out.write(json.dumps({"id": r["id"], "category": r["category"], "label": r["label"],
                                      "gold_readings": r["gold_readings"], "readings": [[k, v] for k, v in rd],
                                      "decision": decide(rd), "latency_s": dt, **extra}) + "\n")
    meta["client_peak_rss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    if a.server_pid:
        try:
            meta["server_peak_rss_mb"] = next(int(l.split()[1]) / 1024 for l in open(f"/proc/{a.server_pid}/status") if l.startswith("VmHWM:"))
        except OSError:
            meta["server_peak_rss_mb"] = None
    meta["energy"] = "not measured: no RAPL/powercap interface on this host"
    json.dump(meta, open(os.path.join(a.out, "run.json"), "w"), indent=2)
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
