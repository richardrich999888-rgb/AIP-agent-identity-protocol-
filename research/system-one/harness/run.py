"""Run one decision method over the dataset splits and write raw predictions.

usage:
  run.py symbolic DATA OUT
  run.py tfidf    DATA OUT
  run.py readout  DATA OUT --endpoint IP:PORT --server-pid PID [--no-cache]
  run.py json     DATA OUT --endpoint IP:PORT --server-pid PID --limit N

Outputs in OUT/:
  preds_<split>.jsonl  one line per item: id, label, pred, probs, latency_s, extra
  run.json             method, settings, calibration temperature, peak memory,
                       dataset manifest hash, host info
Metrics are computed separately by harness/report.py from these files, so a
metric bug can be fixed without re-running inference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import metrics as M  # noqa: E402
from methods import llm, symbolic, tfidf_lr  # noqa: E402

TEST_SPLITS = ("test_id", "test_para", "test_ood")


def load(data: str, split: str) -> list:
    with open(os.path.join(data, f"{split}.jsonl")) as f:
        return [json.loads(line) for line in f]


def vm_hwm_mb(pid: int | None) -> float | None:
    if not pid:
        return None
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024
    except OSError:
        return None
    return None


def stratified_head(rows: list, n: int) -> list:
    """First items of each class in round-robin order; deterministic."""
    by = {c: [r for r in rows if r["label"] == c] for c in (1, 2, 3, 4)}
    out, i = [], 0
    while len(out) < n and any(i < len(v) for v in by.values()):
        for c in (1, 2, 3, 4):
            if i < len(by[c]) and len(out) < n:
                out.append(by[c][i])
        i += 1
    return out


def write_preds(out: str, split: str, rows: list, probs: np.ndarray, lat: list, extra: list) -> None:
    with open(os.path.join(out, f"preds_{split}.jsonl"), "w") as f:
        for r, p, t, e in zip(rows, probs, lat, extra):
            f.write(json.dumps({"id": r["id"], "label": r["label"], "pred": int(np.argmax(p)) + 1,
                                "probs": [round(float(x), 6) for x in p], "latency_s": t, "extra": e}) + "\n")


def run_symbolic(a, meta):
    for split in TEST_SPLITS:
        rows = load(a.data, split)
        probs, lat, extra = [], [], []
        for r in rows:
            t = time.perf_counter()
            p, abst = symbolic.predict(r["text"])
            lat.append(time.perf_counter() - t)
            probs.append(p)
            extra.append({"abstained": abst})
        write_preds(a.out, split, rows, np.array(probs), lat, extra)


def run_tfidf(a, meta):
    tr, va = load(a.data, "train"), load(a.data, "val")
    t = time.perf_counter()
    model = tfidf_lr.fit([r["text"] for r in tr], [r["label"] for r in tr])
    meta["train_seconds"] = time.perf_counter() - t
    yv = np.array([r["label"] for r in va])
    meta["temperature"] = M.temperature_fit(tfidf_lr.logits(model, [r["text"] for r in va]), yv)
    for split in TEST_SPLITS:
        rows = load(a.data, split)
        probs, lat = [], []
        for r in rows:  # one at a time: per-decision latency, not batch
            t = time.perf_counter()
            lg = tfidf_lr.logits(model, [r["text"]])
            probs.append(M.softmax(lg, meta["temperature"])[0])
            lat.append(time.perf_counter() - t)
        write_preds(a.out, split, rows, np.array(probs), lat, [{} for _ in rows])


def run_readout(a, meta):
    cache = not a.no_cache
    meta["cache_prompt"] = cache
    va = load(a.data, "val")
    vl = np.array([llm.readout(a.endpoint, r["text"], cache)[0] for r in va])
    meta["temperature"] = M.temperature_fit(vl, np.array([r["label"] for r in va]))
    for split in TEST_SPLITS:
        rows = load(a.data, split)
        if a.limit:
            rows = stratified_head(rows, a.limit)
        probs, lat, extra = [], [], []
        for r in rows:
            lg, dt, ntok = llm.readout(a.endpoint, r["text"], cache)
            probs.append(M.softmax(lg[None, :], meta["temperature"])[0])
            lat.append(dt)
            extra.append({"raw_logprobs": [round(float(x), 4) for x in lg], "completion_tokens": ntok})
        write_preds(a.out, split, rows, np.array(probs), lat, extra)


def run_json(a, meta):
    meta["limit_per_split"] = a.limit
    for split in TEST_SPLITS:
        rows = stratified_head(load(a.data, split), a.limit)
        probs, lat, extra = [], [], []
        for r in rows:
            label, dt, ntok, raw = llm.json_gen(a.endpoint, r["text"])
            p = np.full(4, 0.25) if label is None else np.eye(4)[label - 1]
            probs.append(p)
            lat.append(dt)
            extra.append({"parsed": label is not None, "completion_tokens": ntok, "raw": raw})
        write_preds(a.out, split, rows, np.array(probs), lat, extra)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method", choices=("symbolic", "tfidf", "readout", "json"))
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--endpoint")
    ap.add_argument("--server-pid", type=int)
    ap.add_argument("--model", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-cache", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    manifest = os.path.join(a.data, "MANIFEST.json")
    meta = {
        "method": a.method,
        "model": a.model,
        "dataset_manifest_sha256": hashlib.sha256(open(manifest, "rb").read()).hexdigest(),
        "host": {"platform": platform.platform(), "nproc": os.cpu_count(), "python": platform.python_version()},
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    t = time.perf_counter()
    {"symbolic": run_symbolic, "tfidf": run_tfidf, "readout": run_readout, "json": run_json}[a.method](a, meta)
    meta["wall_seconds"] = time.perf_counter() - t
    meta["client_peak_rss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    meta["server_peak_rss_mb"] = vm_hwm_mb(a.server_pid)
    meta["energy"] = "not measured: no RAPL/powercap interface on this host"
    with open(os.path.join(a.out, "run.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
