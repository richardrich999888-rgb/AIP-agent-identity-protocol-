"""Baselines 1-3: a local model classifies each request directly (no capability).

usage (inside offline.sh): baselines.py OUT_DIR --model GGUF --model-sha SHA --server LLAMA [--port 8420]

  B1 model only           request + label vocabulary
  B2 conventional RAG     + top-k authorized documents (SQLite FTS5 BM25 over the
                            principal's tenant and clearance; same ACL rule as the runtime)
  B3 prompt skill library + the 6 expert demonstrations with working (few-shot)

Output label is constrained to the vocabulary by a JSON-schema enum, so every
answer is scoreable (this favours the baselines: free text would be worse).
Decoding greedy (temperature 0, seed 0). Cost per item: llama-server CPU
seconds (/proc delta), wall time, prompt and completion tokens.
Evaluation set: test_unseen (32) + false_activation (8), principal
koravi-process/restricted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(ROOT, "research/capability-learning/data/ir-tasks-v1")
SOV = os.path.join(ROOT, "sovereign/eval/corpus")
sys.path.insert(0, os.path.join(ROOT, "research/compute-memory/bench"))
import llama_proc as L  # noqa: E402

LABELS = ["PASS", "RETEST_30D", "DRY_OUT", "REJECT", "INVALID_TEST", "OUT_OF_SCOPE", "INSUFFICIENT_INPUT", "NOT_APPLICABLE"]
SCHEMA = {"type": "object", "properties": {"label": {"enum": LABELS}}, "required": ["label"]}
RANK = {"public": 0, "internal": 1, "restricted": 2}
TOP_K = 2
PRINCIPAL = ("koravi-process", "restricted")


def rows(name: str) -> list[dict]:
    return [json.loads(l) for l in open(os.path.join(DATA, name))]


def corpus() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE VIRTUAL TABLE d USING fts5(tenant UNINDEXED, doc_id UNINDEXED, cls UNINDEXED, title, body)")
    files = [os.path.join(SOV, f) for f in sorted(os.listdir(SOV))] + \
            [os.path.join(DATA, "corpus", f) for f in sorted(os.listdir(os.path.join(DATA, "corpus")))]
    for p in files:
        head, body = open(p).read().split("\n", 1)
        t, d, c, title = head.split("|", 3)
        db.execute("INSERT INTO d VALUES (?,?,?,?,?)", (t, d, c, title, body))
    return db


def retrieve(db: sqlite3.Connection, text: str) -> list[tuple[str, str]]:
    terms = [w for w in "".join(ch if ch.isalnum() else " " for ch in text.lower()).split() if len(w) > 1]
    if not terms:
        return []
    q = " OR ".join(f'"{w}"' for w in terms)
    tenant, clr = PRINCIPAL
    allowed = [k for k, v in RANK.items() if v <= RANK[clr]]
    rs = db.execute(f"SELECT doc_id, title, body FROM d WHERE d MATCH ? AND tenant = ? AND cls IN ({','.join('?' * len(allowed))}) "
                    "ORDER BY bm25(d) LIMIT ?", (q, tenant, *allowed, TOP_K)).fetchall()
    return [(f"{r[0]}: {r[1]}", r[2]) for r in rs]


def demo_block() -> str:
    return "\n".join(f"- \"{d['text']}\" -> {d['label']}" + (f" ({d['expert_working']})" if d.get("expert_working") else "")
                     for d in rows("demos.jsonl"))


def messages(kind: str, text: str, db) -> tuple[list[dict], list[str]]:
    instr = ("Classify the request about a motor insulation-resistance test into exactly one label. "
             f"Labels: {', '.join(LABELS)}. Use NOT_APPLICABLE when the request does not ask for a test decision.")
    parts, docs = [instr], []
    if kind in ("B2", "B3"):
        ret = retrieve(db, text)
        docs = [t for t, _ in ret]
        parts.append("ORGANISATION DOCUMENTS:\n" + "\n\n".join(f"[{t}]\n{b}" for t, b in ret))
    if kind == "B3":
        parts.append("EXPERT EXAMPLES:\n" + demo_block())
    parts.append(f"REQUEST: {text}\nAnswer as JSON.")
    return [{"role": "system", "content": "You are a careful electrical maintenance engineer. Output JSON only."},
            {"role": "user", "content": "\n\n".join(parts)}], docs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--model", required=True)
    ap.add_argument("--model-sha", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=8420)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    h = hashlib.sha256()
    with open(a.model, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    if h.hexdigest() != a.model_sha:
        sys.exit("model hash mismatch")
    items = rows("test_unseen.jsonl") + rows("false_activation.jsonl")
    db = corpus()
    srv = L.Server(a.server, a.model, a.port, ("-c", "8192"), os.path.join(a.out, "llama.log"))
    load_s = srv.start()
    summary = {"model": os.path.basename(a.model), "model_sha256": a.model_sha, "load_s": round(load_s, 2)}
    try:
        for kind in ("B1", "B2", "B3"):
            res = []
            for it in items:
                msgs, docs = messages(kind, it["text"], db)
                before = srv.stats()
                body = {"messages": msgs, "temperature": 0, "seed": 0, "max_tokens": 24, "cache_prompt": False,
                        "response_format": {"type": "json_schema", "json_schema": {"schema": SCHEMA}}}
                resp, wall = srv.post("/v1/chat/completions", body)
                after = srv.stats()
                raw = resp["choices"][0]["message"]["content"]
                try:
                    got = json.loads(raw)["label"]
                except (ValueError, KeyError):
                    got = "UNPARSED"
                u = resp.get("usage", {})
                res.append({"id": it["id"], "label": it["label"], "got": got, "ok": got == it["label"],
                            "docs": docs, "wall_s": round(wall, 3), "cpu_s": round(after["cpu_s"] - before["cpu_s"], 3),
                            "prompt_tokens": u.get("prompt_tokens"), "completion_tokens": u.get("completion_tokens")})
            with open(os.path.join(a.out, f"{kind}.jsonl"), "w") as f:
                f.writelines(json.dumps(r) + "\n" for r in res)
            summary[kind] = {"n": len(res), "correct": sum(r["ok"] for r in res),
                             "false_activation": sum(r["label"] == "NOT_APPLICABLE" and r["got"] != "NOT_APPLICABLE" for r in res),
                             "cpu_s_total": round(sum(r["cpu_s"] for r in res), 2),
                             "wall_s_total": round(sum(r["wall_s"] for r in res), 2),
                             "prompt_tokens": sum(r["prompt_tokens"] or 0 for r in res)}
        summary["llama_peak_rss_mib"] = round(srv.stats()["VmHWM"], 1)
    finally:
        srv.stop()
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    print(json.dumps({k: (v if not isinstance(v, dict) else [v["correct"], v["n"], "fa", v["false_activation"], "cpu", v["cpu_s_total"]]) for k, v in summary.items()}))


if __name__ == "__main__":
    main()
