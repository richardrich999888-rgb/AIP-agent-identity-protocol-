"""Offline cascade simulation over recorded per-item predictions (no model runs).

Each method's per-item record (decision, latency_s) was produced by the
System One harness. A cascade runs stages in order and stops at the first
stage that releases a decision (or at an escalation rule). Cost = sum of the
latencies of the stages actually run. Memory = sum of peak RSS of every
model that must stay resident (or a cold-load cost if loaded on demand).

Rules are fixed a priori (written before computing any cascade result):
  R1 rules-first:   rules_equnit; if it abstains -> encoder+gate
  R2 multi-escalate: encoder+gate, except texts naming >= 2 registered
                    equipment codes -> SLM+gate (the only category where the
                    SLM was better in iteration 2)
  R3 R1 then R2
Caveat: v3 and v4 were both seen before these rules were written, so the
results are exploratory, not held-out evidence.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass

GATE_PREFIXES = ("p", "cp", "t", "tx", "v", "g", "gen", "ch", "fp")
REGISTERED_CODES = {"p7", "cp7", "t3", "tx3", "v12", "g2", "gen2", "ch5", "fp1"}
_CODE = re.compile(r"(?<![a-z0-9])([a-z]{1,3})[- ]?(\d{1,3})(?![0-9.])", re.IGNORECASE)


def registered_codes(text: str) -> set[str]:
    """Distinct registered equipment codes named in the text (normalised)."""
    out = set()
    for fam, num in _CODE.findall(text):
        c = fam.lower() + str(int(num))
        if c in REGISTERED_CODES:
            out.add({"cp7": "p7", "tx3": "t3", "gen2": "g2"}.get(c, c))
    return out


@dataclass(frozen=True)
class Outcome:
    decision: str
    cost_s: float
    stages: tuple


def run_cascade(rule: str, item: dict, preds: dict) -> Outcome:
    """preds: method -> {id: record}. Returns the cascade's decision and cost."""
    i = item["id"]

    def st(m):
        r = preds[m][i]
        return r["decision"], r["latency_s"]

    if rule == "R1":
        d, c = st("rules_equnit")
        if d != "ABSTAIN":
            return Outcome(d, c, ("rules",))
        d2, c2 = st("enc+gate")
        return Outcome(d2, c + c2, ("rules", "enc"))
    if rule == "R2":
        if len(registered_codes(item["text"])) >= 2:
            d, c = st("slm+gate")
            return Outcome(d, c, ("slm",))
        d, c = st("enc+gate")
        return Outcome(d, c, ("enc",))
    if rule == "R3":
        d, c = st("rules_equnit")
        if d != "ABSTAIN":
            return Outcome(d, c, ("rules",))
        o = run_cascade("R2", item, preds)
        return Outcome(o.decision, c + o.cost_s, ("rules",) + o.stages)
    if rule in preds:
        d, c = st(rule)
        return Outcome(d, c, (rule,))
    raise ValueError(f"unknown rule {rule}")


def score(items: list[dict], outs: list[Outcome]) -> dict:
    n = len(items)
    correct = sum(o.decision == it["label"] for it, o in zip(items, outs))
    wrong = sum(o.decision != "ABSTAIN" and o.decision != it["label"] for it, o in zip(items, outs))
    cost = sum(o.cost_s for o in outs)
    return {"n": n, "decision_acc": round(correct / n, 3), "wrong_release": wrong,
            "compute_s_total": round(cost, 2), "correct_per_compute_s": round(correct / cost, 3) if cost else None,
            "slm_calls": sum(any("slm" in s for s in o.stages) for o in outs)}


def gate(rec: dict, text: str) -> dict:
    """Apply the equipment-registry gate (abstain on unregistered family code)."""
    for fam, num in _CODE.findall(text):
        f = fam.lower()
        if f in GATE_PREFIXES and (f + str(int(num))) not in REGISTERED_CODES:
            return {**rec, "decision": "ABSTAIN"}
    return rec


def main(iter2: str, data: str, split: str) -> None:
    texts = {r["id"]: r for r in map(json.loads, open(os.path.join(data, "test_hard.jsonl")))}
    load = lambda m: {r["id"]: r for r in map(json.loads, open(os.path.join(iter2, m, f"{split}.jsonl")))}
    preds = {"rules_equnit": load("rules_equnit"), "tfidf+gate": {}, "enc+gate": {}, "slm+gate": {}}
    for src, dst in (("tfidf_clf", "tfidf+gate"), ("bge_clf", "enc+gate"), ("qwen1.5b_json_v2", "slm+gate")):
        preds[dst] = {i: gate(r, texts[i]["text"]) for i, r in load(src).items()}
    items = [{**r, "text": texts[r["id"]]["text"]} for r in preds["rules_equnit"].values()]
    res = {}
    for rule in ("rules_equnit", "tfidf+gate", "enc+gate", "slm+gate", "R1", "R2", "R3"):
        res[rule] = score(items, [run_cascade(rule, it, preds) for it in items])
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:4])
