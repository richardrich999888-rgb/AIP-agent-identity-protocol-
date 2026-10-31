"""Phases A, C (lifecycle), D, E, F and baseline 4 through the real runtime CLI.

usage: run_learning.py OUT_DIR CAPABILITY.json [--profile balanced] [--skip-baseline4]

Every model call happens inside research/compute-memory/bench/offline.sh (no
route out). Lifecycle commands need no network. Keys are generated per run
under OUT_DIR/state/keys (mode 0600) and never committed.

Scoring (fixed before any run):
  Decision -> its label; Withheld/Refused -> "WITHHELD"/"REFUSED";
  Answer text (no capability) -> label by the keyword table below, or
  "AMBIGUOUS" when it names more than one label, or "NONE".
  NOT_APPLICABLE items are correct iff no capability decided them.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
DATA = os.path.join(ROOT, "research/capability-learning/data/ir-tasks-v1")
BIN = os.environ.get("SYNTRIASS_BIN", os.path.join(ROOT, "target/release/syntriass"))
OFFLINE = os.path.join(ROOT, "research/compute-memory/bench/offline.sh")
MKCONFIG = os.path.join(ROOT, "research/intelligence-runtime/harness/mkconfig.py")
EXPERT, APPROVER = "expert:koravi-elec-lead", "user:koravi-elec-authority"
KORAVI = {"tenant": "koravi-process", "clearance": "restricted"}
COUNTEREX = {"OUT_OF_SCOPE", "INVALID_TEST", "INSUFFICIENT_INPUT"}
KEYWORDS = [  # label, patterns (word-bounded, case-insensitive)
    ("REJECT", [r"reject", r"rewind"]),
    ("DRY_OUT", [r"dry(?:[- ]out)?", r"dried"]),
    ("RETEST_30D", [r"retest", r"30 days"]),
    ("INVALID_TEST", [r"invalid"]),
    ("OUT_OF_SCOPE", [r"out of scope", r"does not apply", r"not applicable"]),
    ("INSUFFICIENT_INPUT", [r"insufficient", r"missing"]),
    ("PASS", [r"pass(?:es|ed)?", r"accept(?:ed|able)?"]),
]


def rows(name: str) -> list[dict]:
    return [json.loads(l) for l in open(os.path.join(DATA, name))]


def run(cmd: list[str], **kw) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise SystemExit(f"{' '.join(cmd[:3])}: {r.stderr.strip()[-400:]}")
    return r.stdout


def keyword_label(text: str) -> str:
    found = {lab for lab, pats in KEYWORDS if any(re.search(rf"\b{p}\b", text, re.I) for p in pats)}
    return found.pop() if len(found) == 1 else ("NONE" if not found else "AMBIGUOUS")


def label_of(resp: dict) -> str:
    o = resp["outcome"]
    k = o["kind"]
    if k == "decision":
        return o["label"]
    if k == "answer":
        return keyword_label(o["text"])
    return "WITHHELD" if k == "withheld" else "REFUSED"


def correct(item: dict, resp: dict) -> bool:
    if item["label"] == "NOT_APPLICABLE":
        return "Capability" not in json.dumps(resp["strategy"])
    return label_of(resp) == item["label"]


def setup(out: str, profile: str) -> tuple[str, dict]:
    keys = os.path.join(out, "keys")
    os.makedirs(keys, exist_ok=True)
    pub = {}
    for who, f in ((EXPERT, "expert.json"), (APPROVER, "approver.json")):
        p = os.path.join(keys, f)
        if not os.path.exists(p):
            run([BIN, "keygen", "--id", who, "--out", p])
        pub[who] = json.load(open(p))["public_hex"]
    json.dump({APPROVER: pub[APPROVER]}, open(os.path.join(keys, "approvers.json"), "w"))
    json.dump({EXPERT: pub[EXPERT]}, open(os.path.join(keys, "experts.json"), "w"))
    state = os.path.join(out, "state")
    run([sys.executable, MKCONFIG, state, profile, "--approvers", os.path.join(keys, "approvers.json"),
         "--experts", os.path.join(keys, "experts.json")], env={**os.environ, "SYNTRIASS_BIN": BIN})
    return os.path.join(state, "config.json"), {"keys": keys}


def lifecycle(cfg: str, keys: str, cap_path: str, out: str) -> dict:
    cases = os.path.join(out, "suite_cases.jsonl")
    with open(cases, "w") as f:
        for r in rows("validation.jsonl"):  # counterexample rule fixed in tests/common is_counterexample
            f.write(json.dumps({**r, "counterexample": r["label"] in COUNTEREX}) + "\n")
    suite = os.path.join(out, "suite.json")
    run([BIN, "suite-sign", "--key", os.path.join(keys, "expert.json"), "--cases", cases, "--suite-id",
         "ir-tasks-v1/validation", "--tenant", "koravi-process", "--task", "motor IR acceptance (EP-114 rev C)", "--out", suite])
    h = json.loads(run([BIN, "cap-propose", "--config", cfg, "--file", cap_path]))["hash"]
    rep = json.loads(run([BIN, "cap-validate", "--config", cfg, "--hash", h, "--suite", suite]))
    res = {"hash": h, "validation": rep}
    if rep["passed"]:
        run([BIN, "cap-approve", "--config", cfg, "--hash", h, "--key", os.path.join(keys, "approver.json")])
        run([BIN, "cap-transition", "--config", cfg, "--hash", h, "--to", "ACTIVE", "--role", "operator",
             "--actor", "operator:koravi-ot", "--reason", "approved for service"])
    res["records"] = [json.loads(l) for l in run([BIN, "cap-list", "--config", cfg]).splitlines()]
    return res


def serve(cfg: str, reqs: list[dict], out_jsonl: str) -> list[dict]:
    inp = "\n".join(json.dumps(r) for r in reqs) + "\n"
    r = subprocess.run([OFFLINE, BIN, "serve", "--eval", "--config", cfg], input=inp, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"serve: {r.stderr[-600:]}")
    res = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    with open(out_jsonl, "w") as f:
        f.writelines(json.dumps(x) + "\n" for x in res)
    return res


def requests(items: list[dict], principal: dict, tag: str, capability: str | None = None) -> list[dict]:
    out = []
    for it in items:
        r = {"id": f"{tag}:{it['id']}", "principal": principal, "text": it["text"]}
        if capability:
            r["capability"] = capability
        out.append(r)
    return out


def score(items: list[dict], res: list[dict]) -> dict:
    by = {r["id"].split(":", 1)[1]: r for r in res}
    n = ok = fa = errors = 0
    per = []
    for it in items:
        r = by.get(it["id"])
        n += 1
        if r is None or "error" in r:
            errors += 1
            per.append({"id": it["id"], "label": it["label"], "got": "ERROR"})
            continue
        resp = r["response"]
        c = correct(it, resp)
        ok += c
        if it["label"] == "NOT_APPLICABLE" and not c:
            fa += 1
        cost = resp["cost"]
        per.append({"id": it["id"], "label": it["label"], "got": label_of(resp), "ok": c,
                    "strategy": resp["strategy"], "cpu_s": round(sum(cost["cpu_s"].values()), 3),
                    "wall_ms": round(cost["wall_ms"], 1), "model_calls": cost["model_calls"],
                    "load_ms": round(cost["model_load_ms"], 1), "rss_mib": cost["rss_mib"]})
    return {"n": n, "correct": ok, "false_activation": fa, "errors": errors, "items": per}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("capability")
    ap.add_argument("--profile", default="balanced")
    ap.add_argument("--skip-baseline4", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    unseen, fa = rows("test_unseen.jsonl"), rows("false_activation.jsonl")
    evalset = unseen + fa
    report = {"profile": a.profile, "capability_file": a.capability}
    # Phase A / baseline 4: runtime without any capability.
    if not a.skip_baseline4:
        cfg0, _ = setup(os.path.join(a.out, "no_capability"), a.profile)
        res0 = serve(cfg0, requests(evalset, KORAVI, "b4"), os.path.join(a.out, "no_capability", "responses.jsonl"))
        report["baseline4_no_capability"] = score(evalset, res0)
    # Phase C lifecycle + Phase D.
    cfg, k = setup(os.path.join(a.out, "with_capability"), a.profile)
    life = lifecycle(cfg, k["keys"], a.capability, os.path.join(a.out, "with_capability"))
    report["lifecycle"] = life
    cap_id = json.load(open(a.capability))["id"]
    sample = unseen[:6]
    reqs = (requests(evalset, KORAVI, "d")
            + requests(sample, {"tenant": "tarvel-grid", "clearance": "restricted"}, "x-tenant")
            + requests(sample, {"tenant": "koravi-process", "clearance": "internal"}, "x-clear")
            + requests(sample, {"tenant": "tarvel-grid", "clearance": "restricted"}, "x-invoke", capability=cap_id))
    res = serve(cfg, reqs, os.path.join(a.out, "with_capability", "responses.jsonl"))
    report["phaseD_capability"] = score(evalset, [r for r in res if r["id"].startswith("d:")])
    sec = []
    for r in res:
        if r["id"].startswith("x-"):
            s = r.get("response", {}).get("strategy")
            sec.append({"id": r["id"], "strategy": s, "capability_used": "Capability" in json.dumps(s),
                        "outcome": r.get("response", {}).get("outcome", {}).get("kind")})
    report["unauthorized"] = {"n": len(sec), "capability_used": sum(x["capability_used"] for x in sec), "items": sec}
    json.dump(report, open(os.path.join(a.out, "report.json"), "w"), indent=1)
    pd = report["phaseD_capability"]
    b4 = report.get("baseline4_no_capability", {})
    print(json.dumps({"validation_passed": life["validation"]["passed"], "phaseD": [pd["correct"], pd["n"], "fa", pd["false_activation"]],
                      "baseline4": [b4.get("correct"), b4.get("n")], "unauthorized_capability_used": report["unauthorized"]["capability_used"]}))


if __name__ == "__main__":
    main()
