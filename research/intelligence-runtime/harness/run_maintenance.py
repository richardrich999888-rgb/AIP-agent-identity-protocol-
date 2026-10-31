"""Phase F regression + fresh routing test: hard-reports-v5 through the runtime.

usage: run_maintenance.py OUT_JSON CONFIG [CONFIG ...]

Each config is served the same 37 v5 reports (principal plant-alpha/internal,
inside offline.sh). Scoring: Decision label vs gold; Refused or Withheld ->
"ABSTAIN". Records the strategy and measured cost per item, and whether any
capability decided a maintenance report (false activation across tasks).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.environ.get("SYNTRIASS_BIN", os.path.join(ROOT, "target/release/syntriass"))
OFFLINE = os.path.join(ROOT, "research/compute-memory/bench/offline.sh")
V5 = os.path.join(ROOT, "research/system-one/data/hard-reports-v5/test_hard.jsonl")
PRINCIPAL = {"tenant": "plant-alpha", "clearance": "internal"}


def got(resp: dict) -> str:
    o = resp["outcome"]
    return o["label"] if o["kind"] == "decision" else "ABSTAIN"


def main() -> None:
    items = [json.loads(l) for l in open(V5)]
    out = {}
    for cfg in sys.argv[2:]:
        inp = "".join(json.dumps({"id": it["id"], "principal": PRINCIPAL, "text": it["text"]}) + "\n" for it in items)
        r = subprocess.run([OFFLINE, BIN, "serve", "--eval", "--config", cfg], input=inp, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(r.stderr[-600:])
        res = {x["id"]: x for x in map(json.loads, r.stdout.splitlines()) if x}
        per = []
        for it in items:
            resp = res[it["id"]]["response"]
            g, c = got(resp), resp["cost"]
            per.append({"id": it["id"], "category": it["category"], "label": it["label"], "got": g,
                        "ok": g == it["label"], "wrong_release": g != "ABSTAIN" and g != it["label"],
                        "strategy": resp["strategy"], "capability": resp["capability_hash"],
                        "cpu_s": round(sum(c["cpu_s"].values()), 3), "wall_ms": round(c["wall_ms"], 1),
                        "model_calls": c["model_calls"], "load_ms": round(c["model_load_ms"], 1)})
        out[cfg] = {"n": len(per), "correct": sum(p["ok"] for p in per), "wrong_release": sum(p["wrong_release"] for p in per),
                    "capability_decided": sum(p["capability"] is not None for p in per),
                    "model_calls": sum(p["model_calls"] for p in per), "items": per}
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    for k, v in out.items():
        print(os.path.basename(os.path.dirname(k)), {x: v[x] for x in ("n", "correct", "wrong_release", "capability_decided", "model_calls")})


if __name__ == "__main__":
    main()
