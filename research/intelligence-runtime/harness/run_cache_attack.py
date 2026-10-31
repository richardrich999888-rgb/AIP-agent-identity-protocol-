"""Cache-isolation attack against the integrated runtime (not the research harness).

usage: run_cache_attack.py OUT_JSON CONFIG

Three principals = three cache scopes (tenant:clearance differ; snapshot
digests differ). Every grounded-QA prompt the runtime builds starts with the
same system prompt, so under llama.cpp's default shared cache a scope's FIRST
request would reuse another scope's prefix (cached_tokens > 0; shown for the
raw server in research/compute-memory/CACHE_SECURITY.md, AUC 1.00).

Property tested: for every scope, its first request has cached_tokens == 0,
including when it sends exactly the victim's question text; later requests
may reuse only that scope's own state. With 2 slots and 3 scopes, slots are
evicted (erased) and reassigned during the sequence.
Also records wall time of first vs repeat requests per scope.
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
P = {"victim": {"tenant": "koravi-process", "clearance": "restricted"},
     "same-tenant-lower": {"tenant": "koravi-process", "clearance": "internal"},
     "other-tenant": {"tenant": "plant-alpha", "clearance": "internal"}}
Q = "What is the minimum insulation resistance for a 6.6 kV motor under EP-114?"
SEQ = ["victim", "victim", "other-tenant", "victim", "same-tenant-lower", "other-tenant",
       "same-tenant-lower", "victim", "other-tenant", "victim"]


def main() -> None:
    out, cfg = sys.argv[1], sys.argv[2]
    reqs = [{"id": f"{i}:{who}", "principal": P[who], "text": Q} for i, who in enumerate(SEQ)]
    r = subprocess.run([OFFLINE, BIN, "serve", "--eval", "--config", cfg],
                       input="".join(json.dumps(x) + "\n" for x in reqs), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(r.stderr[-600:])
    res = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    seen, rows, violations = set(), [], []
    for x in res:
        who = x["id"].split(":", 1)[1]
        c = x["response"]["cost"]
        first = who not in seen
        seen.add(who)
        row = {"id": x["id"], "first_in_scope": first, "cached_tokens": c["cached_tokens"],
               "prompt_tokens": c["prompt_tokens"], "wall_ms": round(c["wall_ms"]),
               "outcome": x["response"]["outcome"]["kind"], "sources": x["response"]["outcome"].get("sources")}
        rows.append(row)
        if first and c["cached_tokens"] > 0:
            violations.append(row)
    rep = {"sequence": SEQ, "rows": rows, "violations": violations,
           "first_requests": sum(r["first_in_scope"] for r in rows),
           "repeat_requests_with_reuse": sum((not r["first_in_scope"]) and r["cached_tokens"] > 0 for r in rows)}
    json.dump(rep, open(out, "w"), indent=1)
    for row in rows:
        print(row)
    print(json.dumps({"violations": len(violations), "first_requests": rep["first_requests"],
                      "repeat_requests_with_reuse": rep["repeat_requests_with_reuse"]}))


if __name__ == "__main__":
    main()
