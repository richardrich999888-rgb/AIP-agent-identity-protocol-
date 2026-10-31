"""Baseline A on any task: the unchanged propose.py with task parameters applied.

usage: propose_task.py --task tasks/X.json <propose.py arguments>

propose.py is the proposer evaluated in the learning benchmark; it is left
byte-for-byte unchanged and parametrised here (document, demos, outcome
vocabulary, envelope) so Baseline A on a new family is the same method.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import propose as P  # noqa: E402

i = sys.argv.index("--task")
spec = json.load(open(sys.argv[i + 1]))
del sys.argv[i:i + 2]
P.DATA = os.path.join(P.ROOT, "research/capability-learning", spec["data"])
P.OUTCOMES = spec["outcomes"]
for f in ("missing_input_outcome", "default_outcome"):
    P.SCHEMA["properties"][f] = {"enum": P.OUTCOMES}
P.SCHEMA["properties"]["rules"]["items"]["properties"]["outcome"] = {"enum": P.OUTCOMES}
P.load_doc = lambda: open(os.path.join(P.DATA, spec["doc_file"])).read().split("\n", 1)[1]
_wrap = P.to_capability


def to_capability(p: dict, model_sha: str) -> dict:
    c = _wrap(p, model_sha)
    c.update(id=spec["capability_id"].replace(".compiled", ".baseline-a"), intended_task=spec["intended_task"], outcomes=P.OUTCOMES,
             required={"tenant": spec["tenant"], "min_clearance": spec["clearance"], "security_domain": spec["domain"]},
             evidence_refs=[spec["doc_id"]] + [d["id"] for d in P.demos()])
    c["dependencies"] = {"knowledge": {spec["doc_id"]: ""}, "policy_version": spec["policy_version"], "execution_model_sha256": None}
    return c


P.to_capability = to_capability
P.main()
