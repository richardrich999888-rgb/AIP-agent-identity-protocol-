"""Deploy and evaluate a capability for any task spec through the real runtime.

usage: run_task.py OUT_DIR TASK.json CAPABILITY.json

The unchanged run_learning.py functions (setup, lifecycle, serve, score) with
the task's data, principal, expert/approver ids, domain and policy applied.
Requests: test_unseen + false_activation as the owning principal; 6 unseen
items as another tenant, as the same tenant at lower clearance, and as
another tenant invoking the capability explicitly.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_learning as R  # noqa: E402

out, task_path, cap_path = sys.argv[1:4]
spec = json.load(open(task_path))
R.DATA = os.path.join(R.ROOT, "research/capability-learning", spec["data"])
OWNER = {"tenant": spec["tenant"], "clearance": spec["clearance"]}
R.EXPERT, R.APPROVER = f"expert:{spec['tenant']}-lead", f"user:{spec['tenant']}-authority"
if spec.get("counterexample_from_file"):
    R.COUNTEREX = set()  # flags are in validation.jsonl already; keep them


def setup(o, profile):
    keys = os.path.join(o, "keys")
    os.makedirs(keys, exist_ok=True)
    pub = {}
    for who, f in ((R.EXPERT, "expert.json"), (R.APPROVER, "approver.json")):
        p = os.path.join(keys, f)
        if not os.path.exists(p):
            R.run([R.BIN, "keygen", "--id", who, "--out", p])
        pub[who] = json.load(open(p))["public_hex"]
    json.dump({R.APPROVER: pub[R.APPROVER]}, open(os.path.join(keys, "approvers.json"), "w"))
    json.dump({R.EXPERT: pub[R.EXPERT]}, open(os.path.join(keys, "experts.json"), "w"))
    state = os.path.join(o, "state")
    R.run([sys.executable, R.MKCONFIG, state, profile, "--approvers", os.path.join(keys, "approvers.json"),
           "--experts", os.path.join(keys, "experts.json"), "--domain", spec["domain"], "--policy", spec["policy_version"],
           "--corpus", os.path.join(R.DATA, "corpus")], env={**os.environ, "SYNTRIASS_BIN": R.BIN})
    return os.path.join(state, "config.json"), {"keys": keys}


def lifecycle(cfg, keys, cap, o):
    cases = os.path.join(o, "suite_cases.jsonl")
    with open(cases, "w") as f:
        for r in R.rows("validation.jsonl"):
            f.write(json.dumps({**r, "counterexample": r.get("counterexample", r["label"] in R.COUNTEREX)}) + "\n")
    suite = os.path.join(o, "suite.json")
    R.run([R.BIN, "suite-sign", "--key", os.path.join(keys, "expert.json"), "--cases", cases, "--suite-id",
           f"{spec['family']}/validation", "--tenant", spec["tenant"], "--task", spec["suite_task"], "--out", suite])
    h = json.loads(R.run([R.BIN, "cap-propose", "--config", cfg, "--file", cap]))["hash"]
    rep = json.loads(R.run([R.BIN, "cap-validate", "--config", cfg, "--hash", h, "--suite", suite]))
    res = {"hash": h, "validation": rep}
    if rep["passed"]:
        R.run([R.BIN, "cap-approve", "--config", cfg, "--hash", h, "--key", os.path.join(keys, "approver.json")])
        R.run([R.BIN, "cap-transition", "--config", cfg, "--hash", h, "--to", "ACTIVE", "--role", "operator",
               "--actor", f"operator:{spec['domain']}", "--reason", "approved for service"])
    return res


os.makedirs(out, exist_ok=True)
cfg, k = setup(os.path.join(out, "deploy"), "balanced")
life = lifecycle(cfg, k["keys"], cap_path, os.path.join(out, "deploy"))
report = {"task": spec["family"], "capability_file": cap_path, "lifecycle": life}
if life["validation"]["passed"]:
    unseen, fa = R.rows("test_unseen.jsonl"), R.rows("false_activation.jsonl")
    evalset = unseen + fa
    cap_id = json.load(open(cap_path))["id"]
    s6 = unseen[:6]
    reqs = (R.requests(evalset, OWNER, "d") + R.requests(s6, {"tenant": "tarvel-grid", "clearance": "restricted"}, "x-tenant")
            + R.requests(s6, {"tenant": spec["tenant"], "clearance": "internal"}, "x-clear")
            + R.requests(s6, {"tenant": "tarvel-grid", "clearance": "restricted"}, "x-invoke", capability=cap_id))
    res = R.serve(cfg, reqs, os.path.join(out, "responses.jsonl"))
    report["unseen"] = R.score(evalset, [r for r in res if r["id"].startswith("d:")])
    sec = [r for r in res if r["id"].startswith("x-")]
    report["unauthorized"] = {"n": len(sec), "capability_used": sum("Capability" in json.dumps(r.get("response", {}).get("strategy")) for r in sec)}
json.dump(report, open(os.path.join(out, "report.json"), "w"), indent=1)
print(json.dumps({"validated": life["validation"]["passed"], "failures": len(life["validation"]["failures"]),
                  "unseen": [report.get("unseen", {}).get("correct"), report.get("unseen", {}).get("n")],
                  "unauthorized_used": report.get("unauthorized", {}).get("capability_used")}))
