"""Phase E — model replacement.

usage: phase_e.py OUT_DIR CAPABILITY.json

E1  The learned capability (model-independent execution) is installed in a
    runtime whose serving model is replaced (speed profile: Qwen2.5-1.5B Q8_0
    instead of Q4_K_M). Re-run Phase D; capability outputs must be identical
    to the Q4 run, item for item.
E2  A model-DEPENDENT variant (execution_model_sha256 = the Q4 model) is
    validated, approved and activated, then served under both profiles. Under
    Q4 it must run; under Q8 the runtime must refuse it as stale
    ("compatibility re-validation required") instead of reusing it.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_learning as R  # noqa: E402

Q4_SHA = "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"


def install(out: str, profile: str, cap_path: str) -> tuple[str, dict]:
    cfg, k = R.setup(out, profile)
    life = R.lifecycle(cfg, k["keys"], cap_path, out)
    return cfg, life


def main() -> None:
    out, cap_path = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    unseen, fa = R.rows("test_unseen.jsonl"), R.rows("false_activation.jsonl")
    evalset = unseen + fa
    rep = {}
    # E1
    cfg, life = install(os.path.join(out, "e1_speed_q8"), "speed", cap_path)
    res = R.serve(cfg, R.requests(evalset, R.KORAVI, "d"), os.path.join(out, "e1_speed_q8", "responses.jsonl"))
    rep["e1_speed_q8"] = R.score(evalset, res)
    rep["e1_validation_passed"] = life["validation"]["passed"]
    # E2
    cap = json.load(open(cap_path))
    cap["id"] = cap["id"] + ".model-bound"
    cap["dependencies"]["execution_model_sha256"] = Q4_SHA
    dep_path = os.path.join(out, "capability_model_bound.json")
    json.dump(cap, open(dep_path, "w"), indent=1, ensure_ascii=False)
    probe = unseen[:8]
    for prof in ("balanced", "speed"):
        d = os.path.join(out, f"e2_{prof}")
        cfg, life = install(d, prof, dep_path)
        res = R.serve(cfg, R.requests(probe, R.KORAVI, "d"), os.path.join(d, "responses.jsonl"))
        strategies = [json.dumps(r["response"]["strategy"]) for r in res]
        rep[f"e2_{prof}"] = {"validation_passed": life["validation"]["passed"], "n": len(res),
                             "ran_capability": sum('"Capability"' in s for s in strategies),
                             "refused_stale": sum("CapabilityStale" in s for s in strategies),
                             "strategies": strategies}
    json.dump(rep, open(os.path.join(out, "report.json"), "w"), indent=1)
    print(json.dumps({"e1": [rep["e1_speed_q8"]["correct"], rep["e1_speed_q8"]["n"]],
                      "e2_balanced": [rep["e2_balanced"]["ran_capability"], rep["e2_balanced"]["refused_stale"]],
                      "e2_speed": [rep["e2_speed"]["ran_capability"], rep["e2_speed"]["refused_stale"]]}))


if __name__ == "__main__":
    main()
