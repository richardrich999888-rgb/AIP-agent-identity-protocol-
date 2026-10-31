"""Engineer-taught baseline (v0.2 comparison arm 4): an engineer writes the
typed IR directly from the procedure document — no model draft.

usage: engineer_ir.py TASK.json OUT_DIR

Written for tx-tasks-v1 from HU-TX-2 rev A only (each field cites its
sentence), before any v0.2 result on that family was produced. Every leaf is
human-authored, so the "correction" count is the full IR leaf count.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from correct_ir import leaves  # noqa: E402
from ir_compiler import compile_ir, provenance_check  # noqa: E402

R = lambda v, op, ag, n, u, frac, o: {"value": v, "op": op, "against": ag, "number": n, "unit": u, "limit_fraction": frac, "outcome": o}
IRS = {
    "tx-tasks-v1": ({
        "topic_terms": ["transformer"],  # Scope: oil-immersed distribution transformers
        "inputs": [{"ref": "voltage", "unit": "kV", "cues": []}, {"ref": "resistance", "unit": "MΩ", "cues": []},
                   {"ref": "temperature", "unit": "°C", "cues": []},
                   {"ref": "cued_1", "unit": "none", "cues": ["DAR", "dielectric absorption ratio"]}],  # Required inputs
        "out_of_scope_terms": ["motor", "cable", "generator", "dry-type"],  # does not apply to motors, cables, generators or dry-type
        "out_of_scope_limits": [{"ref": "voltage", "op": ">", "value": 33, "unit": "kV"}],  # rated above 33 kV are out of scope
        "missing_input_outcome": "INSUFFICIENT_INPUT",
        "validity": [{"ref": "temperature", "min": 0, "max": 90, "unit": "°C", "outcome": "INVALID_TEST"}],  # Step 1
        "correction": {"template": "multiply_power_per_degree", "target": "resistance", "by": "temperature", "reference": 20,
                       "reference_unit": "°C", "rate": 0, "rate_unit": "°C", "base": 2, "step": 15},  # Step 2
        "limit": {"template": "coefficient_times_input_plus_offset", "coefficient": 20, "input": "voltage", "offset": 2, "unit": "MΩ"},  # Step 3
        "rules": [R("corrected", "<", "limit", 0, "none", 1 / 3, "REMOVE_FROM_SERVICE"),  # Step 4
                  R("corrected", "<", "limit", 0, "none", 1, "DRY_OUT_OIL"),
                  R("cued_1", "<", "number", 1.25, "none", 1, "INVESTIGATE"),
                  R("cued_1", "<", "number", 1.4, "none", 1, "MONITOR_90D")],
        "default_outcome": "ACCEPT",
    }, ["HU-TX-2 sentences: Scope; does-not-apply list; above 33 kV; Required inputs; missing -> insufficient input; "
        "Step 1 validity; Step 2 correction; Step 3 minimum; Step 4 decision (5 sentences)"]),
}


def main() -> None:
    task, out = json.load(open(sys.argv[1])), sys.argv[2]
    os.makedirs(out, exist_ok=True)
    ir, cites = IRS[task["family"]]
    doc = open(os.path.join(HERE, "..", task["data"], task["doc_file"])).read()
    spec = {**task, "proposed_by": f"user:{task['tenant']}-engineer", "demo_ids": []}
    cap = compile_ir(ir, spec).capability
    json.dump(ir, open(os.path.join(out, "engineer.ir.json"), "w"), indent=1, ensure_ascii=False)
    json.dump(cap, open(os.path.join(out, "capability.json"), "w"), indent=1, ensure_ascii=False)
    rec = {"authored_leaves": len(dict(leaves(ir))), "cites": cites, "unsupported_numbers": provenance_check(ir, doc)}
    json.dump(rec, open(os.path.join(out, "authoring.json"), "w"), indent=1)
    print(json.dumps(rec))


if __name__ == "__main__":
    main()
