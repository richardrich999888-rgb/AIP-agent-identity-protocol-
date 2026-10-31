"""Engineer corrections to a model-filled IR, counted mechanically.

usage: correct_ir.py DRAFT.ir.json TASK.json OUT_DIR

The engineer edits typed fields (numbers, enums, short word lists) instead of
code. The edit count is computed, not asserted: the number of leaf values
that differ between the model's draft and the corrected IR (a list element
added or removed counts its leaves). Each correction cites the HU-BT-4 text.
Written from the document only, before the corrected capability was run on
the fresh unseen set.
"""
from __future__ import annotations

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ir_compiler import compile_ir  # noqa: E402

CITES = [
    "inputs: SG is the cue used in requests ('specific gravity (SG)'); no second cued input exists",
    "out_of_scope_limits: 'A voltage above 3 volts is a block or string voltage ... out of scope'",
    "validity: only 'electrolyte temperature must be between 5 and 45'; no voltage or SG validity range",
    "correction: 'adding 0.003 volts for every degree Celsius above 25' -> add_per_degree, rate 0.003 V, reference 25 °C",
    "rules: '< 2.10 replace; < 2.17 equalize; > 2.30 reduce float; SG < 1.200 equalize', on the corrected voltage",
    "default_outcome: 'Otherwise accept'",
]


def correct(d: dict) -> dict:
    c = copy.deepcopy(d)
    c["inputs"] = [{"ref": "voltage", "unit": "V", "cues": []}, {"ref": "temperature", "unit": "°C", "cues": []},
                   {"ref": "cued_1", "unit": "none", "cues": ["SG", "specific gravity"]}]
    c["out_of_scope_limits"] = [{"ref": "voltage", "op": ">", "value": 3, "unit": "V"}]
    c["validity"] = [{"ref": "temperature", "min": 5, "max": 45, "unit": "°C", "outcome": "INVALID_TEST"}]
    c["correction"].update(template="add_per_degree", target="voltage", by="temperature", reference=25,
                           reference_unit="°C", rate=0.003, rate_unit="V")
    r = lambda v, op, n, u, o: {"value": v, "op": op, "against": "number", "number": n, "unit": u, "limit_fraction": 1, "outcome": o}
    c["rules"] = [r("corrected", "<", 2.10, "V", "REPLACE_CELL"), r("corrected", "<", 2.17, "V", "EQUALIZE"),
                  r("corrected", ">", 2.30, "V", "REDUCE_FLOAT"), r("cued_1", "<", 1.200, "none", "EQUALIZE")]
    c["default_outcome"] = "ACCEPT"
    return c


def leaves(x, path=""):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from leaves(v, f"{path}.{k}")
    elif isinstance(x, list):
        for i, v in enumerate(x):
            yield from leaves(v, f"{path}[{i}]")
    else:
        yield path, x


def edit_count(a: dict, b: dict) -> int:
    la, lb = dict(leaves(a)), dict(leaves(b))
    return sum(1 for k in set(la) | set(lb) if la.get(k, object()) != lb.get(k, object()))


def main() -> None:
    draft, task, out = json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), sys.argv[3]
    os.makedirs(out, exist_ok=True)
    fixed = correct(draft)
    spec = {**task, "proposed_by": "model:" + "corrected-draft", "demo_ids": []}
    cap = compile_ir(fixed, spec).capability
    cap["proposed_by"] = draft.get("_proposed_by", cap["proposed_by"])
    json.dump(fixed, open(os.path.join(out, "corrected.ir.json"), "w"), indent=1, ensure_ascii=False)
    json.dump(cap, open(os.path.join(out, "capability.json"), "w"), indent=1, ensure_ascii=False)
    rec = {"draft": sys.argv[1], "sections_corrected": len(CITES), "cites": CITES,
           "leaf_edits": edit_count(draft, fixed), "draft_leaves": len(dict(leaves(draft))),
           "corrected_leaves": len(dict(leaves(fixed)))}
    json.dump(rec, open(os.path.join(out, "corrections.json"), "w"), indent=1)
    print(json.dumps({k: rec[k] for k in ("sections_corrected", "leaf_edits", "draft_leaves", "corrected_leaves")}))


if __name__ == "__main__":
    main()
