"""R2b — capability collision as a library grows, and a specificity fix (H4/H5).

usage: fp_collision.py OUT_DIR

Puts the three validated capabilities in one library and counts, for every
unseen and validation item of every family, how many capabilities activate
(any label other than NOT_APPLICABLE). >1 = the runtime refuses it as an
ambiguous capability. Variant "signature": activation requires every
declared input to be present and at least one topic term (unit spellings no
longer count as topic). Reported: collisions, own-family coverage lost, and
own-family strict accuracy, for both variants. Rules fixed before running.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CL = os.path.join(HERE, "..")
BIN = os.path.join(CL, "..", "..", "target", "release", "syntriass")
CAPS = {"ir": ("data/ir-tasks-v1", "results/corrected/capability.json", ["motor"]),
        "bt": ("data/bt-tasks-v1", "results/sprint/corrected_bt/capability.json", ["cell", "battery"]),
        "tx": ("data/tx-tasks-v1", "results/v02/engineer_tx/capability.json", ["transformer", "TX"])}
UNIT_WORDS = {"V", "volt", "volts", "kV", "megohm", "megohms", "MΩ", "Mohm", "GΩ", "kΩ"}


def signature(cap: dict, topic: list) -> dict:
    """Topic noun required (as an extra term set) and all inputs present."""
    c = copy.deepcopy(cap)
    terms = [t for t in c["applicability"]["any_terms"] if t not in UNIT_WORDS]
    c["applicability"]["any_terms"] = list(dict.fromkeys(topic + [t.lower() for t in topic] + terms))
    c["applicability"]["min_inputs_present"] = len(c["procedure"]["inputs"])
    c["id"] += ".signature"
    return c


def rows(d):
    out = []
    for f in ("test_unseen.jsonl", "validation.jsonl"):
        out += [json.loads(l) for l in open(os.path.join(CL, d, f))]
    return out


def run(cap_path, items, o, tag):
    cases = os.path.join(o, f"{tag}.cases.jsonl")
    with open(cases, "w") as f:
        f.writelines(json.dumps({"id": r["id"], "text": r["text"], "label": r["label"]}, ensure_ascii=False) + "\n" for r in items)
    out = subprocess.run([BIN, "cap-check", "--file", cap_path, "--cases", cases], capture_output=True, text=True, check=True).stdout
    return {json.loads(l)["id"]: json.loads(l)["got"] for l in out.splitlines()}


def main():
    o = sys.argv[1]
    os.makedirs(o, exist_ok=True)
    items = {f: [{**r, "id": f"{f}:{r['id']}", "fam": f} for r in rows(d)] for f, (d, _, _) in CAPS.items()}
    allit = [r for v in items.values() for r in v]
    res = {}
    for variant in ("original", "signature"):
        got = {}
        for f, (d, cp, topic) in CAPS.items():
            cap = json.load(open(os.path.join(CL, cp)))
            if variant == "signature":
                cap = signature(cap, topic)
            p = os.path.join(o, f"{variant}_{f}.capability.json")
            json.dump(cap, open(p, "w"), indent=1, ensure_ascii=False)
            got[f] = run(p, allit, o, f"{variant}_{f}")
        per = {}
        for f in CAPS:
            own = items[f]
            act = lambda r, c: got[c][r["id"]] != "NOT_APPLICABLE"
            n_coll = sum(1 for r in own if sum(act(r, c) for c in CAPS) > 1)
            own_act = sum(act(r, f) for r in own)
            # strict accuracy if routed to own capability only when it alone activates
            strict_alone = sum(1 for r in own if got[f][r["id"]] == r["label"] and sum(act(r, c) for c in CAPS) == 1)
            strict_own = sum(1 for r in own if got[f][r["id"]] == r["label"])
            foreign = sum(1 for r in allit if r["fam"] != f and act(r, f))
            per[f] = {"items": len(own), "own_activates": own_act, "collide": n_coll, "strict_own_cap": strict_own,
                      "strict_in_shared_library": strict_alone,
                      "foreign_items_claimed": f"{foreign}/{sum(1 for r in allit if r['fam'] != f)}"}
        res[variant] = per
    json.dump(res, open(os.path.join(o, "summary.json"), "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
