"""R2c — strongest-fit routing in a shared library (H4/H5). Rules fixed before running.

usage: fp_resonance.py OUT_DIR   (reuses fp_collision's capabilities and items)

Fit score of capability c on request r = (number of c's declared inputs present
in r) + 1 if one of c's topic nouns appears. Inputs present are measured with
the real runtime: c is re-run with min_inputs_present = k for k = 1..n; the
largest k at which it still activates is the count. The request goes to the
unique highest-scoring capability with score >= 2; ties and lower scores are
refused. The decision itself is the ORIGINAL capability's label.
"""
import copy, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fp_collision as C

o = sys.argv[1]; os.makedirs(o, exist_ok=True)
items = {f: [{**r, "id": f"{f}:{r['id']}", "fam": f} for r in C.rows(d)] for f, (d, _, _) in C.CAPS.items()}
allit = [r for v in items.values() for r in v]
score, label = {}, {}
for f, (d, cp, topic) in C.CAPS.items():
    cap = json.load(open(os.path.join(C.CL, cp)))
    p0 = os.path.join(o, f"orig_{f}.json"); json.dump(cap, open(p0, "w"), ensure_ascii=False)
    label[f] = C.run(p0, allit, o, f"orig_{f}")
    n = len(cap["procedure"]["inputs"])
    present = {r["id"]: 0 for r in allit}
    for k in range(1, n + 1):
        c = copy.deepcopy(cap)
        c["applicability"]["any_terms"] = ["\u0000never"]  # placeholder replaced below
        c["applicability"]["any_terms"] = sorted({t for t in cap["applicability"]["any_terms"]} | set(topic))
        c["applicability"]["min_inputs_present"] = k
        p = os.path.join(o, f"k{k}_{f}.json"); json.dump(c, open(p, "w"), ensure_ascii=False)
        g = C.run(p, allit, o, f"k{k}_{f}")
        for r in allit:
            if g[r["id"]] != "NOT_APPLICABLE":
                present[r["id"]] = k
    t = copy.deepcopy(cap); t["applicability"]["any_terms"] = topic + [x.lower() for x in topic]
    t["applicability"]["min_inputs_present"] = 1
    pt = os.path.join(o, f"topic_{f}.json"); json.dump(t, open(pt, "w"), ensure_ascii=False)
    gt = C.run(pt, allit, o, f"topic_{f}")
    score[f] = {r["id"]: present[r["id"]] + (1 if gt[r["id"]] != "NOT_APPLICABLE" else 0) for r in allit}
res = {}
for f in C.CAPS:
    own = items[f]; routed_ok = strict = refused = misrouted = 0
    for r in own:
        s = {c: score[c][r["id"]] for c in C.CAPS}
        best = max(s.values()); top = [c for c, v in s.items() if v == best]
        if best < 2 or len(top) > 1:
            refused += 1; continue
        if top[0] != f:
            misrouted += 1; continue
        routed_ok += 1; strict += label[f][r["id"]] == r["label"]
    res[f] = {"items": len(own), "routed_to_own": routed_ok, "misrouted": misrouted, "refused": refused, "strict": strict}
json.dump(res, open(os.path.join(o, "summary.json"), "w"), indent=1); print(json.dumps(res, indent=1))
