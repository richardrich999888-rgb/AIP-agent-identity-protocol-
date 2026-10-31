"""Score extractor runs. usage: extract_report.py RESULTS_DIR

Per split and method:
  decision_acc      decision (1-4 or ABSTAIN) equals label
  released          items with a non-ABSTAIN decision
  correct_release   released and decision == label
  wrong_release     released and decision != label (incl. releasing on an ABSTAIN item)
  correct_abstain   ABSTAIN on an ABSTAIN item
  coverage          correct_release / answerable items
  release_precision correct_release / released
  extraction_exact  predicted reading set == gold set (keys equal; values within 2 %)
  latency p50/p95/p99, tokens (LLM)
Paired bootstrap of correct-release indicator between methods on identical items.
"""
from __future__ import annotations

import glob
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import metrics as M  # noqa: E402

REL_TOL = 0.02


def same_readings(pred: list, gold: list) -> bool:
    if len(pred) != len(gold):
        return False
    g = sorted(gold)
    p = sorted(pred)
    return all(pk == gk and abs(pv - gv) <= REL_TOL * max(1.0, abs(gv)) for (pk, pv), (gk, gv) in zip(p, g))


def score(rows: list) -> dict:
    n = len(rows)
    lab = np.array([r["label"] for r in rows])
    dec = np.array([r["decision"] for r in rows])
    rel = dec != "ABSTAIN"
    ans = lab != "ABSTAIN"
    corr = dec == lab
    cr = rel & corr
    lat = M.latency_summary([r["latency_s"] for r in rows])
    toks = [r.get("completion_tokens") for r in rows if r.get("completion_tokens") is not None]
    lo, hi = M.bootstrap_ci(lambda y, x: float(np.mean(x)), corr.astype(float), cr.astype(float), seed=0)
    return {
        "n": n,
        "decision_acc": float(corr.mean()),
        "released": int(rel.sum()),
        "correct_release": int(cr.sum()),
        "wrong_release": int((rel & ~corr).sum()),
        "correct_abstain": int((~rel & ~ans).sum()),
        "abstain_items": int((~ans).sum()),
        "coverage": float(cr.sum() / max(1, ans.sum())),
        "coverage_ci95": [lo * n / max(1, ans.sum()), hi * n / max(1, ans.sum())],
        "release_precision": float(cr.sum() / max(1, rel.sum())),
        "extraction_exact": float(np.mean([same_readings(r["readings"], r["gold_readings"]) for r in rows])),
        "tokens_mean": float(np.mean(toks)) if toks else None,
        **{k: lat[k] for k in ("p50_ms", "p95_ms", "p99_ms", "decisions_per_s")},
    }


def main(root: str) -> None:
    runs = {}
    for d in sorted(glob.glob(os.path.join(root, "*/run.json"))):
        mdir = os.path.dirname(d)
        name = os.path.basename(mdir)
        runs[name] = {"meta": json.load(open(d)), "splits": {}}
        for f in glob.glob(os.path.join(mdir, "*.jsonl")):
            runs[name]["splits"][os.path.basename(f)[:-6]] = [json.loads(l) for l in open(f)]
    # "+gate" variants: the deterministic equipment-registry gate (methods/
    # extractors.unregistered_equipment) applied to each method's stored
    # decisions. The gate reads only the report text.
    from methods.extractors import unregistered_equipment
    from harness.extract_eval import SPLITS, load
    texts = {r["id"]: r["text"] for path in SPLITS.values() if os.path.exists(path) for r in load(path)}
    for name in list(runs):
        if name.startswith("rules_"):
            continue
        g = {"meta": runs[name]["meta"], "splits": {}}
        for s_, rows in runs[name]["splits"].items():
            g["splits"][s_] = [{**x, "decision": "ABSTAIN" if unregistered_equipment(texts[x["id"]]) else x["decision"],
                                "readings": [] if unregistered_equipment(texts[x["id"]]) else x["readings"]} for x in rows]
        runs[name + "+gate"] = g
    out = {}
    for name, r in runs.items():
        out[name] = {"meta": {k: r["meta"].get(k) for k in ("model", "client_peak_rss_mb", "server_peak_rss_mb", "load_seconds", "train_seconds")}}
        for s, rows in r["splits"].items():
            out[name][s] = score(rows)
            if s in ("hard_v3", "hard_v4"):
                cats = sorted({x["category"] for x in rows})
                out[name][s]["by_category"] = {c: {"n": sum(x["category"] == c for x in rows),
                                                   "correct": sum(x["category"] == c and x["decision"] == x["label"] for x in rows),
                                                   "wrong_release": sum(x["category"] == c and x["decision"] != "ABSTAIN" and x["decision"] != x["label"] for x in rows)}
                                               for c in cats}
    # Paired comparisons on each hard split.
    comps = {}
    for split in ("hard_v3", "hard_v4"):
      names = [n for n in runs if split in runs[n]["splits"]]
      for a in names:
        for b in names:
            if a >= b:
                continue
            A = {x["id"]: x for x in runs[a]["splits"][split]}
            B = {x["id"]: x for x in runs[b]["splits"][split]}
            if set(A) != set(B):
                continue
            ids = sorted(A)
            y = np.ones(len(ids), dtype=int)
            pa = np.array([1 if A[i]["decision"] == A[i]["label"] else 0 for i in ids])
            pb = np.array([1 if B[i]["decision"] == B[i]["label"] else 0 for i in ids])
            comps[f"[{split}] {a} vs {b}"] = M.paired_bootstrap_diff(y, pa, pb)
    out["_paired_decision_acc"] = comps
    json.dump(out, open(os.path.join(root, "summary.json"), "w"), indent=2)

    lines = ["| method | split | n | decision acc | correct rel. | wrong rel. | correct abstain | coverage | rel. precision | extraction exact | p50 ms | p95 ms | tokens | peak RSS MB |",
             "|" + "---|" * 14]
    for name in sorted(out):
        if name.startswith("_"):
            continue
        mt = out[name]["meta"]
        rss = mt.get("server_peak_rss_mb") or mt.get("client_peak_rss_mb")
        for s in ("hard_v3", "hard_v4", "v2_test_para", "v2_test_ood"):
            e = out[name].get(s)
            if not e:
                continue
            lines.append(f"| {name} | {s} | {e['n']} | {e['decision_acc']:.3f} | {e['correct_release']} | {e['wrong_release']} | "
                         f"{e['correct_abstain']}/{e['abstain_items']} | {e['coverage']:.3f} | {e['release_precision']:.3f} | "
                         f"{e['extraction_exact']:.3f} | {e['p50_ms']:.1f} | {e['p95_ms']:.1f} | "
                         f"{'' if e['tokens_mean'] is None else round(e['tokens_mean'])} | {'' if rss is None else round(rss)} |")
    cat_lines = []
    for split in ("hard_v3", "hard_v4"):
        meths = [n for n in sorted(out) if not n.startswith("_") and split in out[n]]
        if not meths:
            continue
        cat_lines += ["", f"{split}: correct ✓ / wrong release ✗ by category", ""]
        cats = sorted({c for n in meths for c in out[n][split]["by_category"]})
        cat_lines.append("| category | n | " + " | ".join(meths) + " |")
        cat_lines.append("|" + "---|" * (2 + len(meths)))
        for c in cats:
            row = [c, str(out[meths[0]][split]["by_category"].get(c, {}).get("n", ""))]
            for n in meths:
                bc = out[n][split]["by_category"].get(c, {})
                row.append(f"{bc.get('correct', 0)}✓/{bc.get('wrong_release', 0)}✗")
            cat_lines.append("| " + " | ".join(row) + " |")
    txt = "\n".join(lines + cat_lines) + "\n"
    open(os.path.join(root, "REPORT.md"), "w").write(txt)
    print(txt)


if __name__ == "__main__":
    main(sys.argv[1])
