"""Compute all metrics from raw prediction files and write a machine-readable
summary plus a markdown table.

usage: report.py RESULTS_DIR

Discovers every */preds_<split>.jsonl under RESULTS_DIR. Adds composed
methods without new inference:

  cascade(<llm>)  symbolic first; items where symbolic abstains are answered
                  by the LLM readout. Latency = symbolic latency + LLM latency
                  on escalated items only. Requires the LLM readout to have
                  covered every item of the split (no --limit).

Comparisons between methods use only the items both covered (json_gen runs
on a stratified subset).
"""
from __future__ import annotations

import glob
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import metrics as M  # noqa: E402

SPLITS = ("test_id", "test_para", "test_ood")


def load_method(d: str) -> dict:
    out = {}
    for s in SPLITS:
        p = os.path.join(d, f"preds_{s}.jsonl")
        if os.path.exists(p):
            out[s] = {r["id"]: r for r in map(json.loads, open(p))}
    meta = json.load(open(os.path.join(d, "run.json"))) if os.path.exists(os.path.join(d, "run.json")) else {}
    return {"preds": out, "meta": meta}


def evaluate(rows: list) -> dict:
    y = np.array([r["label"] for r in rows])
    p = np.array([r["probs"] for r in rows])
    pred = np.array([r["pred"] for r in rows])
    lat = M.latency_summary([r["latency_s"] for r in rows])
    lo, hi = M.bootstrap_ci(M.accuracy, y, pred, seed=0)
    abst = sum(bool(r.get("extra", {}).get("abstained")) for r in rows)
    return {
        "n": len(rows),
        "accuracy": M.accuracy(y, pred),
        "accuracy_ci95": [lo, hi],
        "macro_f1": M.macro_f1(y, pred),
        "ece": M.ece(y, p),
        "brier": M.brier(y, p),
        "aurc": M.aurc(y, p),
        "risk_coverage": M.risk_coverage(y, p),
        "abstained": abst,
        **lat,
    }


def compose_cascade(sym: dict, llm: dict) -> dict:
    out = {}
    for s in SPLITS:
        if s not in sym or s not in llm or set(sym[s]) - set(llm[s]):
            continue
        rows = {}
        for i, r in sym[s].items():
            if r["extra"].get("abstained"):
                l = llm[s][i]
                rows[i] = {**l, "latency_s": r["latency_s"] + l["latency_s"], "extra": {"escalated": True}}
            else:
                rows[i] = {**r, "extra": {"escalated": False}}
        out[s] = rows
    return out


def main(root: str) -> None:
    methods = {}
    dirs = sorted({os.path.dirname(d) for d in glob.glob(os.path.join(root, "**", "preds_*.jsonl"), recursive=True)})
    for mdir in dirs:
        name = os.path.relpath(mdir, root)
        methods[name] = load_method(mdir)
    sym = methods.get("symbolic", {}).get("preds", {})
    # Cascade: exact rules first; a learned method answers only where the
    # rules abstain. Built for every learned method that covered a full split.
    for name in list(methods):
        leaf = name.split("/")[-1]
        if not sym or "invalid" in name or not (leaf == "readout" or leaf.startswith("extract_") or name == "tfidf"):
            continue
        casc = compose_cascade(sym, methods[name]["preds"])
        if casc:
            methods[f"cascade[symbolic→{name}]"] = {"preds": casc, "meta": {**methods[name]["meta"], "method": f"cascade(symbolic→{name})"}}

    summary = {}
    for name, m in methods.items():
        summary[name] = {"meta": {k: m["meta"].get(k) for k in ("method", "model", "temperature", "server_peak_rss_mb", "client_peak_rss_mb", "cache_prompt", "limit_per_split")}}
        for s, rows in m["preds"].items():
            ev = evaluate(list(rows.values()))
            if name.startswith("cascade["):
                ev["escalated"] = sum(r["extra"]["escalated"] for r in rows.values())
            if "/json" in name:
                ev["completion_tokens_mean"] = float(np.mean([r["extra"].get("completion_tokens") or 0 for r in rows.values()]))
                ev["unparsed"] = sum(not r["extra"].get("parsed", True) for r in rows.values())
            masses = [r.get("extra", {}).get("label_mass") for r in rows.values()]
            masses = [x for x in masses if x is not None]
            if masses:
                ev["label_mass_median"] = float(np.median(masses))
            summary[name][s] = ev

    # Paired comparisons on shared items: readout vs json (same model), and
    # every method vs symbolic.
    comps = {}
    for name, m in methods.items():
        if "/json" not in name:
            continue
        base, variant = name.split("/json", 1)
        ro = methods.get(base + "/readout")
        if not ro:
            continue
        for s in SPLITS:
            ids = sorted(set(m["preds"].get(s, {})) & set(ro["preds"].get(s, {})))
            if not ids:
                continue
            y = np.array([m["preds"][s][i]["label"] for i in ids])
            a = np.array([ro["preds"][s][i]["pred"] for i in ids])
            b = np.array([m["preds"][s][i]["pred"] for i in ids])
            la = M.latency_summary([ro["preds"][s][i]["latency_s"] for i in ids])
            lb = M.latency_summary([m["preds"][s][i]["latency_s"] for i in ids])
            comps[f"{base}: readout vs json{variant} [{s}]"] = {
                "n": len(ids),
                "accuracy_readout_minus_json": M.paired_bootstrap_diff(y, a, b),
                "p95_ms_readout": la["p95_ms"],
                "p95_ms_json": lb["p95_ms"],
                "p95_reduction": 1 - la["p95_ms"] / lb["p95_ms"],
                "throughput_ratio": la["decisions_per_s"] / lb["decisions_per_s"],
            }
    summary["_comparisons"] = comps
    with open(os.path.join(root, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    lines = ["| method | split | n | acc [95% CI] | macro-F1 | ECE | Brier | AURC | p50 ms | p95 ms | p99 ms | dec/s | notes |", "|" + "---|" * 13]
    for name in sorted(k for k in summary if not k.startswith("_")):
        for s in SPLITS:
            e = summary[name].get(s)
            if not e:
                continue
            note = []
            if e["abstained"]:
                note.append(f"abstained {e['abstained']}")
            if "escalated" in e:
                note.append(f"escalated {e['escalated']}")
            if "unparsed" in e and e["unparsed"]:
                note.append(f"unparsed {e['unparsed']}")
            if "label_mass_median" in e:
                note.append(f"label mass {e['label_mass_median']:.2f}")
            if "completion_tokens_mean" in e:
                note.append(f"{e['completion_tokens_mean']:.0f} gen tokens")
            lines.append(
                f"| {name} | {s} | {e['n']} | {e['accuracy']:.3f} [{e['accuracy_ci95'][0]:.3f}, {e['accuracy_ci95'][1]:.3f}] | "
                f"{e['macro_f1']:.3f} | {e['ece']:.3f} | {e['brier']:.3f} | {e['aurc']:.3f} | {e['p50_ms']:.2f} | {e['p95_ms']:.2f} | "
                f"{e['p99_ms']:.2f} | {e['decisions_per_s']:.1f} | {'; '.join(note)} |"
            )
    lines += ["", "| comparison | n | Δacc (readout − json) [95% CI] | P(readout ≤ json) | p95 readout ms | p95 json ms | p95 reduction | throughput × |", "|" + "---|" * 8]
    for k, c in comps.items():
        d = c["accuracy_readout_minus_json"]
        lines.append(f"| {k} | {c['n']} | {d['diff']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}] | {d['p_a_not_better']:.3f} | {c['p95_ms_readout']:.0f} | {c['p95_ms_json']:.0f} | {c['p95_reduction']:.0%} | {c['throughput_ratio']:.1f} |")
    mem = ["", "| method | server peak RSS MB | client peak RSS MB | temperature |", "|---|---|---|---|"]
    for name in sorted(k for k in summary if not k.startswith("_")):
        mt = summary[name]["meta"]
        mem.append(f"| {name} | {mt.get('server_peak_rss_mb') or '—'} | {round(mt['client_peak_rss_mb'], 1) if mt.get('client_peak_rss_mb') else '—'} | {round(mt['temperature'], 3) if mt.get('temperature') else '—'} |")
    with open(os.path.join(root, "REPORT.md"), "w") as f:
        f.write("\n".join(lines + mem) + "\n")
    print("\n".join(lines + mem))


if __name__ == "__main__":
    main(sys.argv[1])
