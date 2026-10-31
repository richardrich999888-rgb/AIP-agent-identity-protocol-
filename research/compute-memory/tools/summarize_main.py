"""Regenerate every compute/memory table from raw JSON in results/.

usage: summarize_main.py [RESULTS_DIR]   -> prints markdown tables
"""
from __future__ import annotations

import glob
import json
import os
import statistics as st
import sys


def med(xs):
    xs = list(xs)
    return st.median(xs) if xs else None


def throughput(R):
    print("| config | prefill@128 | prefill@512 | prefill@1.5k | decode (256 gen) | peak RSS MB | private MB | file MB |\n|---|---|---|---|---|---|---|---|")
    for f in sorted(glob.glob(f"{R}/main/throughput_*.json")) + sorted(glob.glob(f"{R}/e1r/throughput_*.json")):
        d = json.load(open(f))["result"]
        rows, s = d["rows"], d["server_after"]
        pf = [med(r["prefill_tok_s"] for r in rows if r["n_gen"] == 64 and abs(r["n_prompt"] - n) < 60) for n in (128, 512, 1536)]
        dc = med(r["decode_tok_s"] for r in rows if r["n_gen"] >= 256)
        tag = os.path.basename(f)[len("throughput_"):-5] + ("" if "/main/" in f else "")
        print(f"| {tag} | " + " | ".join(f"{x:.1f}" for x in pf) + f" | {dc:.1f} | {s['VmHWM']:.0f} | {s['RssAnon']:.0f} | {s['RssFile']:.0f} |")


def load(R):
    print("\n| model | mode | load s (median) | peak RSS MB | private MB | file MB |\n|---|---|---|---|---|---|")
    for f in sorted(glob.glob(f"{R}/main/load_*.json")):
        rows = json.load(open(f))["result"]["rows"]
        for mm in (True, False):
            for cold in (True, False):
                g = [r for r in rows if r["mmap"] == mm and r["cold"] == cold]
                a = [r["after_first_request"] for r in g]
                print(f"| {os.path.basename(f)[5:-5]} | {'mmap' if mm else 'no-mmap'} {'cold' if cold else 'warm'} | {med(r['load_s'] for r in g):.2f} | "
                      f"{med(x['VmHWM'] for x in a):.0f} | {med(x['RssAnon'] for x in a):.0f} | {med(x['RssFile'] for x in a):.0f} |")


def main() -> None:
    R = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "results")
    throughput(R)
    load(R)
    p = json.load(open(f"{R}/main/prefix_1.5b-q4.json"))["result"]
    print("\n| prefix cache | evaluated tokens (median, requests 2..n) | prefill ms | wall s |\n|---|---|---|---|")
    for k, v in p.items():
        print(f"| {k} | {med(x['prompt_n'] for x in v[1:]):.0f} | {med(x['prompt_ms'] for x in v[1:]):.0f} | {med(x['wall_s'] for x in v[1:]):.2f} |")
    s = json.load(open(f"{R}/main/sidechan_1.5b-q4.json"))["result"]
    print("\n| cache mode | attacker AUC | median hit s | median miss s | victim 2nd-request tokens (median) |\n|---|---|---|---|---|")
    for k, v in s.items():
        print(f"| {k} | {v['auc_attacker']:.2f} | {v['median_hit_s']:.2f} | {v['median_miss_s']:.2f} | {med(v['victim_second_request_prompt_n']):.0f} |")
    r = json.load(open(f"{R}/main/restore_1.5b-q4.json"))["result"]["rows"]
    print("\n| tokens | recompute s | restore s | file MB |\n|---|---|---|---|")
    for n in sorted({x["n_tokens"] for x in r}):
        g = [x for x in r if x["n_tokens"] == n]
        print(f"| {n} | {med(x['recompute_wall_s'] for x in g):.2f} | {med(x['restore_wall_s'] for x in g):.3f} | {g[0]['file_bytes'] / 2**20:.1f} |")
    sp = json.load(open(f"{R}/main/specdec_1.5b-q4.json"))["result"]
    print("\n| speculative | decode tok/s | accepted/drafted | peak RSS MB | outputs identical |\n|---|---|---|---|---|")
    for m in ("baseline", "draft"):
        rows = sp[m]["rows"]
        acc = sum(x["draft_n_accepted"] or 0 for x in rows), sum(x["draft_n"] or 0 for x in rows)
        print(f"| {m} | {med(x['predicted_n'] / (x['predicted_ms'] / 1000) for x in rows):.2f} | {acc[0]}/{acc[1]} | {sp[m]['server']['VmHWM']:.0f} | {sum(sp['outputs_identical'])}/{len(sp['outputs_identical'])} |")
    sh = json.load(open(f"{R}/main/shared_1.5b-q4.json"))["result"]
    print(f"\nshared mapping: solo RSS {sh['solo']['VmRSS']:.0f} PSS {sh['solo']['Pss']:.0f}; pair PSS {sh['pair']['a']['Pss']:.0f}+{sh['pair']['b']['Pss']:.0f}, private {sh['pair']['a']['RssAnon']:.0f} each")


if __name__ == "__main__":
    main()
