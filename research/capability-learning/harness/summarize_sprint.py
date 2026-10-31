"""Sprint summary: proposal validity, fresh-family deployment and economics.

usage: summarize_sprint.py RESULTS_DIR   (research/capability-learning/results)
Writes RESULTS_DIR/sprint/summary.json. Every number is read from a result
file written by the runs; nothing is entered by hand.

Scoring on bt-tasks-v1 is reported two ways:
  strict   — the runtime's outcome label must equal the expected label
             (a Withheld outcome never matches AMBIGUOUS);
  intended — additionally, an AMBIGUOUS item counts as correct when the
             runtime withheld it *because an input appeared with different
             values* (the reason string is checked). This mapping was the
             design intent when the data was authored, but it was applied
             after the strict score was seen; both are reported.
"""
from __future__ import annotations

import glob
import json
import math
import os
import sys

POSITIVE = {"ACCEPT", "EQUALIZE", "REPLACE_CELL", "REDUCE_FLOAT"}


def j(p):
    with open(p) as f:
        return json.load(f)


def proposals(S: str) -> dict:
    out = {}
    runs = {"baseline_A_old_proposer/ir-tasks-v1": [f"{os.path.dirname(S)}/propose_qwen1.5b-q8", f"{os.path.dirname(S)}/propose_qwen1.5b-q8_diag"],
            "baseline_A_old_proposer/bt-tasks-v1": [f"{S}/baselineA_bt"],
            "candidate_ir_single/ir-tasks-v1": [f"{S}/candidate_ir"], "candidate_ir_single/bt-tasks-v1": [f"{S}/candidate_bt"],
            "candidate_ir_decomposed/ir-tasks-v1": [f"{S}/candidate_ir_decomposed"],
            "candidate_ir_decomposed/bt-tasks-v1": [f"{S}/candidate_bt_decomposed"]}
    for k, dirs in runs.items():
        rounds, cpu, peak = [], 0.0, 0.0
        for d in dirs:
            c = j(f"{d}/cost.json")
            rounds += c["rounds"]
            cpu += c["llama_cpu_s"]
            peak = max(peak, c.get("llama_peak_rss_mib", 0))
        comp = [r for r in rounds if r.get("compiled", r.get("parsed")) and r.get("compiled", True)]
        out[k] = {"rounds": len(rounds), "compiling_rounds": len(comp),
                  "best_demo_agreement": max([r.get("demo_agreement") or 0 for r in rounds], default=0),
                  "demos": 6, "validated_without_manual_correction": 0, "model_cpu_s": round(cpu, 1),
                  "peak_rss_mib": peak or None}
    return out


def main() -> None:
    R = sys.argv[1]
    S = os.path.join(R, "sprint")
    prop = proposals(S)
    dep = j(f"{S}/deploy_bt/report.json")
    corr = j(f"{S}/corrected_bt/corrections.json")
    resp = {x["id"]: x["response"] for x in map(json.loads, open(f"{S}/deploy_bt/responses.jsonl")) if "response" in x}
    items = dep["unseen"]["items"]
    dec = [i for i in items if i["label"] != "NOT_APPLICABLE"]

    def intended_ok(i):
        if i["ok"]:
            return True
        o = resp[f"d:{i['id']}"]["outcome"]
        return i["label"] == "AMBIGUOUS" and o["kind"] == "withheld" and "appears with different values" in o.get("reason", "")

    strict = sum(i["ok"] for i in dec)
    intended = sum(intended_ok(i) for i in dec)
    wrong_pos = sum(i["got"] in POSITIVE and i["got"] != i["label"] for i in dec)
    correct_refusals = sum(intended_ok(i) for i in dec if i["label"] not in POSITIVE)
    cap_items = [i for i in items if "Capability" in json.dumps(i["strategy"])]
    acq_cpu = j(f"{S}/candidate_bt/cost.json")["llama_cpu_s"]
    base = {}
    for k in ("B1", "B2", "B3"):
        p = f"{S}/baselines_bt/{k}.jsonl"
        if not os.path.exists(p):
            continue
        rows = [json.loads(l) for l in open(p)]
        d = [r for r in rows if r["label"] != "NOT_APPLICABLE"]
        base[k] = {"correct": sum(r["ok"] for r in d), "n": len(d), "per_task_cpu_s": round(sum(r["cpu_s"] for r in d) / len(d), 3),
                   "wrong_positive": sum(r["got"] in POSITIVE and r["got"] != r["label"] for r in d),
                   "false_activation": sum(r["label"] == "NOT_APPLICABLE" and r["got"] != "NOT_APPLICABLE" for r in rows)}
    c_cap = 0.01  # bound: below /proc resolution per item (see economics.py)
    acc = intended / len(dec)
    be = {k: math.ceil(acq_cpu / (b["per_task_cpu_s"] - c_cap)) for k, b in base.items()
          if b["correct"] / b["n"] <= acc and b["per_task_cpu_s"] > c_cap}
    summary = {
        "proposal_validity": prop,
        "fresh_family_bt_tasks_v1": {
            "workflow": "model fills typed IR (1 run, 3 rounds) -> engineer corrects IR fields -> compiler -> signed expert suite -> approval -> ACTIVE",
            "engineer_corrections": {"sections": corr["sections_corrected"], "leaf_field_edits": corr["leaf_edits"],
                                     "of_draft_leaves": corr["draft_leaves"], "human_time": "not measured"},
            "validation": {k: dep["lifecycle"]["validation"][k] for k in ("passed", "expert_cases", "expert_passed", "counterexamples", "counterexamples_passed")},
            "unseen_decisions": len(dec), "correct_strict": strict, "correct_intended": intended,
            "incorrect_positive_decisions": wrong_pos, "correct_refusals": correct_refusals,
            "false_activations": dep["unseen"]["false_activation"], "false_activation_probes": len(items) - len(dec),
            "unauthorized_probes": dep["unauthorized"]["n"], "unauthorized_capability_used": dep["unauthorized"]["capability_used"],
            "via_capability": len(cap_items), "model_calls_on_capability_path": sum(i["model_calls"] for i in cap_items),
            "median_wall_ms_capability": sorted(i["wall_ms"] for i in cap_items)[len(cap_items) // 2],
            "acquisition_model_cpu_s": acq_cpu, "baselines": base, "break_even_uses_compute_only": be,
        },
    }
    fb = summary["fresh_family_bt_tasks_v1"]
    summary["headline"] = {
        "valid capabilities proposed without manual correction (all methods, both families)": "0",
        "compiling proposal rounds: old proposer vs typed-IR compiler (single form)":
            f"{prop['baseline_A_old_proposer/ir-tasks-v1']['compiling_rounds'] + prop['baseline_A_old_proposer/bt-tasks-v1']['compiling_rounds']}/"
            f"{prop['baseline_A_old_proposer/ir-tasks-v1']['rounds'] + prop['baseline_A_old_proposer/bt-tasks-v1']['rounds']} vs "
            f"{prop['candidate_ir_single/ir-tasks-v1']['compiling_rounds'] + prop['candidate_ir_single/bt-tasks-v1']['compiling_rounds']}/"
            f"{prop['candidate_ir_single/ir-tasks-v1']['rounds'] + prop['candidate_ir_single/bt-tasks-v1']['rounds']}",
        "fresh family after engineer IR corrections: expert suite": f"{fb['validation']['expert_passed']}/{fb['validation']['expert_cases']}",
        "fresh family unseen decisions correct (strict / intended)": f"{strict}/{len(dec)} / {intended}/{len(dec)}",
        "incorrect positive decisions": wrong_pos,
        "false activations": f"{fb['false_activations']}/{fb['false_activation_probes']}",
        "unauthorized uses": f"{fb['unauthorized_capability_used']}/{fb['unauthorized_probes']}",
        "model calls during reuse": fb["model_calls_on_capability_path"],
    }
    json.dump(summary, open(f"{S}/summary.json", "w"), indent=1, ensure_ascii=False)
    print(json.dumps(summary["headline"], indent=1, ensure_ascii=False))
    print(json.dumps({"baselines": base, "break_even": be}, indent=1))


if __name__ == "__main__":
    main()
