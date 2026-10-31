"""Summarise the v0.2 holdout (tx-tasks-v1) from recorded result files only.

usage: summarize_v02.py  → results/v02/summary.json (and prints it)

Strict accuracy first (exact label match on the 30 unseen decisions). The
withhold-for-AMBIGUOUS mapping is reported separately and was defined in
v0.1, before this family existed. Costs are CPU-seconds measured on this
2-vCPU/8 GB host; human time was not measured.
"""
from __future__ import annotations

import json
import os
import statistics

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "..", "results", "v02")
POS = {"ACCEPT", "MONITOR_90D"}  # decisions that release equipment to service


def load(p):
    return json.load(open(os.path.join(R, p)))


def score_items(items, label_key="label", got_key="got"):
    u = [x for x in items if x["id"].startswith("t-")]
    fa = [x for x in items if x["id"].startswith("fa")]
    strict = sum(x[got_key] == x[label_key] for x in u)
    mapped = sum(x[got_key] == x[label_key] or (x[label_key] == "AMBIGUOUS" and x[got_key] == "WITHHELD") for x in u)
    wrong_pos = sum(1 for x in u if x[got_key] != x[label_key] and x[got_key] in POS)
    return {"strict": strict, "withhold_mapped": mapped, "n": len(u), "wrong_release_decisions": wrong_pos,
            "false_activations": sum(x[got_key] != "NOT_APPLICABLE" for x in fa), "fa_n": len(fa)}


def deployed(path):
    r = load(path)
    out = {"validated": r["lifecycle"]["validation"]["passed"], "suite_failures": r["lifecycle"]["validation"]["failures"]}
    if "unseen" in r:
        it = r["unseen"]["items"]
        out.update(score_items(it))
        # In the deployed runtime a probe "activates" only if the capability ran.
        out["false_activations"] = sum("Capability" in json.dumps(x["strategy"]) for x in it if x["id"].startswith("fa"))
        caps = [x for x in it if x["id"].startswith("t-") and "Capability" in json.dumps(x["strategy"])]
        out.update(model_calls=sum(x["model_calls"] for x in caps), median_ms=statistics.median(x["wall_ms"] for x in caps),
                   per_task_cpu_s_upper=0.01, rss_mib=caps[0]["rss_mib"] if caps else None, unauthorized=r["unauthorized"])
    return out


def main() -> None:
    b = load("baselines_tx/summary.json")
    base = {}
    for k in ("B1", "B2", "B3"):
        rows = [json.loads(l) for l in open(os.path.join(R, "baselines_tx", f"{k}.jsonl"))]
        s = score_items(rows)
        cpu = sum(r["cpu_s"] for r in rows)
        s.update(cpu_s_total=round(cpu, 1), per_task_cpu_s=round(cpu / len(rows), 2),
                 cpu_per_correct_s=round(cpu / max(s["strict"], 1), 1), model_calls=len(rows))
        base[k] = s
    base_meta = {"model": b["model"], "load_s": b["load_s"], "peak_rss_mib": b["llama_peak_rss_mib"]}
    acq = load("holdout_tx/cost.json")
    acq_nr = load("holdout_tx_norepair/cost.json")
    tri = load("holdout_tx/triage.json")
    dry = [json.loads(l) for l in open(os.path.join(R, "dryrun_atomic_tx/check.jsonl"))]
    atomic_cpu = acq["model_cpu_s"] + 0.0
    arms = {
        "primary_pre_fix": {
            "atomic_pipeline": {"status": tri["status"], "blocking": "boundary probe b-003 (runtime did not read -0.001 °C)",
                                "demos": tri["demo_agreement"], "fields": tri["field_provenance"],
                                "unapproved_dry_run": score_items(dry, "expected", "got")},
            "engineer_taught": deployed("deploy_engineer_tx/report.json"),
        },
        "secondary_post_fix": {
            "atomic_pipeline_uncorrected": deployed("postfix/deploy_atomic_tx/report.json"),
            "atomic_plus_3_expert_edits": {**deployed("postfix/deploy_corrected_atomic_tx/report.json"),
                                           **load("postfix/corrected_atomic_tx/corrections.json")},
            "engineer_taught": {**deployed("postfix/deploy_engineer_tx/report.json"),
                                "authored_leaves": load("engineer_tx/authoring.json")["authored_leaves"]},
        },
    }
    cap_cpu = 0.01
    be = {k: (round(atomic_cpu / (v["per_task_cpu_s"] - cap_cpu), 1)) for k, v in base.items()}
    model_fields = tri["field_provenance"]
    determined = model_fields["evidence"] + model_fields["repaired"]
    summary = {
        "family": "tx-tasks-v1 (frozen 4072971, before any v0.2 pipeline code; single author)",
        "pipeline_commit": "b4371a1 (frozen after 3 dev attempts)",
        "baselines": base, "baseline_meta": base_meta, "arms": arms,
        "acquisition": {"atomic_model_calls": acq["model_calls"], "atomic_model_cpu_s": acq["model_cpu_s"],
                        "atomic_load_s": acq["load_s"], "atomic_wall_s": acq["acquisition_wall_s"], "tiers": acq["tiers"],
                        "model_agreed_with_clause_evidence": f"{model_fields['evidence']}/{determined} uniquely determined fields",
                        "no_repair_ablation": {"status": load("holdout_tx_norepair/triage.json")["status"], "model_calls": acq_nr["model_calls"],
                                               "model_cpu_s": acq_nr["model_cpu_s"], "issues": load("holdout_tx_norepair/triage.json")["field_provenance"]["issues"]},
                        "human_inputs": {"engineer_taught": "68 authored IR leaves + 12 signed cases + 1 approval",
                                         "atomic": "3 leaf edits (after a signed-suite failure) + 12 signed cases + 1 approval + 6 demonstrations"}},
        "break_even_uses_compute_only_atomic_vs": be,
        "notes": ["CPU-only, 2 vCPU / 8 GB, Qwen2.5 0.5B+1.5B Q8_0; no GPU, no energy measurement",
                  "human time not measured; break-even counts model CPU only",
                  "post-fix results follow a runtime parser fix made after the primary run; labels unchanged"],
    }
    json.dump(summary, open(os.path.join(R, "summary.json"), "w"), indent=1, ensure_ascii=False)
    print(json.dumps(summary, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
