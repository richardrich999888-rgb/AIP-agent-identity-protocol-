"""Atomic-claim proposer (v0.2): per-clause model questions, deterministic checks.

usage (inside offline.sh):
  propose_atomic.py OUT_DIR --task tasks/X.json --bin SYNTRIASS --server LLAMA
      --small GGUF:SHA [--large GGUF:SHA] [--no-repair] [--port 8440]

Model tiers (phase 2): every claim is first asked of the small model; a claim
with an unresolved issue is re-asked of the large model, then once more of the
large model with the issue text as feedback (≤ 3 attempts per claim). If no
large model is given, the small model takes all attempts. All model costs —
loading included, failed attempts included — are recorded.

Reads only the task's procedure document and its expert demonstrations;
validation and unseen data are never opened. Writes: claims.jsonl (one record
per claim: clause cite, raw model answer, verified claim, field provenance,
repairs, issues, tier), ir.json, capability.json (if it compiles),
demos.check.jsonl, boundary.jsonl (generated probes, unlabelled, plus
runtime-vs-IR agreement), clarification.json, triage.json, cost.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "research/compute-memory/bench"))
import atomic as A  # noqa: E402
import llama_proc as L  # noqa: E402
from ir_compiler import IRError, compile_ir, provenance_check  # noqa: E402
from propose_ir import check, load  # noqa: E402

SYSTEM = "You read one sentence of an engineering procedure and fill in a small form exactly. Output JSON only."
KIND_HELP = """Kinds of statement:
- scope_subject: says what equipment the procedure covers (give its words)
- scope_exclusion_terms: names equipment the procedure does NOT cover
- scope_limit: a measured value that makes a request in or out of scope
- required_inputs: lists the measurements the procedure needs
- missing_input: what happens when an input is missing
- validity: a range a measurement must lie in for the test to be valid
- correction: how a measurement is corrected for temperature
- limit: how an acceptance limit is computed
- decision_rule: "if <condition>, <outcome>"
- default_outcome: the outcome when no rule applies ("Otherwise ...")
- none: anything else (titles, confidentiality notes)"""
FILL_HELP = {
    "scope_subject": "Copy the words naming the covered equipment.",
    "scope_exclusion_terms": "Copy each excluded equipment word exactly as written.",
    "scope_limit": "ref: which measurement; op and value: the comparison stated; meaning: whether the comparison puts a request out of scope or describes what is in scope.",
    "required_inputs": "One entry per measurement. ref voltage/resistance/temperature, or cued_1/cued_2 for a plain number named by a word or abbreviation (copy that word into cues). unit as written.",
    "missing_input": "The outcome when an input is missing.",
    "validity": "Which measurement, its allowed min and max, and the outcome outside the range.",
    "correction": "add_per_degree: corrected = target + rate*(by - reference). multiply_power_per_degree: corrected = target * base^((by - reference)/step). Copy the numbers; unused numbers 0 or 1.",
    "limit": "constant: limit = coefficient. coefficient_times_input_plus_offset: limit = coefficient*(input + offset).",
    "decision_rule": "Each condition: subject (use 'corrected' for a corrected value), op, and either a number or 'limit' (number = fraction of the limit, 1 for the limit itself). Then the outcome.",
    "default_outcome": "The outcome when no rule applies.",
}


class Tier:
    """One model behind one llama-server process; costs accumulate here."""

    def __init__(self, name: str, server: str, spec: str, port: int, logdir: str):
        path, sha = spec.split(":", 1)
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while b := f.read(1 << 20):
                h.update(b)
        if h.hexdigest() != sha:
            sys.exit(f"{name}: model hash mismatch")
        self.name, self.model, self.sha = name, os.path.basename(path), sha
        self.srv = L.Server(server, path, port, ("-c", "4096"), os.path.join(logdir, f"llama-{name}.log"))
        self.load_s = None
        self.calls = self.prompt_tokens = self.completion_tokens = 0
        self.cpu_s = 0.0
        self.peak = 0.0

    def ask(self, user: str, schema: dict) -> dict:
        if self.load_s is None:
            self.load_s = self.srv.start()
        before = self.srv.stats()["cpu_s"]
        body = {"messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                "temperature": 0, "seed": 0, "max_tokens": 400,
                "response_format": {"type": "json_schema", "json_schema": {"schema": schema}}}
        resp, _ = self.srv.post("/v1/chat/completions", body)
        st = self.srv.stats()
        self.cpu_s += st["cpu_s"] - before
        self.peak = max(self.peak, st["VmHWM"])
        u = resp.get("usage", {})
        self.calls += 1
        self.prompt_tokens += u.get("prompt_tokens", 0)
        self.completion_tokens += u.get("completion_tokens", 0)
        return json.loads(resp["choices"][0]["message"]["content"])

    def cost(self) -> dict:
        peak = self.peak
        return {"tier": self.name, "model": self.model, "sha256": self.sha, "loaded": self.load_s is not None,
                "load_s": round(self.load_s or 0, 2), "calls": self.calls, "cpu_s": round(self.cpu_s, 2),
                "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens, "peak_rss_mib": round(peak, 1)}

    def stop(self) -> None:
        if self.load_s is not None:
            self.srv.stop()


def context(doc_title: str, prev: str, clause: A.Clause, outcomes: list[str], declared: dict) -> str:
    dec = ", ".join(f"{r} (cues {c})" if c else r for r, c in declared.items()) or "not yet known"
    return (f"Procedure: {doc_title}\nOutcome labels: {', '.join(outcomes)}\nDeclared measurements: {dec}\n"
            f"Previous sentence: \"{prev}\"\nSENTENCE: \"{clause.text}\"\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--task", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--small", required=True, help="GGUF:SHA256")
    ap.add_argument("--large", help="GGUF:SHA256 (optional larger model)")
    ap.add_argument("--no-repair", action="store_true", help="ablation: keep model values even when the clause determines them")
    ap.add_argument("--port", type=int, default=8440)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    spec = json.load(open(a.task))
    doc, demos = load(spec)
    title = open(os.path.join(ROOT, "research/capability-learning", spec["data"], spec["doc_file"])).readline().split("|")[-1].strip()
    outcomes = spec["outcomes"]
    small = Tier("small", a.server, a.small, a.port, a.out)
    large = Tier("large", a.server, a.large, a.port + 1, a.out) if a.large else None
    t0 = time.monotonic()
    clauses = A.segment(doc)
    records, claims, claimed, kind_log = [], [], {}, []
    ctx = {"cues": {}, "prev_subject": None}
    declared: dict = {}
    try:
        prev = ""
        for ci, cl in enumerate(clauses):
            ctx["next_text"] = clauses[ci + 1].text if ci + 1 < len(clauses) else ""
            base = context(title, prev, cl, outcomes, declared)
            # Attempt 2: the model only chooses among kinds the clause can
            # support (evidence gates); one plausible kind needs no question;
            # several go to the large tier (harder judgement).
            plaus = A.plausible_kinds(cl.text, outcomes)
            if len(plaus) <= 1:
                kinds, kind_src = (plaus or ["none"]), "determined"
            else:
                chooser = large or small
                sch = {"type": "object", "properties": {"kinds": {"type": "array", "items": {"enum": plaus + ["none"]},
                                                                   "minItems": 1, "maxItems": len(plaus)}}, "required": ["kinds"]}
                kinds = chooser.ask(base + KIND_HELP + f"\nWhich of these kinds does the SENTENCE state: {', '.join(plaus)}? "
                                    "Choose every one that applies.", sch)["kinds"]
                kinds = [x for x in dict.fromkeys(kinds) if x != "none"] or ["none"]
                kind_src = chooser.name
            claimed[cl.cid] = kinds
            kind_log.append({"clause": cl.cid, "plausible": plaus, "kinds": kinds, "source": kind_src})
            for kind in kinds:
                if kind == "none":
                    continue
                schema = A.claim_schema(kind, cl, outcomes)
                q = base + f"Fill in the {kind} form for the SENTENCE. {FILL_HELP[kind]}"
                attempts = [(small, q), (large or small, q)]
                v = None
                tiers_used = []
                for k in range(3):
                    tier, prompt = attempts[k] if k < 2 else (large or small, q + "\nYour previous answer had problems: "
                                                              + json.dumps(v.issues, ensure_ascii=False) + "\nCorrect them.")
                    raw = tier.ask(prompt, schema)
                    tiers_used.append(tier.name)
                    v = A.verify_claim(kind, raw, cl, outcomes, ctx)
                    if a.no_repair and v.repairs:
                        # Ablation: discard repairs, keep the model's values; count them as issues.
                        v.issues += [{"field": r["field"], "issue": "model value differs from clause (repair disabled)",
                                      "value": r["from"], "clause_value": r["to"]} for r in v.repairs]
                        v.claim = raw
                        v.repairs = []
                    if not v.issues:
                        break
                rec = {"clause": cl.cid, "span": [cl.start, cl.end], "text": cl.text, "kind": kind, "raw": raw,
                       "claim": v.claim, "fields": v.fields, "repairs": v.repairs, "issues": v.issues, "tiers": tiers_used,
                       "status": "hypothesis" if any(s == "hypothesis" for s in v.fields.values()) else "evidence"}
                records.append(rec)
                if not v.issues:
                    claims.append({"kind": kind, "claim": v.claim, "clause": cl.cid})
                    if kind == "required_inputs":
                        declared = {i["ref"]: i["cues"] for i in v.claim["inputs"]}
                        ctx["cues"] = {r: c for r, c in declared.items() if r.startswith("cued")}
                    if kind == "decision_rule":
                        ctx["prev_subject"] = v.claim["conditions"][-1]["subject"]
            prev = cl.text
    finally:
        small.stop()
        if large:
            large.stop()
    acq_wall = time.monotonic() - t0
    json.dump(kind_log, open(os.path.join(a.out, "kinds.json"), "w"), indent=1)
    with open(os.path.join(a.out, "claims.jsonl"), "w") as f:
        f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
    ir, simp, asm_issues = A.assemble(claims)
    json.dump(ir, open(os.path.join(a.out, "ir.json"), "w"), indent=1, ensure_ascii=False)
    claim_issues = [{"clause": r["clause"], "kind": r["kind"], "text": r["text"], **i} for r in records for i in r["issues"]]
    cover = A.coverage_issues(clauses, claimed, outcomes)
    tri = {"simplifications": simp, "claim_issues": claim_issues, "assembly_issues": asm_issues, "coverage_issues": cover,
           "field_provenance": A.field_summary(records)}
    cap = None
    try:
        if asm_issues:
            raise IRError("assembly incomplete")
        cspec = {**spec, "proposed_by": f"model:{small.sha}" + (f"+{large.sha}" if large else ""), "demo_ids": [d["id"] for d in demos]}
        cap = compile_ir(ir, cspec).capability
    except (IRError, KeyError, TypeError) as e:
        tri["compile_error"] = f"{type(e).__name__}: {e}"
    if cap:
        cp = os.path.join(a.out, "capability.json")
        json.dump(cap, open(cp, "w"), indent=1, ensure_ascii=False)
        tri["unsupported_numbers"] = provenance_check(ir, doc)
        tri["consistency_issues"] = A.consistency(ir, outcomes, A.doc_outcomes(clauses, outcomes))
        cases = os.path.join(a.out, "demos.cases.jsonl")
        with open(cases, "w") as f:
            f.writelines(json.dumps({"id": d["id"], "text": d["text"], "label": d["label"]}) + "\n" for d in demos)
        rows = check(a.bin, cp, cases)
        with open(os.path.join(a.out, "demos.check.jsonl"), "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)
        tri["demo_agreement"] = [sum(r.get("got") == r.get("expected") for r in rows), len(demos)]
        tri["demo_disagreements"] = [r for r in rows if r.get("got") != r.get("expected")]
        # Compile equivalence on generated boundary probes (no labels involved).
        topic = (ir["topic_terms"] or [spec["intended_task"]])[0]
        pts = A.boundary_points(ir)
        bcases = os.path.join(a.out, "boundary.cases.jsonl")
        with open(bcases, "w") as f:
            for k, p in enumerate(pts):
                p["id"], p["text"], p["ir_says"] = f"b-{k:03d}", A.render(ir, p["inputs"], topic), A.evaluate_ir(ir, p["inputs"])
                f.write(json.dumps({"id": p["id"], "text": p["text"], "label": p["ir_says"]}, ensure_ascii=False) + "\n")
        brows = {r["id"]: r for r in check(a.bin, cp, bcases)}
        for p in pts:
            p["runtime_says"] = brows.get(p["id"], {}).get("got")
        with open(os.path.join(a.out, "boundary.jsonl"), "w") as f:
            f.writelines(json.dumps(p, ensure_ascii=False) + "\n" for p in pts)
        tri["boundary_probes"] = len(pts)
        tri["boundary_runtime_mismatch"] = [p["id"] for p in pts if p["runtime_says"] != p["ir_says"]]
    blocking = claim_issues or asm_issues or cover or "compile_error" in tri or tri.get("unsupported_numbers") \
        or tri.get("consistency_issues") or tri.get("demo_disagreements") or tri.get("boundary_runtime_mismatch")
    tri["status"] = "NEEDS_EXPERT_CLARIFICATION" if blocking else "CANDIDATE_FOR_EXPERT_VALIDATION"
    json.dump({"questions": claim_issues + asm_issues + cover + tri.get("consistency_issues", []),
               "demo_disagreements": tri.get("demo_disagreements", []),
               "hypothesis_fields": [{"clause": r["clause"], "kind": r["kind"], "field": f, "value": r["claim"]}
                                     for r in records for f, s in r["fields"].items() if s == "hypothesis"]},
              open(os.path.join(a.out, "clarification.json"), "w"), indent=1, ensure_ascii=False)
    json.dump(tri, open(os.path.join(a.out, "triage.json"), "w"), indent=1, ensure_ascii=False)
    costs = [small.cost()] + ([large.cost()] if large else [])
    cost = {"method": "atomic-claims-v3" + ("-norepair" if a.no_repair else ""), "task": spec["family"], "clauses": len(clauses),
            "claims": len(records), "tiers": costs, "model_calls": sum(c["calls"] for c in costs),
            "model_cpu_s": round(sum(c["cpu_s"] for c in costs), 2), "load_s": round(sum(c["load_s"] for c in costs), 2),
            "acquisition_wall_s": round(acq_wall, 2), "peak_rss_mib": max(c["peak_rss_mib"] for c in costs)}
    json.dump(cost, open(os.path.join(a.out, "cost.json"), "w"), indent=1)
    print(json.dumps({"task": spec["family"], "status": tri["status"], "demos": tri.get("demo_agreement"),
                      "fields": tri["field_provenance"], "issues": len(claim_issues) + len(asm_issues) + len(cover),
                      "consistency": len(tri.get("consistency_issues", [])), "calls": cost["model_calls"],
                      "cpu_s": cost["model_cpu_s"], "wall_s": cost["acquisition_wall_s"]}))


if __name__ == "__main__":
    main()
