"""Candidate — a local model fills the typed IR; the deterministic compiler builds the capability.

usage (inside offline.sh):
  propose_ir.py OUT_DIR --task tasks/X.json --model GGUF --model-sha SHA --server LLAMA --bin SYNTRIASS
                [--rounds 3] [--port 8430]

Same conditions as propose.py (Baseline A): same model, greedy decoding,
same document and demonstrations, repair feedback only from compiler
diagnostics and demo mismatches (validation and unseen data never read), same
round limit. The worked example in the prompt is from a different domain.
Outputs per round: round_K.ir.json, round_K.json (compiled capability, if
any), round_K.check.jsonl, plus cost.json, transcript.jsonl, proposal.json.
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
CL = os.path.join(ROOT, "research/capability-learning")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "research/compute-memory/bench"))
import llama_proc as L  # noqa: E402
from ir_compiler import IRError, compile_ir, ir_schema  # noqa: E402

GUIDE = """Fill in a structured description of the procedure. You never write formulas:
you choose options and copy numbers and units from the document.

inputs: one entry per required measurement. ref is "voltage", "resistance",
  "temperature", or "cued_1"/"cued_2" for a plain number that follows a word
  (give that word in cues, e.g. "PI"). unit = the unit the document uses.
out_of_scope_terms: words that mean the request is outside the procedure.
out_of_scope_limits: a measurement value that makes the request out of scope.
validity: allowed range of a measurement; outside it -> the given outcome.
correction: how the document corrects a measurement for temperature:
  "none"; "add_per_degree": corrected = target + rate * (by - reference);
  "multiply_power_per_degree": corrected = target * base ^ ((by - reference) / step).
  Fill unused numbers with 0 (base/step with 1).
limit: an acceptance limit computed from a measurement: "none"; "constant";
  "coefficient_times_input_plus_offset": limit = coefficient * (input + offset).
rules: tried top to bottom; the first true rule decides. value is a measurement
  or "corrected"; compare with a number (in unit) or with limit_fraction * limit.
default_outcome: the outcome when no rule is true.
The order of checks is fixed: out-of-scope, missing input, validity, then your rules.

Example from a DIFFERENT procedure (bearing temperature, not your task):
{"topic_terms": ["bearing"], "inputs": [{"ref": "temperature", "unit": "°C", "cues": []},
 {"ref": "cued_1", "unit": "none", "cues": ["hours"]}], "out_of_scope_terms": ["sealed"],
 "out_of_scope_limits": [], "missing_input_outcome": "INSUFFICIENT_INPUT",
 "validity": [{"ref": "temperature", "min": -20, "max": 150, "unit": "°C", "outcome": "INVALID_TEST"}],
 "correction": {"template": "none", "target": "temperature", "by": "temperature", "reference": 0, "reference_unit": "°C",
  "rate": 0, "rate_unit": "°C", "base": 1, "step": 1},
 "limit": {"template": "none", "coefficient": 0, "input": "temperature", "offset": 0, "unit": "°C"},
 "rules": [{"value": "temperature", "op": ">", "against": "number", "number": 95, "unit": "°C", "limit_fraction": 1, "outcome": "REJECT"},
  {"value": "cued_1", "op": ">", "against": "number", "number": 2000, "unit": "none", "limit_fraction": 1, "outcome": "RETEST_30D"}],
 "default_outcome": "PASS"}
"""


def load(spec: dict) -> tuple[str, list[dict]]:
    data = os.path.join(CL, spec["data"])
    doc = open(os.path.join(data, spec["doc_file"])).read().split("\n", 1)[1]
    demos = [json.loads(l) for l in open(os.path.join(data, "demos.jsonl"))]
    return doc, demos


def prompt(spec: dict, doc: str, ds: list[dict]) -> list[dict]:
    dem = "\n".join(f"- \"{d['text']}\" -> {d['label']}" + (f"  (expert: {d['expert_working']})" if d.get("expert_working") else "")
                    for d in ds)
    user = (f"{GUIDE}\nOutcome labels: {', '.join(spec['outcomes'])}.\n\nPROCEDURE DOCUMENT:\n{doc}\n\n"
            f"EXPERT DEMONSTRATIONS:\n{dem}\n\nFill in the structured description as JSON.")
    return [{"role": "system", "content": "You read engineering procedures carefully and fill in structured forms exactly. Output JSON only."},
            {"role": "user", "content": user}]


SECTIONS = [  # (keys filled, question)
    (["topic_terms", "inputs"], "Which measurements does the procedure require? Give each with its ref and unit, and for a plain number after a word (cued_1/cued_2) the word(s) that come before it in a request. Also give topic words."),
    (["out_of_scope_terms", "out_of_scope_limits"], "When is a request outside this procedure? Give the words, and any measurement value that makes it out of scope."),
    (["missing_input_outcome", "validity"], "What is the outcome when an input is missing, and which measurement must lie in which range for the reading to be valid?"),
    (["correction"], "Does the document correct a measurement for temperature? Choose the template and copy its numbers."),
    (["limit"], "Does the document compute an acceptance limit from a measurement? Choose the template and copy its numbers."),
    (["rules", "default_outcome"], "List the decision rules in the document's order (first true rule decides) and the outcome when none applies. Use \"corrected\" for a corrected measurement."),
]


def decomposed(srv, spec: dict, doc: str, ds: list[dict], prior: dict | None, note: str) -> tuple[dict, list[dict], list[dict]]:
    """Fill the IR one section at a time; each call sees the answers so far."""
    full = ir_schema(spec["outcomes"])
    ir: dict = {}
    usages, raws = [], []
    base = prompt(spec, doc, ds)[1]["content"].rsplit("Fill in the structured description as JSON.", 1)[0]
    for keys, q in SECTIONS:
        sub = {"type": "object", "properties": {k: full["properties"][k] for k in keys}, "required": keys}
        ctx = f"\nSo far: {json.dumps(ir, ensure_ascii=False)}" if ir else ""
        if prior is not None:
            ctx += f"\nPrevious attempt for these fields: {json.dumps({k: prior.get(k) for k in keys}, ensure_ascii=False)}\n{note}"
        msgs = [{"role": "system", "content": "You read engineering procedures carefully and fill in structured forms exactly. Output JSON only."},
                {"role": "user", "content": f"{base}{ctx}\n\nQUESTION: {q}\nAnswer with JSON containing only: {', '.join(keys)}."}]
        body = {"messages": msgs, "temperature": 0, "seed": 0, "max_tokens": 600,
                "response_format": {"type": "json_schema", "json_schema": {"schema": sub}}}
        resp, _ = srv.post("/v1/chat/completions", body)
        raw = resp["choices"][0]["message"]["content"]
        raws.append({"keys": keys, "raw": raw})
        usages.append(resp.get("usage", {}))
        ir.update({k: v for k, v in json.loads(raw).items() if k in keys})
    return ir, usages, raws


def check(bin_: str, cap_path: str, cases: str) -> list[dict]:
    out = subprocess.run([bin_, "cap-check", "--file", cap_path, "--cases", cases], capture_output=True, text=True, check=True).stdout
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--task", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--model-sha", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--port", type=int, default=8430)
    ap.add_argument("--decompose", action="store_true",
                    help="ask one small question per IR section instead of one large form")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    spec = json.load(open(a.task))
    h = hashlib.sha256()
    with open(a.model, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    if h.hexdigest() != a.model_sha:
        sys.exit("model hash mismatch")
    doc, ds = load(spec)
    cspec = {**spec, "proposed_by": f"model:{a.model_sha}", "demo_ids": [d["id"] for d in ds]}
    cases = os.path.join(a.out, "demos.cases.jsonl")
    with open(cases, "w") as f:
        f.writelines(json.dumps({"id": d["id"], "text": d["text"], "label": d["label"]}) + "\n" for d in ds)
    srv = L.Server(a.server, a.model, a.port, ("-c", "8192"), os.path.join(a.out, "llama.log"))
    t0 = time.monotonic()
    load_s = srv.start()
    msgs = prompt(spec, doc, ds)
    schema = ir_schema(spec["outcomes"])
    rounds, transcript = [], []
    prev_ir, prev_note = None, ""
    try:
        for k in range(1, a.rounds + 1):
            before = srv.stats()
            tw = time.monotonic()
            if a.decompose:
                ir_d, usages, raws = decomposed(srv, spec, doc, ds, prev_ir, prev_note)
                raw = json.dumps(ir_d, ensure_ascii=False)
                usage = {"prompt_tokens": sum(u.get("prompt_tokens", 0) for u in usages),
                         "completion_tokens": sum(u.get("completion_tokens", 0) for u in usages), "calls": len(usages)}
                transcript.append({"round": k, "sections": raws, "usage": usage})
            else:
                body = {"messages": msgs, "temperature": 0, "seed": 0, "max_tokens": 1400,
                        "response_format": {"type": "json_schema", "json_schema": {"schema": schema}}}
                resp, _ = srv.post("/v1/chat/completions", body)
                raw = resp["choices"][0]["message"]["content"]
                usage = resp.get("usage", {})
                transcript.append({"round": k, "raw": raw, "usage": usage})
            wall = time.monotonic() - tw
            after = srv.stats()
            rec = {"round": k, "wall_s": round(wall, 2), "usage": usage, "llama_cpu_s": round(after["cpu_s"] - before["cpu_s"], 2)}
            try:
                ir = json.loads(raw)
                json.dump(ir, open(os.path.join(a.out, f"round_{k}.ir.json"), "w"), indent=1, ensure_ascii=False)
                comp = compile_ir(ir, cspec)
            except (ValueError, KeyError) as e:
                rec.update(compiled=False, error=f"{type(e).__name__}: {e}")
                rounds.append(rec)
                fb = (f"The form could not be compiled: {e}. Fix that field and output the whole JSON again."
                      if isinstance(e, IRError) else "Your output was not valid. Output the whole JSON again.")
                prev_ir, prev_note = (ir if isinstance(e, IRError) else None), fb
                msgs = msgs + [{"role": "assistant", "content": raw}, {"role": "user", "content": fb}]
                continue
            cp = os.path.join(a.out, f"round_{k}.json")
            json.dump(comp.capability, open(cp, "w"), indent=1, ensure_ascii=False)
            rows = check(a.bin, cp, cases)
            with open(os.path.join(a.out, f"round_{k}.check.jsonl"), "w") as f:
                f.writelines(json.dumps(r) + "\n" for r in rows)
            ok = 0 if (rows and "compiled" in rows[0]) else sum(r["got"] == r["expected"] for r in rows)
            rec.update(compiled=not (rows and "compiled" in rows[0]), demo_agreement=ok, demos=len(ds), repairs=comp.repairs)
            rounds.append(rec)
            json.dump(comp.capability, open(os.path.join(a.out, "proposal.json"), "w"), indent=1, ensure_ascii=False)
            if ok == len(ds):
                break
            by = {d["id"]: d for d in ds}
            bad = [r for r in rows if r.get("got") != r.get("expected")]
            fb = "Your procedure disagrees with the expert on these demonstrations:\n" + "\n".join(
                f"- \"{by[r['id']]['text']}\": your form gives {r['got']}, the expert says {r['expected']}"
                + (f" ({by[r['id']]['expert_working']})" if by[r['id']].get("expert_working") else "") for r in bad) + \
                "\nRe-read the document, correct the form, and output the whole JSON again."
            msgs = msgs + [{"role": "assistant", "content": raw}, {"role": "user", "content": fb}]
            prev_ir, prev_note = ir, fb
        peak = srv.stats()
    finally:
        srv.stop()
    cost = {"method": "constrained-ir" + ("-decomposed" if a.decompose else ""), "task": spec["family"], "model": os.path.basename(a.model), "model_sha256": a.model_sha,
            "load_s": round(load_s, 2), "total_wall_s": round(time.monotonic() - t0, 2), "rounds": rounds,
            "llama_cpu_s": round(sum(r["llama_cpu_s"] for r in rounds), 2),
            "completion_tokens": sum(r["usage"].get("completion_tokens", 0) for r in rounds),
            "llama_peak_rss_mib": round(peak["VmHWM"], 1)}
    json.dump(cost, open(os.path.join(a.out, "cost.json"), "w"), indent=1)
    with open(os.path.join(a.out, "transcript.jsonl"), "w") as f:
        f.writelines(json.dumps(t, ensure_ascii=False) + "\n" for t in transcript)
    print(json.dumps({"task": spec["family"], "rounds": [(r["round"], r.get("compiled"), r.get("demo_agreement"), r.get("error", "")[:80]) for r in rounds],
                      "cpu_s": cost["llama_cpu_s"], "wall_s": cost["total_wall_s"]}))


if __name__ == "__main__":
    main()
