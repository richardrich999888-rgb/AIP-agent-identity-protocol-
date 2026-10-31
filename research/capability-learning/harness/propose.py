"""Phase C — a local model proposes a capability from a document and demonstrations.

usage (inside research/compute-memory/bench/offline.sh):
  propose.py OUT_DIR --model GGUF --model-sha SHA --server LLAMA_SERVER --bin SYNTRIASS
             [--rounds 3] [--port 8410]

Inputs (frozen, ir-tasks-v1): corpus/koravi-ep-114.txt (the procedure, read as
the requesting engineer is authorised to), demos.jsonl (6 expert
demonstrations with working). Never read: validation.jsonl (the expert's
signed suite is applied later by the runtime), test_unseen.jsonl,
false_activation.jsonl.

What the model writes: applicability terms, inputs (kind + cue words), scope
guards, derived quantities, ordered rules, default and missing-input
outcomes. What it cannot write (filled by this harness from the task
definition): id, version, outcome vocabulary, required tenant/clearance/
domain, evidence document names (digests are bound later by the runtime from
the corpus), proposer identity.

Repair loop: after each round the candidate is dry-run on the 6 demos
(`syntriass cap-check`); mismatches are fed back. Validation data is never
shown. Decoding is greedy (temperature 0, fixed seed): deterministic.
Outputs: round_K.json (candidate), round_K.check.jsonl, transcript.jsonl,
cost.json, proposal.json (last candidate).
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
DATA = os.path.join(ROOT, "research/capability-learning/data/ir-tasks-v1")
sys.path.insert(0, os.path.join(ROOT, "research/compute-memory/bench"))
import llama_proc as L  # noqa: E402

# Task interface defined by the organisation (not learned).
OUTCOMES = ["PASS", "RETEST_30D", "DRY_OUT", "REJECT", "INVALID_TEST", "OUT_OF_SCOPE", "INSUFFICIENT_INPUT"]
KINDS = ["voltage", "resistance", "temperature", "cued"]
MIN_INPUTS_PRESENT = 2  # applicability policy default, fixed before any run
NAME = {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,19}$"}
EXPR = {"type": "string", "minLength": 1, "maxLength": 160}

SCHEMA = {
    "type": "object",
    "properties": {
        "applicability_terms": {"type": "array", "items": {"type": "string", "maxLength": 32}, "minItems": 1, "maxItems": 12},
        "inputs": {"type": "array", "minItems": 1, "maxItems": 6, "items": {"type": "object", "properties": {
            "name": NAME, "kind": {"enum": KINDS},
            "cues": {"type": "array", "items": {"type": "string", "maxLength": 32}, "maxItems": 4}},
            "required": ["name", "kind", "cues"]}},
        "out_of_scope_terms": {"type": "array", "items": {"type": "string", "maxLength": 32}, "maxItems": 8},
        "out_of_scope_conditions": {"type": "array", "items": EXPR, "maxItems": 4},
        "missing_input_outcome": {"enum": OUTCOMES},
        "derived": {"type": "array", "maxItems": 6, "items": {"type": "object", "properties": {"name": NAME, "expr": EXPR},
                                                            "required": ["name", "expr"]}},
        "rules": {"type": "array", "minItems": 1, "maxItems": 10, "items": {"type": "object", "properties": {
            "when": EXPR, "outcome": {"enum": OUTCOMES}}, "required": ["when", "outcome"]}},
        "default_outcome": {"enum": OUTCOMES},
    },
    "required": ["applicability_terms", "inputs", "out_of_scope_terms", "out_of_scope_conditions",
                 "missing_input_outcome", "derived", "rules", "default_outcome"],
}

LANGUAGE = """You write a decision procedure in a small structured language. The runtime
extracts numbers from the request text; you only choose what they mean.

Input kinds (the runtime converts units for you):
  voltage      -> kilovolts (kV)
  resistance   -> megohms
  temperature  -> degrees Celsius
  cued         -> a bare number written right after one of your cue words (give 1-4 cues)

Expressions: numbers, input or derived names, + - * / ^ and parentheses.
Precedence: ^ binds tighter than * and /, which bind tighter than + and -;
"a ^ b / c" means "(a ^ b) / c". Every name you use must be an input name or
a derived name defined earlier, spelled exactly the same.
Conditions: comparisons (< <= > >= == !=) joined by "and" / "or" (no parentheses
around conditions). No functions, no other syntax.

Evaluation order: if any out_of_scope_terms word appears -> OUT_OF_SCOPE; if an
out_of_scope_condition holds -> OUT_OF_SCOPE; if an input is missing ->
missing_input_outcome; then derived values are computed in order; then rules are
tried top to bottom and the first true rule decides; otherwise default_outcome.

Example from a DIFFERENT procedure (bearing grease checks, not your task):
{"applicability_terms": ["bearing", "grease"], "inputs": [{"name": "t", "kind": "temperature", "cues": []},
 {"name": "hours", "kind": "cued", "cues": ["hours", "run hours"]}], "out_of_scope_terms": ["sealed"],
 "out_of_scope_conditions": ["hours > 50000"], "missing_input_outcome": "INSUFFICIENT_INPUT",
 "derived": [{"name": "margin", "expr": "95 - t"}],
 "rules": [{"when": "t < -20 or t > 150", "outcome": "INVALID_TEST"}, {"when": "margin < 0", "outcome": "REJECT"},
           {"when": "margin < 10 and hours > 2000", "outcome": "RETEST_30D"}],
 "default_outcome": "PASS"}
"""


def load_doc() -> str:
    t = open(os.path.join(DATA, "corpus/koravi-ep-114.txt")).read()
    return t.split("\n", 1)[1]


def demos() -> list[dict]:
    return [json.loads(l) for l in open(os.path.join(DATA, "demos.jsonl"))]


def prompt(doc: str, ds: list[dict]) -> list[dict]:
    dem = "\n".join(f"- \"{d['text']}\" -> {d['label']}" + (f"  (expert: {d['expert_working']})" if d.get("expert_working") else "")
                    for d in ds)
    user = (f"{LANGUAGE}\nOutcome labels you may use: {', '.join(OUTCOMES)}.\n\n"
            f"PROCEDURE DOCUMENT:\n{doc}\n\nEXPERT DEMONSTRATIONS:\n{dem}\n\n"
            "Write the procedure for this document as JSON.")
    return [{"role": "system", "content": "You convert engineering procedures into the structured language exactly. Output JSON only."},
            {"role": "user", "content": user}]


def to_capability(p: dict, model_sha: str) -> dict:
    """Wrap the model's procedure in the organisation-defined envelope."""
    guards = [{"when": c, "outcome": "OUT_OF_SCOPE"} for c in p["out_of_scope_conditions"]]
    text_guards = [{"any_terms": p["out_of_scope_terms"], "outcome": "OUT_OF_SCOPE"}] if p["out_of_scope_terms"] else []
    return {
        "id": "koravi.ep114.ir-acceptance.learned", "version": 1,
        "intended_task": "Motor winding insulation-resistance acceptance per Koravi EP-114 rev C",
        "outcomes": OUTCOMES,
        "applicability": {"any_terms": p["applicability_terms"], "min_inputs_present": MIN_INPUTS_PRESENT},
        "procedure": {"inputs": p["inputs"], "text_guards": text_guards, "numeric_guards": guards,
                      "missing_input_outcome": p["missing_input_outcome"], "derive": p["derived"],
                      "rules": p["rules"], "default_outcome": p["default_outcome"]},
        "required": {"tenant": "koravi-process", "min_clearance": "restricted", "security_domain": "koravi-ot"},
        "dependencies": {"knowledge": {"ep-114": ""}, "policy_version": "ep-114-revC", "execution_model_sha256": None},
        "evidence_refs": ["ep-114"] + [d["id"] for d in demos()],
        "failure_conditions": ["an input appears twice with different values", "a unit the runtime does not recognise"],
        "tests": [],
        "proposed_by": f"model:{model_sha}",
    }


def check(bin_: str, cap_path: str, cases: str) -> list[dict]:
    out = subprocess.run([bin_, "cap-check", "--file", cap_path, "--cases", cases], capture_output=True, text=True, check=True).stdout
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def defined_names(cap: dict) -> list[str]:
    p = cap["procedure"]
    return [i["name"] for i in p["inputs"]] + [d["name"] for d in p["derive"]]


def feedback(rows: list[dict], ds: list[dict], cap: dict) -> str:
    """Generic compiler diagnostics or demo mismatches (never validation data)."""
    by = {d["id"]: d for d in ds}
    if rows and "compiled" in rows[0]:
        return (f"Your JSON does not compile: {rows[0]['error']}. The names you defined are: "
                f"{', '.join(defined_names(cap))}. Use only these names (define any other value under "
                "\"derived\" first). Fix it and output the whole JSON again.")
    bad = [r for r in rows if r["got"] != r["expected"]]
    lines = [f"- \"{by[r['id']]['text']}\": your procedure gives {r['got']}, the expert says {r['expected']}"
             + (f" ({by[r['id']]['expert_working']})" if by[r['id']].get("expert_working") else "") for r in bad]
    return "Your procedure disagrees with the expert on these demonstrations:\n" + "\n".join(lines) + \
        "\nRe-read the document, correct the procedure, and output the whole JSON again."


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--model", required=True)
    ap.add_argument("--model-sha", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--port", type=int, default=8410)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    h = hashlib.sha256()
    with open(a.model, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    if h.hexdigest() != a.model_sha:
        sys.exit("model hash mismatch")
    ds = demos()
    demo_cases = os.path.join(a.out, "demos.cases.jsonl")
    with open(demo_cases, "w") as f:
        for d in ds:
            f.write(json.dumps({"id": d["id"], "text": d["text"], "label": d["label"]}) + "\n")
    srv = L.Server(a.server, a.model, a.port, ("-c", "8192"), os.path.join(a.out, "llama.log"))
    t0 = time.monotonic()
    load_s = srv.start()
    msgs = prompt(load_doc(), ds)
    transcript, rounds = [], []
    try:
        for k in range(1, a.rounds + 1):
            before = srv.stats()
            body = {"messages": msgs, "temperature": 0, "seed": 0, "max_tokens": 1200,
                    "response_format": {"type": "json_schema", "json_schema": {"schema": SCHEMA}}}
            resp, wall = srv.post("/v1/chat/completions", body)
            after = srv.stats()
            raw = resp["choices"][0]["message"]["content"]
            usage = resp.get("usage", {})
            transcript.append({"round": k, "messages": msgs, "raw": raw, "usage": usage})
            try:
                cap = to_capability(json.loads(raw), a.model_sha)
            except (ValueError, KeyError) as e:
                rounds.append({"round": k, "parsed": False, "error": str(e), "wall_s": wall, "usage": usage,
                               "llama_cpu_s": after["cpu_s"] - before["cpu_s"]})
                break
            cp = os.path.join(a.out, f"round_{k}.json")
            json.dump(cap, open(cp, "w"), indent=1)
            rows = check(a.bin, cp, demo_cases)
            with open(os.path.join(a.out, f"round_{k}.check.jsonl"), "w") as f:
                f.writelines(json.dumps(r) + "\n" for r in rows)
            agree = 0 if (rows and "compiled" in rows[0]) else sum(r["got"] == r["expected"] for r in rows)
            rounds.append({"round": k, "parsed": True, "compiled": not (rows and "compiled" in rows[0]),
                           "demo_agreement": agree, "demos": len(ds), "wall_s": wall, "usage": usage,
                           "llama_cpu_s": round(after["cpu_s"] - before["cpu_s"], 2)})
            json.dump(cap, open(os.path.join(a.out, "proposal.json"), "w"), indent=1)
            if agree == len(ds):
                break
            msgs = msgs + [{"role": "assistant", "content": raw}, {"role": "user", "content": feedback(rows, ds, cap)}]
        peak = srv.stats()
    finally:
        srv.stop()
    cost = {"model": os.path.basename(a.model), "model_sha256": a.model_sha, "load_s": round(load_s, 2),
            "total_wall_s": round(time.monotonic() - t0, 2), "rounds": rounds,
            "prompt_tokens": sum(r["usage"].get("prompt_tokens", 0) for r in rounds),
            "completion_tokens": sum(r["usage"].get("completion_tokens", 0) for r in rounds),
            "llama_cpu_s": round(sum(r.get("llama_cpu_s", 0) for r in rounds), 2),
            "llama_peak_rss_mib": round(peak["VmHWM"], 1)}
    json.dump(cost, open(os.path.join(a.out, "cost.json"), "w"), indent=1)
    with open(os.path.join(a.out, "transcript.jsonl"), "w") as f:
        f.writelines(json.dumps(t) + "\n" for t in transcript)
    print(json.dumps({k: cost[k] for k in ("model", "total_wall_s", "llama_cpu_s", "completion_tokens")} | {"rounds": [(r["round"], r.get("demo_agreement")) for r in rounds]}))


if __name__ == "__main__":
    main()
