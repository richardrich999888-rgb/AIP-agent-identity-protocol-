#!/usr/bin/env python3
"""Recorded run for loop item B3: the generated questions against the v0.2 holdout.

The v0.2 holdout (HU-TX-2) candidate was blocked by the signed expert suite
(val-09: "Cable C-4 ..." expected OUT_OF_SCOPE, got ACCEPT) and passed only
after **3 typed leaf edits** (V02_REPORT.md:15). This run asks two questions
and records the answers whichever way they come out:

1. **Coverage.** Does B1 ask a question whose answer owns the leaves those 3
   edits changed? The edits are computed by diffing the v0.2 candidate IR
   against the corrected IR, not typed in here.
2. **Pass without a failed run.** If every question is answered up front as
   it instructs, through B2's checks, does the candidate pass the same signed
   suite on the first validation?

Chain, all real and offline: tx-tasks-v1 regenerated and checked byte for
byte against the digests in the tracked manifest (read from git) -> A1 ingest
-> `syntriass teach start` (compiled) -> A3a draft -> B1 questions -> B2
answers -> compile -> the runtime's own `suite-sign`, `cap-propose` and
`cap-validate`, with the exact arguments `run_task.py` uses. No model.

`run_task.py` itself is not called: after a passing validation it serves the
unseen set, which falls through to a local model for some requests, and no
weights are staged in this container. Validation needs no model. The replica
is checked first against both recorded v0.2 validations (the candidate's
11/12 with val-09, the corrected capability's pass) before any new result is
trusted.

**Who answered:** the engineer recording this run, from the document, under
`engineer:recorder`. Not a domain expert.

Usage:
    deploy/syntriass/venv/bin/python3 \\
        research/capability-learning/harness/record_holdout.py [--out FILE]

Exit codes: 0 recorded (whatever the finding), 3 a step failed,
4 a verification failed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CL = REPO / "research/capability-learning"
sys.path.insert(0, str(REPO / "research" / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import apply_answers as B  # noqa: E402
import demo_evidence  # noqa: E402
import draft_from_session as D  # noqa: E402
import ingest_documents  # noqa: E402
import question_generator as Q  # noqa: E402
import record_answers as RA  # noqa: E402
import record_teach_session as R  # noqa: E402
import schema_subset as S  # noqa: E402
from correct_ir import leaves  # noqa: E402
from ir_compiler import compile_ir  # noqa: E402

TASK = CL / "tasks/tx_hutx2.json"
V02 = CL / "results/v02/postfix"
V02_CANDIDATE_IR = V02 / "holdout_tx/ir.json"
V02_CORRECTED_IR = V02 / "corrected_atomic_tx/corrected.ir.json"
V02_REPORTS = {"candidate": V02 / "deploy_atomic_tx/report.json",
               "corrected": V02 / "deploy_corrected_atomic_tx/report.json"}
MANIFEST = "research/capability-learning/data/tx-tasks-v1/MANIFEST.json"
GENERATOR = CL / "datasets/tx_tasks_v1.py"
EXPERT = "expert:halvorn-power-lead"      # run_task.py: f"expert:{tenant}-lead"
APPROVER = "user:halvorn-power-authority"  # run_task.py: f"user:{tenant}-authority"
PROPOSER = RA.AUTHOR
MKCONFIG = REPO / "research/intelligence-runtime/harness/mkconfig.py"

EXCLUSION_SENTENCE = "does not apply to motors, cables, generators or dry-type transformers"

#: Every question answered as it instructs, read off HU-TX-2 by hand.
AS_INSTRUCTED = [
    # Not "oil-immersed distribution transformers": 38 characters, and the
    # compiler's schema allows 32 per term. B2 refuses it; see LONG_SUBJECT.
    ("scope_subject.*", "Scope: oil-immersed", ["distribution transformers"],
     "'Scope: oil-immersed distribution transformers ...'; the full phrase exceeds the 32-character term limit"),
    ("scope_limit.*", "Scope: oil-immersed", {"ref": "voltage", "op": ">", "value": 33, "unit": "kV"},
     "'up to and including 33 kV': above 33 kV is out of scope"),
    ("scope_exclusion_terms.*", EXCLUSION_SENTENCE, ["motors", "cables", "generators", "dry-type transformers"],
     "copied exactly as written, as the question asks"),
    ("scope_limit.*", "Transformers rated above 33 kV", None,
     "the same 33 kV limit as the scope sentence; teaching it twice would duplicate it"),
    ("required_inputs.*", "Required inputs",
     [{"ref": "voltage", "unit": "kV", "cues": []}, {"ref": "resistance", "unit": "MΩ", "cues": []},
      {"ref": "temperature", "unit": "°C", "cues": []},
      {"ref": "cued_1", "unit": "none", "cues": ["DAR", "dielectric absorption ratio"]}],
     "'voltage in kV, insulation resistance in megohms, top-oil temperature in degrees Celsius, "
     "dielectric absorption ratio (DAR)'"),
    ("correction.*", "Step 2 temperature correction",
     {"template": "multiply_power_per_degree", "target": "resistance", "by": "temperature", "reference": 20,
      "reference_unit": "°C", "rate": 0, "rate_unit": "°C", "base": 2, "step": 15},
     "'to 20 degrees Celsius by multiplying it by 2 raised to the power of (top-oil temperature minus 20) "
     "divided by 15'"),
    ("limit.*", "Step 3 minimum",
     {"template": "coefficient_times_input_plus_offset", "coefficient": 20, "input": "voltage", "offset": 2,
      "unit": "MΩ"}, "'20 times (rated kV plus 2) megohms'"),
    ("rules[].value", "below one third", "corrected", "'if the corrected resistance is below ...'"),
    ("rules[].number", "below one third", {"against": "limit", "number": 0, "unit": "none", "limit_fraction": 1 / 3},
     "'below one third of the minimum'"),
    ("rules[].value", "If it is below the minimum", "corrected", "'it' is the corrected resistance"),
    ("rules[].number", "If it is below the minimum",
     {"against": "limit", "number": 0, "unit": "none", "limit_fraction": 1}, "'below the minimum'"),
    ("rules[].value", "If DAR is below 1.25", "cued_1", "'If DAR is below 1.25'"),
    ("rules[].number", "If DAR is below 1.25", {"against": "number", "number": 1.25, "unit": "none",
                                                 "limit_fraction": 1}, "'below 1.25'; DAR has no unit"),
    ("rules[].value", "at least 1.25 but below 1.4", "cued_1", "'If DAR is at least 1.25 but below 1.4'"),
    ("rules[].op", "at least 1.25 but below 1.4", "<",
     "the 'at least 1.25' half is caught by the earlier 'below 1.25' rule"),
    ("rules[].number", "at least 1.25 but below 1.4",
     {"against": "number", "number": 1.4, "unit": "none", "limit_fraction": 1}, "'below 1.4'; DAR has no unit"),
]

#: The subject copied whole, as the question asks: refused by B2 on length.
LONG_SUBJECT = ["oil-immersed distribution transformers"]

#: Alternative answers to the exclusion question, each put to B2's checks.
EXCLUSION_ALTERNATIVES = {
    "copied_as_written": ["motors", "cables", "generators", "dry-type transformers"],
    "v02_expert_terms": ["motor", "cable", "generator", "dry-type"],
    "both_numbers": ["motor", "motors", "cable", "cables", "generator", "generators", "dry-type"],
}


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise R.Failure(msg, 4)


def run(cmd: list, **kw) -> str:
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise R.Failure(f"{' '.join(str(c) for c in cmd[:3])}: {r.stderr.strip()[-400:]}", 3)
    return r.stdout


def dataset(work: Path) -> Path:
    """Regenerate tx-tasks-v1 and check every file against the tracked manifest."""
    out = work / "data"
    run([sys.executable, "-I", GENERATOR, out])
    pinned = json.loads(run(["git", "-C", REPO, "show", f"HEAD:{MANIFEST}"]))["sha256"]
    for name, digest in pinned.items():
        got = hashlib.sha256((out / name).read_bytes()).hexdigest()
        check(got == digest, f"{name}: regenerated digest {got} != pinned {digest}")
    return out


def release_binary() -> Path:
    run(["cargo", "build", "--release", "--locked", "-p", "syntriass-runtime", "--bin", "syntriass"], cwd=REPO)
    return REPO / "target/release/syntriass"


def validate(binary: Path, data: Path, spec: dict, capability: Path, work: Path) -> dict:
    """run_task.py's setup() + lifecycle() up to cap-validate, same commands and arguments."""
    work.mkdir(parents=True)
    keys = work / "keys"
    keys.mkdir()
    pub = {}
    for who, f in ((EXPERT, "expert.json"), (APPROVER, "approver.json")):
        run([binary, "keygen", "--id", who, "--out", keys / f])
        pub[who] = json.loads((keys / f).read_text())["public_hex"]
    (keys / "approvers.json").write_text(json.dumps({APPROVER: pub[APPROVER]}))
    (keys / "experts.json").write_text(json.dumps({EXPERT: pub[EXPERT]}))
    state = work / "state"
    run([sys.executable, MKCONFIG, state, "balanced", "--approvers", keys / "approvers.json", "--experts",
         keys / "experts.json", "--domain", spec["domain"], "--policy", spec["policy_version"], "--corpus",
         data / "corpus"], env={**os.environ, "SYNTRIASS_BIN": str(binary)})
    cfg = state / "config.json"
    cases = work / "suite_cases.jsonl"
    # counterexample_from_file: run_task.py empties COUNTEREX, so the flag is the file's own.
    rows = [json.loads(line) for line in (data / "validation.jsonl").read_text().splitlines()]
    cases.write_text("".join(json.dumps({**r, "counterexample": r.get("counterexample", False)}) + "\n"
                             for r in rows))
    suite = work / "suite.json"
    run([binary, "suite-sign", "--key", keys / "expert.json", "--cases", cases, "--suite-id",
         f"{spec['family']}/validation", "--tenant", spec["tenant"], "--task", spec["suite_task"], "--out", suite])
    h = json.loads(run([binary, "cap-propose", "--config", cfg, "--file", capability]))["hash"]
    return json.loads(run([binary, "cap-validate", "--config", cfg, "--hash", h, "--suite", suite]))


def summary(rep: dict) -> dict:
    return {k: rep[k] for k in ("passed", "expert_passed", "expert_cases", "counterexamples_passed",
                                "counterexamples", "failures", "suite_independent")}


def compile_to(ir: dict, spec: dict, path: Path) -> Path:
    cap = compile_ir(ir, {**spec, "proposed_by": PROPOSER, "demo_ids": []}).capability
    path.write_text(json.dumps(cap, indent=1, ensure_ascii=False))
    return path


def leaf_diff(a: dict, b: dict) -> list[dict]:
    la, lb = dict(leaves(a)), dict(leaves(b))
    absent = "<absent>"
    return [{"leaf": k, "from": la.get(k, absent), "to": lb.get(k, absent)}
            for k in sorted(set(la) | set(lb)) if la.get(k, absent) != lb.get(k, absent)]


def teach(work: Path, data: Path, spec: dict) -> dict:
    """A1 -> compiled `teach start` -> stored session, for HU-TX-2."""
    binary = R.build_binary()
    cfg = R.write_config(work / "state", work / "config.json")
    corpus = data / "corpus/halvorn-hu-tx-2.txt"
    clauses = work / "clauses.json"
    R.ingest_page(corpus, 1, clauses)
    pick = {"ACCEPT": "allowed", "REMOVE_FROM_SERVICE": "not_allowed", "INVALID_TEST": "not_allowed"}
    demos = [json.loads(line) for line in (data / "demos.jsonl").read_text().splitlines()]
    examples = [{"id": d["id"], "text": d["text"], "label": pick[d["label"]],
                 "reason": f"HU-TX-2 gives {d['label']}"} for d in demos if d["label"] in pick]
    R.jsonl(work / "examples.jsonl", examples)
    (work / "rule.txt").write_text("Accept only a transformer whose corrected resistance meets the HU-TX-2 "
                                   "minimum and whose DAR is acceptable.\n")
    started = json.loads(run([binary, "teach", "start", "--config", cfg, "--tenant", spec["tenant"], "--task",
                              "tx_acceptance", "--expert", EXPERT, "--doc", corpus, "--page", "1", "--clauses",
                              clauses, "--rule-file", work / "rule.txt", "--examples", work / "examples.jsonl"]))
    session = json.loads(run([binary, "teach", "show", "--config", cfg, "--tenant", spec["tenant"], "--session",
                              started["session_id"]]))
    R.verify_hash_independently(session)
    return session


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=REPO / "docs/demo/results/B3_holdout_questions.json")
    a = ap.parse_args(argv)
    spec = json.loads(TASK.read_text())
    work = Path(tempfile.mkdtemp(prefix="b3-holdout-"))
    try:
        data = dataset(work)
        doc_sha = ingest_documents.sha256_file(data / "corpus/halvorn-hu-tx-2.txt")
        release = release_binary()

        # 0. The replica of v0.2's validation reproduces both recorded v0.2 results.
        repro = {}
        for name, cap in (("candidate", V02 / "holdout_tx/capability.json"),
                          ("corrected", V02 / "corrected_atomic_tx/capability.json")):
            got = summary(validate(release, data, spec, cap, work / f"repro_{name}"))
            want = summary(json.loads(V02_REPORTS[name].read_text())["lifecycle"]["validation"])
            check(got == want, f"v0.2 {name} validation not reproduced:\n  got  {got}\n  want {want}")
            repro[name] = got

        # 1. The three edits, computed, and the question that owns them.
        edits = leaf_diff(json.loads(V02_CANDIDATE_IR.read_text()), json.loads(V02_CORRECTED_IR.read_text()))
        check(len(edits) == 3, f"expected the 3 v0.2 edits, found {edits}")
        session = teach(work, data, spec)
        draft = D.draft(session, spec)
        questions = Q.generate(draft, spec)
        owners = [q for q in questions["questions"]
                  if B.LIST_PATHS.get(q["field_path"]) == "out_of_scope_terms"]
        check(len(owners) == 1 and EXCLUSION_SENTENCE in owners[0]["quote"],
              f"expected one exclusion question quoting the sentence, got {[o['quote'] for o in owners]}")
        owner = owners[0]
        # Covered = every edited leaf lies in the list that question's answer sets.
        covered = all(e["leaf"].startswith(".out_of_scope_terms[") for e in edits)

        # 2. What B2 accepts for that question.
        verdicts = {name: B._copied_words(owner["field_path"], terms, owner["quote"]) or "ACCEPTED"
                    for name, terms in EXCLUSION_ALTERNATIVES.items()}

        # 3. Every question answered as instructed, through B2, then validated once.
        check(len(AS_INSTRUCTED) == questions["counts"]["asked"], "the script does not answer every question")
        subject_q = RA.qid_for(questions, "scope_subject.*", "Scope: oil-immersed")
        long_subject = S.validate(LONG_SUBJECT, subject_q["answer_schema"])
        answers = RA.answers_file(draft, questions, AS_INSTRUCTED, 1)
        try:
            answered = B.apply(draft, spec, answers)
        except B.AnswersRefused as e:
            raise R.Failure(f"scripted answers refused: {e.errors}", 4)
        check(answered["status"] == "COMPILES", f"answered IR does not compile: {answered['ir_compile_error']}")
        first = summary(validate(release, data, spec, compile_to(answered["ir"], spec, work / "answered.json"),
                                 work / "val_answered"))

        # 4. Diagnostic, outside B2: the same IR with only the exclusion terms
        #    replaced by the v0.2 expert's. Isolates whether anything else fails.
        swapped = json.loads(json.dumps(answered["ir"]))
        swapped["out_of_scope_terms"] = json.loads(V02_CORRECTED_IR.read_text())["out_of_scope_terms"]
        diag = summary(validate(release, data, spec, compile_to(swapped, spec, work / "swapped.json"),
                                work / "val_swapped"))
        versus_v02 = leaf_diff(json.loads(V02_CORRECTED_IR.read_text()), answered["ir"])
    except R.Failure as e:
        print(f"record_holdout: {e}", file=sys.stderr)
        return e.code
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passes_first_time = first["passed"]
    record = demo_evidence.evidence(
        item="B3 — the generated questions against the v0.2 holdout (HU-TX-2)",
        acceptance_criterion=("the generated questions cover the 3 leaf edits needed after the v0.2 suite "
                              "failure; record honestly whether answering them up front lets the candidate "
                              "pass without a failed run, including if it does not"),
        result="RECORDED",
        repo=REPO,
        finding={
            "questions_cover_the_three_edits": covered,
            "answering_up_front_passes_without_a_failed_run": passes_first_time,
            "why": None if passes_first_time else (
                "The question that owns the three edited leaves is asked, but it instructs 'copy each item "
                "exactly as it is written', which yields the document's plurals; B2 enforces that and refuses "
                "the singular forms the v0.2 expert used. The runtime matches terms whole-word "
                "(quantity.rs find_term), so 'cables' never matches 'Cable C-4' and the first validation "
                "fails on val-09 exactly as v0.2's did."),
        },
        who_answered={"identity": PROPOSER,
                      "statement": "The engineer recording this run, from the document. Not a domain expert."},
        chain={"task_spec": str(TASK.relative_to(REPO)), "dataset": "tx-tasks-v1 regenerated; all files match "
               "the digests in the tracked MANIFEST.json (read from git)",
               "document_sha256": doc_sha,
               "steps": ["tx_tasks_v1.py + digest check", "ingest_documents.py (A1)",
                         "syntriass teach start (A2, compiled)", "draft_from_session.py (A3a)",
                         "question_generator.py (B1)", "apply_answers.py (B2)", "ir_compiler.compile_ir",
                         "syntriass suite-sign / cap-propose / cap-validate (release build)"],
               "model_calls": 0},
        v02_reproduced_first=repro,
        the_three_v02_edits=edits,
        owning_question={"n": owner["n"], "field_path": owner["field_path"], "quote": owner["quote"],
                         "question": owner["question"], "answer_note": owner["answer_note"]},
        b2_verdicts_on_the_exclusion_question=verdicts,
        second_finding_subject_length={
            "question": subject_q["question"],
            "answer_copied_whole": LONG_SUBJECT,
            "b2_verdict": long_subject,
            "reading": ("The question says to copy the words exactly but does not state the compiler's "
                        "32-character term limit, so the natural answer is refused. B2 is right to refuse "
                        "(compile_ir does not enforce its own maxLength; the v0.2 model IR carried this "
                        "38-character term); the question should state the limit."),
        },
        answered_as_instructed={"counts": answered["counts"], "status": answered["status"],
                                "first_validation": first},
        diagnostic_outside_b2={"change": "out_of_scope_terms replaced by the v0.2 expert's terms; nothing else",
                               "validation": diag},
        answered_ir_versus_v02_corrected=versus_v02,
        not_measured={"unseen_30": "NOT_MEASURED here: serving falls through to a local model for some "
                                   "requests and no weights are staged in this container."},
    )
    demo_evidence.write(a.out, record)
    print(f"record_holdout: {a.out}")
    print(f"  v0.2 reproduced: candidate {repro['candidate']['expert_passed']}/{repro['candidate']['expert_cases']}"
          f", corrected passed={repro['corrected']['passed']}")
    print(f"  edits {[e['leaf'] for e in edits]} owned by question {owner['n']} ({owner['field_path']})")
    print(f"  B2: {verdicts}")
    print(f"  answered as instructed -> first validation passed={first['passed']} failures={first['failures']}")
    print(f"  diagnostic (exclusion terms swapped, outside B2) -> passed={diag['passed']} failures={diag['failures']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
