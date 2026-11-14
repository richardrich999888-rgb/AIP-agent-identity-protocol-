#!/usr/bin/env python3
"""Recorded run for loop item B2: answers -> typed leaf edits on the IR.

Chain, all real and offline: EP-114 corpus -> A1 ingester -> `syntriass teach
start` (compiled binary) -> A3a draft -> B1 questions -> B2 answers applied.
No model.

**Who answered.** No domain expert has answered these questions. The answers
below were read off the EP-114 corpus by the engineer recording this run, one
per question, each citing its sentence, and are recorded under the identity
`engineer:recorder` so nothing here can be read as an expert's judgement.
What this run measures is the mechanism — every answer becomes typed leaf
edits with who/when/why, and an answer that cannot be right is refused at its
question — not how well an expert answers.

Two answer files are applied:

1. `SCRIPTED`: one answer per question. Expected: the IR compiles.
2. `REFUSED`: the same file with three deliberate faults (a number the
   sentence does not state, a term it does not contain, the same scope limit
   taught twice). Expected: refused as a whole, each fault reported at its own
   question, nothing applied.

Usage:
    deploy/syntriass/venv/bin/python3 \\
        research/capability-learning/harness/record_answers.py [--out FILE]

Exit codes: 0 pass, 3 a step failed, 4 a verification failed.
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "research" / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import apply_answers as B  # noqa: E402
import demo_evidence  # noqa: E402
import question_generator as Q  # noqa: E402
import record_draft  # noqa: E402
import record_teach_session as R  # noqa: E402

AUTHOR = "engineer:recorder"

#: (field path, text the question quotes, answer or None for "not applicable",
#: why). Read off the EP-114 corpus by hand. Rule order is the document's.
SCRIPTED = [
    ("scope_subject.*", "Scope: induction motors", ["induction motors"],
     "'Scope: induction motors rated up to and including 11 kV.'"),
    ("scope_limit.*", "Scope: induction motors", {"ref": "voltage", "op": ">", "value": 11, "unit": "kV"},
     "'up to and including 11 kV': a rating above 11 kV is out of scope"),
    ("scope_exclusion_terms.*", "does not apply to", ["transformers", "cables", "generators"],
     "'does not apply to transformers, cables, generators'; motors above 11 kV are the voltage limit"),
    ("scope_limit.*", "does not apply to", None,
     "the same 11 kV limit as the scope sentence; teaching it twice would duplicate it"),
    ("required_inputs.*", "Required inputs",
     [{"ref": "voltage", "unit": "kV", "cues": []},
      {"ref": "resistance", "unit": "MΩ", "cues": []},
      {"ref": "temperature", "unit": "°C", "cues": []},
      {"ref": "cued_1", "unit": "none", "cues": ["PI", "polarization index"]}],
     "'rated voltage in kV, insulation resistance in megohms, winding temperature in degrees Celsius, "
     "polarization index (PI)'"),
    ("validity[].outcome", "between 10 and 75 degrees Celsius", "INVALID_TEST",
     "the next sentence: 'Outside that range the test is invalid and must be repeated.'"),
    ("correction.*", "Step 2 temperature correction",
     {"template": "multiply_power_per_degree", "target": "resistance", "by": "temperature",
      "reference": 40, "reference_unit": "°C", "rate": 0, "rate_unit": "°C", "base": 2, "step": 10},
     "'correct the measured resistance to 40 degrees Celsius by multiplying it by two raised to the "
     "power of (winding temperature minus 40) divided by 10'"),
    ("limit.*", "Step 3 minimum",
     {"template": "coefficient_times_input_plus_offset", "coefficient": 10, "input": "voltage",
      "offset": 1, "unit": "MΩ"},
     "'the minimum acceptable corrected resistance is 10 times (rated kV plus 1) megohms'"),
    ("rules[].value", "below half of the minimum", "corrected", "'if the corrected resistance is below ...'"),
    ("rules[].number", "below half of the minimum",
     {"against": "limit", "number": 0, "unit": "none", "limit_fraction": 0.5},
     "'below half of the minimum': half of the Step 3 limit"),
    ("rules[].value", "If it is below the minimum", "corrected", "'it' is the corrected resistance of the previous sentence"),
    ("rules[].number", "If it is below the minimum",
     {"against": "limit", "number": 0, "unit": "none", "limit_fraction": 1},
     "'below the minimum': the whole Step 3 limit"),
    ("rules[].value", "PI is below 1.5", "cued_1", "'PI is below 1.5'"),
    ("rules[].number", "PI is below 1.5",
     {"against": "number", "number": 1.5, "unit": "none", "limit_fraction": 1}, "'below 1.5'; PI has no unit"),
    ("rules[].value", "at least 1.5 but below 2.0", "cued_1", "'If PI is at least 1.5 but below 2.0'"),
    ("rules[].op", "at least 1.5 but below 2.0", "<",
     "the 'at least 1.5' half is already caught by the earlier 'below 1.5' rule, so this rule checks 'below 2.0'"),
    ("rules[].number", "at least 1.5 but below 2.0",
     {"against": "number", "number": 2.0, "unit": "none", "limit_fraction": 1}, "'below 2.0'; PI has no unit"),
]

#: Deliberate faults, each replacing one SCRIPTED answer: (field path, quote
#: fragment, faulty answer, the refusal it must produce).
FAULTS = [
    ("rules[].number", "at least 1.5 but below 2.0",
     {"against": "number", "number": 2.5, "unit": "none", "limit_fraction": 1}, "not stated in the quoted sentence"),
    ("scope_subject.*", "Scope: induction motors", ["synchronous motors"], "not written in the quoted sentence"),
    ("scope_limit.*", "does not apply to", {"ref": "voltage", "op": ">", "value": 11, "unit": "kV"},
     "duplicates an out_of_scope_limits entry"),
]


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise R.Failure(msg, 4)


def qid_for(questions: dict, path: str, fragment: str) -> dict:
    hits = [q for q in questions["questions"] if q["field_path"] == path and fragment in q["quote"]]
    check(len(hits) == 1, f"expected one {path} question quoting {fragment!r}, found {len(hits)}")
    return hits[0]


def answers_file(draft: dict, questions: dict, table: list, start_ms: int) -> dict:
    """An answers file for `table`, one entry per row, timestamps in order."""
    out = []
    for i, (path, frag, answer, why) in enumerate(table):
        e = {"qid": qid_for(questions, path, frag)["qid"], "who": AUTHOR, "when_ms": start_ms + i, "why": why}
        if answer is None:
            e["not_applicable"] = True
        else:
            e["answer"] = copy.deepcopy(answer)
        out.append(e)
    return {"schema": B.ANSWERS_SCHEMA, "session_id": draft["session_id"],
            "draft_sha256": B.draft_digest(draft),
            "questions_sha256": B.questions_digest(questions), "answers": out}


def with_faults(table: list) -> list:
    """SCRIPTED with each FAULTS row's answer substituted."""
    faulty = [list(r) for r in table]
    for path, frag, bad, _ in FAULTS:
        rows = [r for r in faulty if r[0] == path and r[1] == frag]
        check(len(rows) == 1, f"fault target {path} {frag!r} not unique")
        rows[0][2] = bad
    return [tuple(r) for r in faulty]


def read_back(ir: dict, path: str):
    """The value at an edit's resolved path, read independently of B2."""
    node: object = ir
    for part in path.replace("]", "").replace("[", ".").split("."):
        node = node[int(part)] if part.isdigit() else node[part]
    return node


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=REPO / "docs/demo/results/B2_answer_application.json")
    a = ap.parse_args(argv)
    work = Path(tempfile.mkdtemp(prefix="b2-answers-"))
    try:
        binary = R.build_binary()
        sections = record_draft.record_run(work, binary)
        draft = json.loads((work / "draft.json").read_text())
        spec = json.loads(record_draft.TASK.read_text())
        questions = Q.generate(draft, spec)
        check(len(SCRIPTED) == questions["counts"]["asked"], "the script does not answer every question once")

        now_ms = int(time.time() * 1000)
        out = B.apply(draft, spec, answers_file(draft, questions, SCRIPTED, now_ms))
        c = out["counts"]
        check(out["status"] == "COMPILES", f"answered IR does not compile: {out['ir_compile_error']} "
                                           f"{out['ir_schema_errors']}")
        check(out["numbers_without_cited_provenance"] == [], "a number lacks provenance")
        check(c["unanswered"] == 0 and c["elements_incomplete"] == 0, "something left unfilled")
        for e in out["edits"]:
            check(all(e[k] for k in ("who", "why")) and e["when_ms"] > 0, f"edit lacks who/when/why: {e}")
            check(e["path"] is not None, f"edit not in the IR: {e}")
            check(read_back(out["ir"], e["path"]) == e["after"], f"edit not reflected in the IR: {e}")

        try:
            B.apply(draft, spec, answers_file(draft, questions, with_faults(SCRIPTED), now_ms))
        except B.AnswersRefused as refused:
            errors = refused.errors
        else:
            raise R.Failure("the faulty answers file was applied", 4)
        for path, frag, _, expect in FAULTS:
            n = qid_for(questions, path, frag)["n"]
            check(any(x["question"] == n and expect in x["error"] for x in errors),
                  f"fault at question {n} ({path}) not reported as {expect!r}: {errors}")
        check(len(errors) == len(FAULTS), f"expected exactly {len(FAULTS)} refusals, got {errors}")
    except R.Failure as e:
        print(f"record_answers: {e}", file=sys.stderr)
        return e.code
    finally:
        shutil.rmtree(work, ignore_errors=True)

    record = demo_evidence.evidence(
        item="B2 — answer application: answers become typed leaf edits on the IR",
        acceptance_criterion=("answers become typed leaf edits on the IR, each recorded with who, when and "
                              "why, and counted"),
        result="MET",
        repo=REPO,
        chain={**sections["chain"],
               "steps": sections["chain"]["steps"] + ["question_generator.py (B1)", "apply_answers.py (B2)"]},
        who_answered={
            "identity": AUTHOR,
            "statement": ("No domain expert answered. The engineer recording this run read each answer off "
                          "the EP-114 corpus, citing the sentence. This measures the mechanism, not an "
                          "expert's answers."),
        },
        counts=c,
        status=out["status"],
        ir_compiles=out["ir_compiles"],
        ir=out["ir"],
        elements=out["elements"],
        edits=out["edits"],
        not_applicable=out["not_applicable"],
        verification={
            "every_edit_has_who_when_why": True,
            "every_edit_read_back_from_the_ir_at_its_path": len(out["edits"]),
            "method": ("Each edit's resolved path is read from the answered IR by a path walker in this "
                       "recorder, independent of B2, and compared with the edit's `after`."),
        },
        refusal_check={
            "faults_injected": [{"field_path": p, "quote_contains": f, "answer": bad, "expected": x}
                                for p, f, bad, x in FAULTS],
            "result": "REFUSED; nothing applied",
            "errors": errors,
        },
        leaf_count_note=("leaf_edits counts leaves whose value changed, the v0.2 definition "
                         "(correct_ir.edit_count). It includes leaves the compiler's schema requires but "
                         "the compiler ignores, e.g. `number` = 0 on a rule compared with the limit."),
        scored=None,
        scored_note="NOT_MEASURED: C1 scores the answered IR against the examples and the suite.",
    )
    demo_evidence.write(a.out, record)
    print(f"record_answers: {a.out}")
    print(f"  {out['status']}: answered {c['answered']} of {c['questions']} ({c['not_applicable']} not applicable), "
          f"{c['leaf_edits']} leaf edits by {AUTHOR}, {c['leaves_from_document']} leaves from the document")
    print(f"  faulty file refused with {len(errors)} errors at their questions; nothing applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
