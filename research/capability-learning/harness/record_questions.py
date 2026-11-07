#!/usr/bin/env python3
"""Recorded run for loop item B1: draft -> plain-language questions.

Chain, all real and offline: EP-114 corpus -> A1 ingester -> `syntriass teach
start` (compiled binary) -> A3a draft -> B1 questions. No model.

The check that matters for a question generator is not that it produces
questions but that the **right answer is reachable** from what each question
offers. A closed-choice question that leaves out the true answer forces the
expert to answer wrongly. So for every question whose true answer can be read
off the document by hand, this run asserts that answer is among the choices.

Usage:
    deploy/syntriass/venv/bin/python3 \\
        research/capability-learning/harness/record_questions.py [--out FILE]

Exit codes: 0 pass, 3 a step failed, 4 a verification failed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "research" / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo_evidence  # noqa: E402
import question_generator as Q  # noqa: E402
import record_draft  # noqa: E402
import record_teach_session as R  # noqa: E402

#: True answers read off the EP-114 corpus by hand, for the questions whose
#: answer is a choice. (field path, text the question quotes) -> answer code.
TRUE_CHOICES = {
    ("validity[].outcome", "between 10 and 75 degrees Celsius inclusive"): "INVALID_TEST",
    ("rules[].op", "at least 1.5 but below 2.0"): ">=",
}
#: The other half of that sentence, which must also be offered: the expert
#: teaches one comparison here and the other as a second rule.
ALSO_REACHABLE = {("rules[].op", "at least 1.5 but below 2.0"): "<"}


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise R.Failure(msg, 4)


def find(questions: list[dict], path: str, fragment: str) -> dict:
    hits = [q for q in questions if q["field_path"] == path and fragment in q["quote"]]
    check(len(hits) == 1, f"expected one {path} question quoting {fragment!r}, found {len(hits)}")
    return hits[0]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path,
                    default=REPO / "docs/demo/results/B1_question_generator.json")
    a = ap.parse_args(argv)
    work = Path(tempfile.mkdtemp(prefix="b1-questions-"))
    try:
        binary = R.build_binary()
        draft_sections = record_draft.record_run(work, binary)
        draft = json.loads((work / "draft.json").read_text())
        spec = json.loads(record_draft.TASK.read_text())
        out = Q.generate(draft, spec)

        c = out["counts"]
        check(c["asked"] + c["not_asked"] == c["draft_unsettled_fields"], "a field was dropped")
        check(out["model_calls"] == 0, "a model was called")

        reach = {}
        for (path, frag), code in {**TRUE_CHOICES, **ALSO_REACHABLE}.items():
            q = find(out["questions"], path, frag)
            offered = [ch["code"] for ch in q["choices"]]
            check(code in offered, f"{path} on {frag!r}: true answer {code} not offered {offered}")
            reach[f"{path} | {frag}"] = {"true_answer": code, "offered": offered, "reachable": True}

        not_asked_answering = [n["text"] for n in out["not_asked"]
                               if "test is invalid" in n["text"]]
    except R.Failure as e:
        print(f"record_questions: {e}", file=sys.stderr)
        return e.code
    finally:
        shutil.rmtree(work, ignore_errors=True)

    record = demo_evidence.evidence(
        item="B1 — plain-language question generator over the A3a draft",
        acceptance_criterion=(
            "each hypothesis/issue field -> one plain-language question carrying the "
            "candidate values; deterministic templates only; no model"
        ),
        result="MET",
        repo=REPO,
        chain={**draft_sections["chain"],
               "steps": draft_sections["chain"]["steps"] + ["question_generator.py (B1)"]},
        counts=c,
        questions=[{k: q[k] for k in ("n", "field_path", "citation", "question", "choices", "answer_note")}
                   for q in out["questions"]],
        not_asked=out["not_asked"],
        true_answer_reachability={
            "method": ("For each closed-choice question whose answer can be read off the "
                       "corpus by hand, assert that answer is among the choices offered. "
                       "A choice list that excludes the right answer forces a wrong one."),
            "results": reach,
        },
        finding_for_E1={
            "observation": ("The sentence that answers the validity-outcome question is "
                            "itself 'not asked', because on its own it states nothing the "
                            "system can use. B1 is right not to infer from it; the screen "
                            "must still show it beside the question."),
            "sentence": not_asked_answering,
        },
        rephrasing=out["rephrasing"],
    )
    demo_evidence.write(a.out, record)
    print(f"record_questions: {a.out.relative_to(REPO)}")
    print(f"  {c['asked']} asked ({c['with_closed_choices']} closed), {c['not_asked']} not asked, "
          f"true answers reachable: {len(reach)}/{len(reach)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
