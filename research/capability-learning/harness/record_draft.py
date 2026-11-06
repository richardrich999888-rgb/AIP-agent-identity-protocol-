#!/usr/bin/env python3
"""Recorded run for loop item A3a: teach session -> deterministic IR draft.

Chain, all real: the EP-114 corpus the task spec names -> the A1 ingester ->
`syntriass teach start` (the compiled binary) -> `draft_from_session`. No
model is loaded and none is reachable.

What the run is for. A3a's claim is not "drafting works without a model" --
it does not. The claim is that the draft fills exactly what the cited clauses
determine, classifies everything else as `hypothesis` or `issue`, and so
measures how much of the IR the document fixes on its own. That number is the
denominator for any later claim about what a model contributed, which is why
it is recorded before any model exists to credit.

Every filled value is cross-checked here against the document independently of
the drafter, so the evidence does not rest on the drafter agreeing with itself.

Usage:
    deploy/syntriass/venv/bin/python3 \\
        research/capability-learning/harness/record_draft.py [--out FILE] [--keep DIR]

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
import draft_from_session as D  # noqa: E402
import ingest_documents  # noqa: E402
import record_teach_session as R  # noqa: E402

TASK = REPO / "research/capability-learning/tasks/ir_ep114.json"
CORPUS = REPO / "research/capability-learning/data/ir-tasks-v1/corpus/koravi-ep-114.txt"

#: Grounded in EP-114 rev C: validity 10-75 degC, minimum 10*(kV+1) megohm,
#: PI thresholds 1.5 and 2.0. Synthetic readings, no customer data.
EXAMPLES = [
    {
        "id": "d1",
        "text": "A 6.6 kV motor at 40 degrees Celsius read 95 megohm with PI 2.4.",
        "label": "allowed",
        "reason": "Inside the validity range, above the 76 megohm minimum for 6.6 kV, PI above 2.0.",
    },
    {
        "id": "d2",
        "text": "A 6.6 kV motor at 85 degrees Celsius read 95 megohm with PI 2.4.",
        "label": "not_allowed",
        "reason": "85 degrees Celsius is outside the 10 to 75 validity range, so the test is invalid.",
    },
    {
        "id": "d3",
        "text": "A 6.6 kV motor at 40 degrees Celsius read 30 megohm with PI 2.4.",
        "label": "not_allowed",
        "reason": "30 megohm is below the 76 megohm minimum for a 6.6 kV motor.",
    },
]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise R.Failure(message, 4)


def independent_cross_check(draft: dict, document_text: str) -> dict:
    """Confirm each filled value against the document, without the drafter.

    Read straight out of the corpus by eye and asserted here as literals: if
    the drafter's reading of the document ever drifts from what the document
    says, this fails rather than agreeing with it.
    """
    expected = {
        "validity[].min": 10.0,
        "validity[].max": 75.0,
        "validity[].unit": "°C",
        "validity[].ref": "temperature",
        "missing_input_outcome": "INSUFFICIENT_INPUT",
        "default_outcome": "PASS",
    }
    filled = {f["path"]: f["value"] for f in draft["fields"] if f["status"] == "evidence"}
    check(
        filled == expected,
        f"filled fields differ from the document:\n  got      {filled}\n  expected {expected}",
    )
    # And the sentences those came from are really in the corpus.
    for phrase in (
        "between 10 and 75 degrees Celsius inclusive",
        "the result is insufficient input",
        "Otherwise pass.",
    ):
        check(phrase in document_text, f"corpus does not contain {phrase!r}")
    return {
        "method": (
            "Each filled value is asserted against literals read from the "
            "corpus by hand, and the sentence each came from is confirmed "
            "present in the file. The drafter is not consulted."
        ),
        "fields_confirmed": expected,
        "agrees": True,
    }


def record_run(work: Path, binary: Path) -> dict:
    spec = json.loads(TASK.read_text())
    document_text = CORPUS.read_text()
    state = work / "state"
    config = R.write_config(state, work / "config.json")

    clause_file = work / "corpus.clauses.json"
    payload = R.ingest_page(CORPUS, 1, clause_file)
    check(payload["clause_count"] > 0, "the corpus yielded no clauses")
    check(
        set(payload["extraction_counts"]) == {"txt"},
        f"unexpected extraction kinds: {payload['extraction_counts']}",
    )

    rule_file = work / "rule.txt"
    rule_file.write_text(
        "Only accept a motor whose winding temperature was inside the EP-114 "
        "validity range and whose corrected resistance met the minimum for its "
        "rated voltage.\n"
    )
    started = R.start_session(
        binary, config, CORPUS, 1, clause_file, "ir_acceptance", rule_file,
        R.jsonl(work / "examples.jsonl", EXAMPLES),
    )
    session = json.loads(
        R.run([
            str(binary), "teach", "show", "--config", str(config),
            "--tenant", R.TENANT, "--session", started["session_id"],
        ])
    )
    R.verify_hash_independently(session)

    draft = D.draft(session, spec)
    check(draft["model_calls"] == 0, "the draft called a model")
    counts = draft["field_counts"]
    check(sum(counts.values()) == len(draft["fields"]), "field counts do not add up")
    check(
        len(draft["questions"]) == counts["hypothesis"] + counts["issue"],
        "a question is missing for an unsettled field",
    )
    cross = independent_cross_check(draft, document_text)

    draft_path = work / "draft.json"
    draft_path.write_text(json.dumps(draft, indent=2) + "\n")

    return {
        "chain": {
            "task_spec": str(TASK.relative_to(REPO)),
            "document": str(CORPUS.relative_to(REPO)),
            "document_sha256": ingest_documents.sha256_file(CORPUS),
            "steps": [
                "ingest_documents.py (A1)",
                "syntriass teach start (A2, compiled binary)",
                "draft_from_session.py (A3a)",
            ],
            "model_calls": 0,
            "model_calls_note": (
                "A3a is deterministic by construction: it reads values off "
                "clause text and enumerates alternatives it will not choose "
                "between. Choosing is A3b's job and needs the model bundle."
            ),
        },
        "session": {
            "session_id": session["session_id"],
            "tenant": session["tenant"],
            "clauses_cited": len(session["clauses"]),
            "examples": len(session["examples"]),
        },
        "draft": {
            "status": draft["status"],
            "claim_units": len(draft["claim_units"]),
            "claims_determined": [c["kind"] for c in draft["claims_determined"]],
            "field_counts": counts,
            "fields_filled": {
                f["path"]: f["value"] for f in draft["fields"] if f["status"] == "evidence"
            },
            "ir_unfilled_required": draft["ir_unfilled_required"],
            "ir_compiles": draft["ir_compiles"],
            "ir_compile_error": draft["ir_compile_error"],
            "questions": len(draft["questions"]),
        },
        "what_the_document_determines_on_its_own": {
            "of_the_five_required_ir_fields": {
                "determined": sorted(
                    set(D.REQUIRED_IR_FIELDS) - set(draft["ir_unfilled_required"])
                ),
                "not_determined": draft["ir_unfilled_required"],
            },
            "reading": (
                f"{counts['evidence']} of {sum(counts.values())} field states are "
                f"evidence. The draft does not compile and says so: that is the "
                f"honest outcome of a deterministic pass, not a failure of it. "
                f"The {len(draft['questions'])} questions are what a model, or "
                f"the expert, has to answer."
            ),
        },
        "segmentation_bridge": {
            "finding": (
                "A1 splits clauses at . ; : ! ? so a citation is a span a human "
                "can check, which puts 'Step 1 validity:' in a different clause "
                "from the numbers it heads. The claim extractors need the whole "
                "sentence. Cited clauses are therefore rejoined in document "
                "order and re-split at sentence ends, and each claim unit "
                "records the clause ids it came from so a claim stays traceable "
                "to the citations the expert chose."
            ),
            "clauses_cited": len(session["clauses"]),
            "claim_units_after_rejoining": len(draft["claim_units"]),
        },
        "examples_not_scored": {
            "value": None,
            "why": draft["examples_note"],
        },
        "artifacts": {
            "draft": str(draft_path.relative_to(work)),
            "retained": "no (temporary working directory; rerun to reproduce)",
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path,
                    default=REPO / "docs" / "demo" / "results" / "A3a_deterministic_draft.json")
    ap.add_argument("--keep", type=Path, help="work here and leave it in place")
    a = ap.parse_args(argv)

    work = a.keep or Path(tempfile.mkdtemp(prefix="a3a-draft-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        binary = R.build_binary()
        sections = record_run(work, binary)
    except R.Failure as error:
        print(f"record_draft: {error}", file=sys.stderr)
        return error.code
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)

    record = demo_evidence.evidence(
        item="A3a — deterministic draft from a teach session: IR fields the cited clauses determine",
        acceptance_criterion=(
            "session -> IR with every field the clauses determine filled and every "
            "other field marked hypothesis or issue, with no model call"
        ),
        result="MET",
        repo=REPO,
        **sections,
    )
    demo_evidence.write(a.out, record)
    d = record["draft"]
    print(f"record_draft: {a.out.relative_to(REPO)}")
    print(f"  {record['session']['clauses_cited']} clauses cited -> "
          f"{d['claim_units']} claim units -> {len(d['claims_determined'])} claim(s)")
    print(f"  fields: {d['field_counts']['evidence']} evidence, "
          f"{d['field_counts']['hypothesis']} hypothesis, {d['field_counts']['issue']} issue")
    print(f"  {d['questions']} question(s); status {d['status']}; model calls 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
