#!/usr/bin/env python3
"""A3a: deterministic draft of a capability IR from a teach session.

Takes the session `syntriass teach start` produced (cited clauses, the
expert's plain-language rule, 2-5 labelled examples) and fills as much of the
`ir_compiler` IR as the **cited clause text alone determines**. Every field it
cannot determine is classified, never guessed:

    evidence    the clause fixes exactly one value, and it is filled in
    hypothesis  the clause allows several values; the alternatives are
                recorded and the field is left empty
    issue       the clause supports the field's kind but fixes nothing, or
                states something the IR cannot express

No model is loaded and none is reachable. That is the point of splitting A3:
the model's job in `propose_atomic.py` is to *choose* among the alternatives
this module enumerates, so what the document already determines should never
be left to it. Running the deterministic half alone also measures how much of
the IR the clauses fix on their own, which is the denominator for any later
claim about what a model contributed.

What this module does not do: invent a value, rank alternatives, or fill a
field from the expert's free-text rule. The rule is recorded for the question
generator (B1) to quote back; parsing intent out of prose is exactly the step
that produced the wrong thresholds recorded in `YC_TECHNICAL_CLAIMS.md`.

Usage:
    draft_from_session.py SESSION.json --task TASK.json [--out DRAFT.json]

Exit codes: 0 a draft was produced (complete or not), 2 bad input,
3 the session and the task disagree.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import atomic as A  # noqa: E402
from ir_compiler import IRError, compile_ir, provenance_check  # noqa: E402

#: Session schema this module reads. A different one is refused rather than
#: parsed hopefully: the field meanings are the contract.
SESSION_SCHEMA = "syntriass.teach-session/v1"

#: Kinds whose fields this module determines from clause text. Deliberately
#: short. A kind is added here only once there is a rule that reads the value
#: off the clause without judgement, and a test that pins it.
DETERMINED_KINDS = ("validity", "decision_rule", "missing_input", "default_outcome")

#: Kinds a clause may plausibly state but whose fields need a choice this
#: module will not make (which words name the subject, which template a
#: correction follows). Recorded as questions for B1.
DEFERRED_KINDS = (
    "scope_subject",
    "scope_exclusion_terms",
    "scope_limit",
    "required_inputs",
    "correction",
    "limit",
)


class DraftError(ValueError):
    """The session or task is unusable. Never raised for an incomplete draft:
    an incomplete draft is the normal, useful outcome."""


@dataclass
class FieldState:
    """One IR field and why it holds what it holds."""

    path: str
    status: str  # "evidence" | "hypothesis" | "issue"
    clause: str
    basis: str
    value: Any = None
    candidates: list = field(default_factory=list)


@dataclass
class Question:
    """A field the expert must settle, with everything needed to ask about it.

    `candidates` is the closed set the clause allows, so B1 can offer a choice
    rather than an open prompt, and an answer outside it is refusable.
    """

    field_path: str
    clause: str
    citation: str
    clause_text: str
    needs: str
    candidates: list = field(default_factory=list)
    ocr_warning: bool = False


def _frac(x: Fraction | float) -> float:
    """IR numbers are JSON floats; clause numbers arrive as Fractions."""
    return float(x)


def _unit_kind(unit: str) -> str:
    from ir_compiler import UNIT_KIND

    return UNIT_KIND[unit][0] if unit in UNIT_KIND else "cued"


def _ref_for_unit(unit: str) -> str | None:
    """The IR input ref a unit implies, or None when the unit is unitless.

    A unitless number names no input on its own, which is why `cued_1`/
    `cued_2` are never inferred here: which cued input a bare number belongs
    to is a choice, not a reading.
    """
    kind = _unit_kind(unit)
    return kind if kind in ("voltage", "resistance", "temperature") else None


def _outcome_state(
    text: str, outcomes: list[str], path: str, clause_id: str
) -> FieldState:
    """Classify an outcome field from the outcome words the clause contains."""
    matched = A.outcome_match(text, outcomes)
    if len(matched) == 1:
        return FieldState(path, "evidence", clause_id, "the clause names exactly one outcome", matched[0])
    if matched:
        return FieldState(
            path,
            "hypothesis",
            clause_id,
            f"the clause names {len(matched)} outcomes; which one applies is a choice",
            candidates=matched,
        )
    return FieldState(path, "issue", clause_id, "the clause names no outcome from the task's vocabulary")


#: "between 10 and 75 degrees Celsius" tags only the second number, because
#: the unit follows it. The bound that carries no unit takes the other's.
_BETWEEN = re.compile(r"\bbetween\b", re.IGNORECASE)


def _range_numbers(text: str) -> tuple[list[A.Num], str | None]:
    """The two bounds of a stated range, and the unit both carry.

    In "between A and B UNIT" the unit is written once, after the second
    bound, and applies to both: the IR's `validity` has a single `unit` field
    for `min` and `max`, so there is no second unit for A to have had. The
    inheritance is therefore a reading of the sentence, not a choice about it,
    and it only applies when the clause says "between", there are exactly two
    numbers, and exactly one of them is tagged.
    """
    nums = A.clause_numbers(text)
    tagged = [n for n in nums if n.unit != "none"]
    if len(tagged) == 2 and len({n.unit for n in tagged}) == 1:
        return tagged, tagged[0].unit
    if _BETWEEN.search(text) and len(nums) == 2 and len(tagged) == 1:
        unit = tagged[0].unit
        return list(nums), unit
    return tagged, None


#: A rule whose subject is written "corrected <reading>" may compare the
#: reading itself or the value the correction step produced. Which one is a
#: choice: the IR's `corrected` exists only when a correction is taught.
_CORRECTED = re.compile(r"\bcorrected\b", re.IGNORECASE)


def _validity(clause: dict, outcomes: list[str]) -> tuple[dict | None, list[FieldState]]:
    """A validity range: two numbers of one unit, and an outcome for outside it.

    Every leaf of the range is classified on its own, so a range whose
    numbers cannot be read still asks which outcome applies outside it, and
    no leaf is left neither filled nor asked about. A claim is returned only
    when every leaf is evidence.
    """
    cid, text = clause["id"], clause["text"]
    nums, inherited = _range_numbers(text)
    units = {inherited} if inherited else {n.unit for n in nums}
    states: list[FieldState] = []
    ref, lo, hi, unit = None, None, None, None
    if len(nums) != 2 or len(units) != 1 or inherited is None:
        range_states = [
            FieldState(
                "validity[].min/max",
                "issue",
                cid,
                f"a range needs exactly two numbers sharing one unit; found {len(nums)} "
                f"number(s) in {sorted(units) or 'no'} unit(s)",
            )
        ]
        ref_state = FieldState(
            "validity[].ref", "issue", cid, "without a readable range there is no unit naming the reading"
        )
    else:
        unit = inherited
        lo, hi = sorted(_frac(n.value) for n in nums)
        range_states = [
            FieldState("validity[].min", "evidence", cid, "lower of the two numbers in the clause", lo),
            FieldState("validity[].max", "evidence", cid, "upper of the two numbers in the clause", hi),
            FieldState(
                "validity[].unit",
                "evidence",
                cid,
                "the unit written after the second bound, which both bounds carry",
                unit,
            ),
        ]
        ref = _ref_for_unit(unit)
        ref_state = (
            FieldState("validity[].ref", "issue", cid, f"unit {unit} names no IR input")
            if ref is None
            else FieldState("validity[].ref", "evidence", cid, f"unit {unit} is a {ref} unit", ref)
        )
    out = _outcome_state(text, outcomes, "validity[].outcome", cid)
    states = [ref_state, *range_states, out]
    if any(st.status != "evidence" for st in states):
        return None, states
    return {"ref": ref, "min": lo, "max": hi, "unit": unit, "outcome": out.value}, states


def _decision_rule(clause: dict, outcomes: list[str]) -> tuple[dict | None, list[FieldState]]:
    """A single `if <value> <op> <number>, <outcome>` rule.

    Every leaf of the rule is classified on its own — which reading, which
    comparison, compared with what, and the outcome — so a rule that cannot
    be completed from its clause still asks about each missing leaf. Stopping
    at the first undetermined leaf would leave the rest neither filled nor
    asked about, and the expert could answer every question and still be left
    with a rule that cannot compile. A claim is returned only when every leaf
    is evidence, in the shape `atomic.assemble` takes.
    """
    cid, text = clause["id"], clause["text"]
    cmps = A.comparators(text)
    nums = [n for n in A.clause_numbers(text) if n.unit != "none"]

    if len(cmps) == 1:
        op = cmps[0][1]
        op_state = FieldState("rules[].op", "evidence", cid, "the only comparator in the clause", op)
    else:
        op = None
        op_state = FieldState(
            "rules[].op",
            "issue" if not cmps else "hypothesis",
            cid,
            f"the IR has no conjunction, so a rule needs exactly one comparator; found {len(cmps)}",
            candidates=[o for _, o in cmps],
        )

    num = nums[0] if len(nums) == 1 else None
    if num is not None:
        number_states = [
            FieldState("rules[].against", "evidence", cid,
                       "the clause compares with a number it states", "number"),
            FieldState("rules[].number", "evidence", cid, "the only tagged number in the clause",
                       _frac(num.value)),
            FieldState("rules[].unit", "evidence", cid, "the unit that number carries", num.unit),
            FieldState("rules[].limit_fraction", "evidence", cid,
                       "a stated number is compared whole, not as a fraction of a limit", 1),
        ]
    else:
        number_states = [
            FieldState(
                "rules[].number",
                "issue" if not nums else "hypothesis",
                cid,
                f"one comparator needs exactly one tagged number to compare against; found {len(nums)}",
                candidates=[{"value": _frac(n.value), "unit": n.unit} for n in nums],
            )
        ]

    ref = _ref_for_unit(num.unit) if num is not None else None
    if ref is None:
        value_state = FieldState(
            "rules[].value",
            "issue",
            cid,
            "no single tagged number names the reading, so which reading is compared is a choice",
        )
    elif _CORRECTED.search(text):
        value_state = FieldState(
            "rules[].value",
            "hypothesis",
            cid,
            f"the clause says 'corrected': the {ref} reading itself or the corrected value",
            candidates=[ref, "corrected"],
        )
    else:
        value_state = FieldState("rules[].value", "evidence", cid, f"unit {num.unit} is a {ref} unit", ref)

    out = _outcome_state(text, outcomes, "rules[].outcome", cid)
    states = [value_state, op_state, *number_states, out]
    if any(st.status != "evidence" for st in states):
        return None, states
    # `atomic.assemble` takes decision rules as conditions + outcome; any other
    # shape raised KeyError('conditions') the first time a rule was complete.
    return {
        "conditions": [
            {"subject": ref, "op": op, "against": "number", "number": _frac(num.value), "unit": num.unit}
        ],
        "outcome": out.value,
    }, states


def _single_outcome_kind(
    clause: dict, outcomes: list[str], kind: str
) -> tuple[dict | None, list[FieldState]]:
    """`missing_input` and `default_outcome`: one outcome and nothing else."""
    path = "missing_input_outcome" if kind == "missing_input" else "default_outcome"
    state = _outcome_state(clause["text"], outcomes, path, clause["id"])
    if state.status != "evidence":
        return None, [state]
    return {"outcome": state.value}, [state]


def claim_units(clauses: dict) -> list[dict]:
    """Re-segment the cited clauses into claim-sized units.

    The two layers split text for different reasons and neither is wrong:

    - `ingest_documents` (A1) splits at `.;:!?` so a citation is a span a
      human can check against the page. That puts "Step 1 validity:" in one
      clause and the numbers in the next.
    - `atomic.segment` splits at sentence ends only, because the cues a claim
      needs — the word "validity", the word "between", the two numbers — are
      spread across a whole sentence.

    Feeding A1's fragments to the claim extractors loses every cue that
    crosses a colon, so the cited clauses are joined in document order and
    re-split the way the extractors expect. Each resulting unit records the
    clause ids it came from, so a claim is still traceable to the citations
    the expert chose.
    """
    ordered = sorted(clauses.values(), key=lambda c: (c["page"], c["index"]))
    joined, spans = "", []
    for c in ordered:
        if joined:
            joined += " "
        spans.append((len(joined), len(joined) + len(c["text"]), c["id"]))
        joined += c["text"]
    units = []
    seen: dict[str, int] = {}
    for seg in A.segment(joined):
        sources = [cid for (a, b, cid) in spans if a < seg.end and seg.start < b]
        base = "+".join(sources) or seg.cid
        # One A1 clause can yield several claim units: A1 does not split at a
        # line break, `atomic.segment` does. Those units share a source set,
        # so the id is made unique by order of appearance. Without this, two
        # units were both called `p1#0`, a lookup by id kept only the second,
        # and the first unit's question quoted the second unit's sentence.
        seen[base] = seen.get(base, 0) + 1
        uid = base if seen[base] == 1 else f"{base}/{seen[base]}"
        units.append({"id": uid, "text": seg.text, "sources": sources})
    return units


def determine(clause: dict, outcomes: list[str]) -> tuple[list[dict], list[FieldState]]:
    """Every claim the clause determines, and the state of every field touched.

    Returns ([] , states) when the clause determines no complete claim, which
    is the common case and not an error.
    """
    claims: list[dict] = []
    states: list[FieldState] = []
    kinds = A.plausible_kinds(clause["text"], outcomes)
    if not kinds:
        # Not a defect: titles, confidentiality notes and prose carry nothing
        # the IR can express. Recorded so the count of cited-but-unused
        # clauses is visible rather than silently zero.
        states.append(
            FieldState(
                "(none)",
                "issue",
                clause["id"],
                "the clause states nothing the IR can express",
            )
        )
        return claims, states

    for kind in kinds:
        if kind in DEFERRED_KINDS:
            states.append(
                FieldState(
                    f"{kind}.*",
                    "hypothesis",
                    clause["id"],
                    "the clause could state this, but filling it needs a choice "
                    "this module will not make",
                )
            )
            continue
        if kind == "validity":
            claim, st = _validity(clause, outcomes)
        elif kind == "decision_rule":
            claim, st = _decision_rule(clause, outcomes)
        elif kind in ("missing_input", "default_outcome"):
            claim, st = _single_outcome_kind(clause, outcomes, kind)
        else:  # pragma: no cover - DETERMINED_KINDS and the branches agree
            raise DraftError(f"no determiner for kind {kind}")
        states += st
        if claim is not None:
            claims.append({"kind": kind, "claim": claim, "clause": clause["id"]})
    return claims, states


def questions_from(
    states: list[FieldState], clauses: dict, ocr: set[str], units: list[dict]
) -> list[Question]:
    """One question per field the expert must settle, in claim-unit order."""
    by_id = {u["id"]: u for u in units}
    out = []
    for s in states:
        if s.status == "evidence":
            continue
        unit = by_id.get(s.clause, {})
        sources = unit.get("sources", [s.clause])
        out.append(
            Question(
                field_path=s.path,
                clause=s.clause,
                citation="; ".join(
                    clauses[cid]["citation"] for cid in sources if cid in clauses
                )
                or s.clause,
                clause_text=unit.get("text", ""),
                needs=s.basis,
                candidates=s.candidates,
                # OCR'd text may have misread a digit, so a value taken from
                # it is a hypothesis even where the clause looks decisive.
                ocr_warning=any(cid in ocr for cid in sources),
            )
        )
    return out


REQUIRED_IR_FIELDS = (
    "topic_terms",
    "inputs",
    "missing_input_outcome",
    "rules",
    "default_outcome",
)


def unfilled(ir: dict) -> list[str]:
    """Required IR fields the draft leaves empty."""
    return [f for f in REQUIRED_IR_FIELDS if not ir.get(f)]


def draft(session: dict, spec: dict) -> dict:
    """Draft an IR from a teach session. Pure: no IO, no model, no clock."""
    if session.get("schema") != SESSION_SCHEMA:
        raise DraftError(f"session schema {session.get('schema')!r}, expected {SESSION_SCHEMA!r}")
    if session.get("tenant") != spec.get("tenant"):
        raise DraftError(
            f"session tenant {session.get('tenant')!r} is not the task's tenant {spec.get('tenant')!r}"
        )
    outcomes = list(spec["outcomes"])

    clauses = {}
    for c in session["clauses"]:
        cid = f"p{c['page']}#{c['index']}"
        clauses[cid] = {
            "id": cid,
            "page": c["page"],
            "index": c["index"],
            "text": c["text"],
            "citation": f"{c['document']} p.{c['page']} [{c['char_start']}:{c['char_end']}]",
            "extraction": c["extraction"],
        }
    ocr = {cid for cid, c in clauses.items() if c["extraction"] == "pdf_ocr"}

    units = claim_units(clauses)
    claims: list[dict] = []
    states: list[FieldState] = []
    for u in units:
        cl, st = determine(u, outcomes)
        claims += cl
        states += st

    ir, simplifications, assemble_issues = A.assemble(claims)
    missing = unfilled(ir)

    compiles, compile_error = True, None
    try:
        compile_ir(ir, spec)
    except (IRError, KeyError, TypeError) as e:
        compiles, compile_error = False, str(e)

    # Provenance over the cited clause text only: a number the draft uses must
    # appear in a clause the expert actually cited, not merely somewhere in
    # the document.
    cited_text = "\n".join(c["text"] for c in clauses.values())
    unsupported = provenance_check(ir, cited_text) if compiles else []

    counts = {"evidence": 0, "hypothesis": 0, "issue": 0}
    for s in states:
        counts[s.status] += 1

    return {
        "schema": "syntriass.teach-draft/v1",
        "session_id": session["session_id"],
        "tenant": session["tenant"],
        "task": session["task"],
        "document": session["document"],
        "document_sha256": session["document_sha256"],
        "outcomes": outcomes,
        "expert_rule": session["rule"],
        "expert_rule_note": (
            "Recorded for the question generator to quote back. No field is "
            "filled from it: reading intent out of prose is the step that "
            "produced the wrong thresholds in YC_TECHNICAL_CLAIMS.md."
        ),
        "model_calls": 0,
        "clauses_cited": len(clauses),
        "clauses_ocr": sorted(ocr),
        "claims_determined": claims,
        "field_counts": counts,
        "fields": [asdict(s) for s in states],
        "ir": ir,
        "ir_unfilled_required": missing,
        "ir_compiles": compiles,
        "ir_compile_error": compile_error,
        "numbers_without_cited_provenance": unsupported,
        "assemble_issues": assemble_issues,
        "simplifications": simplifications,
        "claim_units": [{"id": u["id"], "sources": u["sources"], "text": u["text"]} for u in units],
        "questions": [asdict(q) for q in questions_from(states, clauses, ocr, units)],
        "examples_checked": None,
        "examples_note": (
            "NOT_MEASURED: the examples cannot be evaluated against an IR that "
            "does not compile. C1 scores them once the expert has answered the "
            "questions. This is not zero agreement."
        )
        if not compiles
        else "evaluable",
        "status": "DRAFT_COMPLETE" if compiles and not missing else "NEEDS_EXPERT_ANSWERS",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("session", type=Path, help="teach session JSON")
    ap.add_argument("--task", type=Path, required=True, help="task spec JSON")
    ap.add_argument("--out", type=Path, help="write the draft here instead of stdout")
    a = ap.parse_args(argv)
    try:
        session = json.loads(a.session.read_text())
        spec = json.loads(a.task.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"draft_from_session: {e}", file=sys.stderr)
        return 2
    try:
        d = draft(session, spec)
    except DraftError as e:
        print(f"draft_from_session: {e}", file=sys.stderr)
        return 3
    text = json.dumps(d, indent=2) + "\n"
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text)
        c = d["field_counts"]
        print(
            f"draft_from_session: {d['status']} -> {a.out}\n"
            f"  {d['clauses_cited']} clauses cited, {len(d['claims_determined'])} claim(s) determined\n"
            f"  fields: {c['evidence']} evidence, {c['hypothesis']} hypothesis, {c['issue']} issue\n"
            f"  {len(d['questions'])} question(s) for the expert; model calls: {d['model_calls']}"
        )
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
