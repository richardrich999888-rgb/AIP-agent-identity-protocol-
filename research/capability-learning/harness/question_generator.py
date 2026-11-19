#!/usr/bin/env python3
"""B1: plain-language questions for the expert, from an A3a draft.

Every field the deterministic draft could not settle (`hypothesis` or
`issue`) becomes exactly one question a domain expert can answer without
knowing what an IR is. Deterministic templates only: no model, no
rephrasing, no ranking of alternatives.

Three rules make the questions safe to act on:

1. **The answer's shape comes from the compiler.** Each question carries an
   `answer_schema` lifted from `ir_compiler.ir_schema(outcomes)`, the schema
   the compiler itself enforces. B2 validates an answer against it, so an
   answer that cannot compile is refused at the question, not discovered at
   compile time. Typed fields retain the compiler's answer vocabulary.
2. **Choices are closed wherever the system can close them.** Outcome fields
   offer the task's outcome vocabulary even when the clause names none, which
   turns "what happens outside the range?" into a choice rather than free
   text. Choices come from the draft, task, compiler, or the explicitly versioned
   exclusion word-form policy. Those word forms name their quoted source and
   cannot be used as topic terms or input cues.
3. **Unknown field paths fail closed.** A path with no template raises rather
   than receiving a generic question: a question that does not say what it is
   asking cannot be answered correctly, and a silent fallback would hide a new
   kind of gap.

Model rephrasing is deferred and marked [B]: no weights are available, and
YC_TECHNICAL_CLAIMS.md records that the local model's drafts all failed. A
rephrasing step, if added, may change wording only, never a choice.

Usage:
    question_generator.py DRAFT.json --task TASK.json [--out QUESTIONS.json]

Exit codes: 0 questions produced, 2 bad input, 3 a field has no template.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ir_compiler import INPUT_REFS, OPS, VALUE_REFS, ir_schema  # noqa: E402
import exclusion_terms as E  # noqa: E402

DRAFT_SCHEMA = "syntriass.teach-draft/v1"
SCHEMA = "syntriass.teach-questions/v1"

#: How comparison operators read aloud. Covers every operator the IR has.
OP_WORDS = {"<": "below", "<=": "at most", ">": "above", ">=": "at least"}
assert set(OP_WORDS) == set(OPS), "every IR operator needs words"

#: How value references read aloud. Deliberately generic: the words for a
#: reading come from the document, and inventing a domain name here ("rated
#: voltage") would put words in the procedure's mouth.
REF_WORDS = {
    "voltage": "the voltage reading",
    "resistance": "the resistance reading",
    "temperature": "the temperature reading",
    "cued_1": "the first named reading (for example an index written as an abbreviation)",
    "cued_2": "the second named reading",
    "corrected": "the corrected value worked out in an earlier step",
}
assert set(REF_WORDS) == set(VALUE_REFS), "every IR reference needs words"

OCR_NOTE = (
    "This text was read from a scanned page by OCR, which can misread digits. "
    "Please check any number against the original page before answering."
)


class TemplateError(ValueError):
    """A draft field has no question template. Raised, never papered over."""


def label(code: str) -> str:
    """Render an outcome code for a person: `RETEST_30D` -> `retest 30d`.

    Only case and underscores change. No meaning is added: what an outcome
    means is the procedure's business, and the code travels with the label so
    an answer maps back exactly.
    """
    return code.replace("_", " ").lower()


def _choices(codes, words=None) -> list[dict]:
    return [{"code": c, "label": (words or {}).get(c, label(c))} for c in codes]


def _quote(q: dict) -> str:
    return f'"{q["clause_text"]}" ({q["citation"]})'


def _sub(schema: dict, *path: str) -> dict:
    """A deep copy of one property of the compiler's schema."""
    node = schema
    for key in path:
        node = node[key]
    return copy.deepcopy(node)


# Each template: (question text, answer_schema, choices, answer_note).
# The text is built from the quoted clause; nothing else is interpolated.

def _outcome(q, schema, outcomes, what):
    return (
        f"The procedure says {_quote(q)}. {what} Choose one.",
        {"enum": list(outcomes)},
        _choices(outcomes),
        "one outcome code from the choices",
    )


def template(q: dict, schema: dict, outcomes: list[str]) -> tuple[str, dict, list, str]:
    """The question for one unsettled draft field."""
    path = q["field_path"]

    if path == "validity[].outcome":
        return _outcome(q, schema, outcomes,
                        "When a reading falls outside that range, what is the result?")
    if path == "rules[].outcome":
        return _outcome(q, schema, outcomes, "When that condition holds, what is the result?")
    if path == "missing_input_outcome":
        return _outcome(q, schema, outcomes, "When a required reading is missing, what is the result?")
    if path == "default_outcome":
        return _outcome(q, schema, outcomes, "When none of the rules applies, what is the result?")

    if path == "rules[].op":
        ops = [o for o in q["candidates"] if o in OP_WORDS] or list(OPS)
        return (
            f"The procedure says {_quote(q)}. That sentence combines more than one "
            "condition, and each rule can check only one. Which comparison should "
            "this rule check? The other can be taught as a separate rule.",
            {"enum": ops},
            _choices(ops, OP_WORDS),
            "one comparison from the choices",
        )

    if path == "rules[].number":
        rule = _sub(schema, "properties", "rules", "items")
        answer = {
            "type": "object",
            "properties": {k: rule["properties"][k] for k in ("against", "number", "unit", "limit_fraction")},
            "required": ["against", "number", "unit", "limit_fraction"],
        }
        cands = q["candidates"]
        listed = ""
        if cands:
            listed = " The numbers in the sentence are: " + ", ".join(
                f'{c["value"]:g} {c["unit"]}' for c in cands) + "."
        return (
            f"The procedure says {_quote(q)}. What is the reading compared with? "
            "Give a number and its unit, or say it is compared with the limit "
            "worked out in an earlier step (and what fraction of that limit, if "
            f"not the whole of it).{listed}",
            answer,
            [],
            "against = number (give number and unit) or limit (give limit_fraction, 1 for the whole limit)",
        )

    if path in ("rules[].value", "validity[].ref"):
        refs = list(VALUE_REFS) if path == "rules[].value" else list(INPUT_REFS)
        return (
            f"The procedure says {_quote(q)}. Which reading is this about?",
            {"enum": refs},
            _choices(refs, REF_WORDS),
            "one reading from the choices",
        )

    if path in ("validity[].min/max", "validity[].min", "validity[].max"):
        item = _sub(schema, "properties", "validity", "items")
        answer = {
            "type": "object",
            "properties": {k: item["properties"][k] for k in ("min", "max", "unit")},
            "required": ["min", "max", "unit"],
        }
        return (
            f"The procedure says {_quote(q)}. What range must the reading lie in "
            "for the test to count? Give the lowest and highest values and their unit.",
            answer, [], "min, max and unit",
        )

    if path == "scope_subject.*":
        answer = _sub(schema, "properties", "topic_terms")
        bound = answer["items"]["maxLength"]
        return (
            f"The procedure says {_quote(q)}. What equipment does the procedure "
            "cover? Copy the words exactly as they are written in that sentence. "
            f"Each term may contain at most {bound} characters; use a shorter quoted phrase if needed.",
            answer, [],
            "words copied from the sentence; anything not in it is refused",
        )
    if path == "scope_exclusion_terms.*":
        answer = _sub(schema, "properties", "out_of_scope_terms")
        bound = answer["items"]["maxLength"]
        variants = E.offered(q["clause_text"])
        note = ""
        if variants:
            note = " You may also explicitly add these word forms: " + "; ".join(
                f"{v['term']!r} from {v['source_term']!r}" for v in variants) + "."
            note += " Keep each paired quoted term in the same answer. No variant is added automatically."
        return (
            f"The procedure says {_quote(q)}. What equipment does the procedure "
            "NOT cover? Copy each item exactly as it is written in that sentence. "
            f"Each term may contain at most {bound} characters.{note}",
            answer, [],
            "quoted terms, optionally with the offered exclusion word forms and their quoted terms; "
            "unlisted forms and synonyms are refused; runtime matching remains literal and whole-word",
        )
    if path == "scope_limit.*":
        return (
            f"The procedure says {_quote(q)}. Does this set a measured limit on "
            "what the procedure covers? If so: which reading, which comparison, "
            "what value and unit — and does meeting it put a request outside the "
            "procedure, or inside it?",
            _sub(schema, "properties", "out_of_scope_limits", "items"), [],
            "a limit stated as the request being OUT of scope when the comparison holds",
        )
    if path == "required_inputs.*":
        return (
            f"The procedure says {_quote(q)}. Which readings does the procedure "
            "need? For each, give its unit as written and any short name it is "
            "known by in the text (for example an abbreviation in brackets).",
            _sub(schema, "properties", "inputs"), [],
            "one entry per reading: which reading, unit, short names",
        )
    if path == "correction.*":
        return (
            f"The procedure says {_quote(q)}. How is the reading corrected? Say "
            "which reading is corrected, by which other reading, to what reference "
            "value, and with what rate or factor — using only the numbers in the sentence.",
            _sub(schema, "properties", "correction"), [],
            "a correction formula built from the sentence's own numbers",
        )
    if path == "limit.*":
        return (
            f"The procedure says {_quote(q)}. How is the acceptance limit worked "
            "out? Say whether it is a fixed number or a multiple of a reading plus "
            "an offset, using only the numbers in the sentence.",
            _sub(schema, "properties", "limit"), [],
            "a limit formula built from the sentence's own numbers",
        )

    raise TemplateError(f"no question template for draft field {path!r}")


def generate(draft: dict, spec: dict) -> dict:
    """Questions for every unsettled field in a draft. Pure."""
    if draft.get("schema") != DRAFT_SCHEMA:
        raise ValueError(f"draft schema {draft.get('schema')!r}, expected {DRAFT_SCHEMA!r}")
    outcomes = list(spec["outcomes"])
    if outcomes != list(draft["outcomes"]):
        raise ValueError("the draft was made against a different outcome vocabulary")
    schema = ir_schema(outcomes)

    asked, not_asked = [], []
    for n, q in enumerate(draft["questions"], start=1):
        if q["field_path"] == "(none)":
            # Not a question an expert can answer — titles, confidentiality
            # notes, prose. Listed, not dropped, so the count stays visible.
            not_asked.append({"clause": q["clause"], "citation": q["citation"],
                              "text": q["clause_text"],
                              "why": "the sentence states nothing the system can use"})
            continue
        text, answer_schema, choices, answer_note = template(q, schema, outcomes)
        if q.get("ocr_warning"):
            text = f"{text} {OCR_NOTE}"
        asked.append({
            "qid": f'{q["clause"]}:{q["field_path"]}',
            "n": len(asked) + 1,
            "field_path": q["field_path"],
            "clause": q["clause"],
            "citation": q["citation"],
            "quote": q["clause_text"],
            "question": text,
            "choices": choices,
            "answer_schema": answer_schema,
            "answer_note": answer_note,
            "ocr_warning": bool(q.get("ocr_warning")),
            "draft_basis": q["needs"],
        })
        if q["field_path"] == "scope_exclusion_terms.*":
            asked[-1]["exclusion_word_form_policy"] = E.POLICY
            asked[-1]["exclusion_word_forms"] = E.offered(q["clause_text"])

    return {
        "schema": SCHEMA,
        "session_id": draft["session_id"],
        "tenant": draft["tenant"],
        "task": draft["task"],
        "outcomes": outcomes,
        "model_calls": 0,
        "questions": asked,
        "not_asked": not_asked,
        "counts": {
            "draft_unsettled_fields": len(draft["questions"]),
            "asked": len(asked),
            "not_asked": len(not_asked),
            "with_closed_choices": sum(1 for a in asked if a["choices"]),
            "with_ocr_warning": sum(1 for a in asked if a["ocr_warning"]),
        },
        "rephrasing": "[B] deferred: deterministic templates only, no model",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", type=Path)
    ap.add_argument("--task", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        draft = json.loads(a.draft.read_text())
        spec = json.loads(a.task.read_text())
        out = generate(draft, spec)
    except TemplateError as e:
        print(f"question_generator: {e}", file=sys.stderr)
        return 3
    except (OSError, ValueError, KeyError) as e:
        print(f"question_generator: {e}", file=sys.stderr)
        return 2
    text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text)
        c = out["counts"]
        print(f"question_generator: {c['asked']} asked, {c['not_asked']} not asked "
              f"({c['with_closed_choices']} with closed choices) -> {a.out}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
