#!/usr/bin/env python3
"""B2: expert answers -> typed leaf edits on the draft IR, each with who, when, why.

Input: an A3a draft, the task spec, and an answers file. The questions are
regenerated here from the draft by B1 (deterministic), never read from a
file, and the answers file must name the digest of exactly those questions
and of the draft they came from. An answer to a question the expert was not
shown cannot be applied, and neither can answers to a draft whose
document-determined values changed after the expert answered (those values
are not in the questions, so the questions digest alone would not notice).

Every answer is checked before anything is applied, and one bad answer
refuses the whole file (exit 3) with every problem listed against its
question. Checks, all fail-closed:

- envelope: known question, answered once, `who` an identifier in the
  runtime's teach grammar, `when_ms` a positive integer, a non-empty `why`,
  one author for the whole file;
- shape: the question's `answer_schema` — the compiler's own schema, lifted
  by B1 — checked strictly (`schema_subset`: no undeclared fields);
- provenance: every number the compiler would use from the answer must be
  stated in the sentence the question quotes (`ir_compiler.provenance_check`
  run on the answer alone), and every word list must be copied from it;
- no silent overwrite: an answer may not set a leaf the document already
  determined or another answer already set, and may not add an element that
  duplicates one already taught.

Then each answered leaf becomes one edit record (`path`, `type`, `before`,
`after`, `who`, `when_ms`, `why`, the question it answers). Leaves are the
scalars of the IR exactly as `correct_ir.leaves` counts them, so an edit
count here is comparable with the v0.2 figures.

An element of an array (a validity range, a rule, a scope limit) belongs to
the sentence it came from. It enters the IR only when every leaf is filled,
from the document or from answers, in document order; a partly filled one is
reported with its missing leaves, never emitted half-built. Answering "not
applicable" to a leaf of a rule withdraws that rule, and is refused if
another answer fills a leaf of it.

What this does not do: score the IR (C1), emit a capability, or reorder
rules. Rule order is the document's; whether that order is right is what the
examples and the suite test.

Usage:
    apply_answers.py DRAFT.json ANSWERS.json --task TASK.json [--out ANSWERED.json]

Exit codes: 0 answers applied (the IR may still be incomplete), 2 bad input,
3 answers refused (nothing applied).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import question_generator as Q  # noqa: E402
import schema_subset as S  # noqa: E402
from draft_from_session import unfilled  # noqa: E402
from ir_check import check_ir  # noqa: E402
from ir_compiler import ir_schema, provenance_check  # noqa: E402

ANSWERS_SCHEMA = "syntriass.teach-answers/v1"
SCHEMA = "syntriass.teach-answered/v1"
QUESTIONS_DOMAIN = b"syntriass-teach-questions/v1\n"
DRAFT_DOMAIN = b"syntriass-teach-draft/v1\n"

#: Same bound and character set as the runtime's teach identifiers
#: (`domain/teach.rs`: MAX_IDENT_CHARS, `[A-Za-z0-9._:-]`, no leading dot).
MAX_IDENT_CHARS = 64
_IDENT = re.compile(r"[A-Za-z0-9_:-][A-Za-z0-9._:-]*")
#: Long enough for a reason, short enough that a pasted document is refused.
MAX_WHY_CHARS = 1000
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

#: Array elements, keyed by the sentence they came from. Their leaves are
#: read off the compiler's schema so the two can never disagree.
ELEMENT_LEAVES = {
    name: tuple(ir_schema([])["properties"][name]["items"]["properties"])
    for name in ("validity", "rules", "out_of_scope_limits")
}

#: Question path -> (array, leaves the answer sets) for element leaves.
_RANGE = ("min", "max", "unit")
SLOT_PATHS = {
    "validity[].ref": ("validity", ("ref",)),
    "validity[].min/max": ("validity", _RANGE),
    "validity[].min": ("validity", _RANGE),
    "validity[].max": ("validity", _RANGE),
    "validity[].outcome": ("validity", ("outcome",)),
    "rules[].value": ("rules", ("value",)),
    "rules[].op": ("rules", ("op",)),
    "rules[].number": ("rules", ("against", "number", "unit", "limit_fraction")),
    "rules[].outcome": ("rules", ("outcome",)),
}
#: A whole element per sentence.
ELEMENT_PATHS = {"scope_limit.*": "out_of_scope_limits"}
#: Items appended to a top-level list; `words_from_quote` names the string
#: fields that must be copied from the quoted sentence.
LIST_PATHS = {"scope_subject.*": "topic_terms", "scope_exclusion_terms.*": "out_of_scope_terms",
              "required_inputs.*": "inputs"}
#: A whole top-level object, set at most once.
OBJECT_PATHS = {"correction.*": "correction", "limit.*": "limit"}
#: A top-level scalar.
SCALAR_PATHS = {"missing_input_outcome": "missing_input_outcome", "default_outcome": "default_outcome"}

ANSWERABLE_PATHS = frozenset(SLOT_PATHS) | set(ELEMENT_PATHS) | set(LIST_PATHS) | set(OBJECT_PATHS) | set(SCALAR_PATHS)

#: Answer paths whose numbers the compiler may use; checked for provenance.
_PROBE_AT = {
    "rules[].number": ("rules", "list"), "validity[].min/max": ("validity", "list"),
    "validity[].min": ("validity", "list"), "validity[].max": ("validity", "list"),
    "scope_limit.*": ("out_of_scope_limits", "list"), "correction.*": ("correction", "object"),
    "limit.*": ("limit", "object"),
}

_ENVELOPE_KEYS = {"qid", "answer", "not_applicable", "who", "when_ms", "why"}


class AnswersRefused(ValueError):
    """At least one answer failed a check; nothing was applied."""

    def __init__(self, errors: list[dict]):
        super().__init__(f"{len(errors)} problem(s) with the answers")
        self.errors = errors


class DraftInconsistent(ValueError):
    """The draft's IR does not follow from its own field states."""


def _digest(domain: bytes, doc: dict) -> str:
    body = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(domain + body.encode("utf-8")).hexdigest()


def questions_digest(questions: dict) -> str:
    """SHA-256 over the canonical questions document, domain separated.

    An answers file names this, so an answer is bound to the exact wording,
    choices and schema the expert was shown.
    """
    return _digest(QUESTIONS_DOMAIN, questions)


def draft_digest(draft: dict) -> str:
    """SHA-256 over the canonical draft, domain separated: binds answers to
    the evidence values the draft filled, which the questions do not carry."""
    return _digest(DRAFT_DOMAIN, draft)


# ── typed leaves ────────────────────────────────────────────────────────────

def typed_leaves(value: Any, schema: dict, path: str):
    """(path, value, type) for every scalar in `value`, walking `schema`.

    Paths and order match `correct_ir.leaves`, so counts are comparable. The
    type is `enum` where the schema closes the choice, else `number`/`string`.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            yield from typed_leaves(v, schema["properties"][k], f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from typed_leaves(v, schema["items"], f"{path}[{i}]")
    else:
        yield path, value, "enum" if "enum" in schema else schema["type"]


# ── slots: one array element per sentence ───────────────────────────────────

@dataclass
class Slot:
    """An array element as it is being filled, keyed by its sentence."""

    array: str
    unit: str
    order: int
    values: dict = field(default_factory=dict)
    source: dict = field(default_factory=dict)  # leaf -> "document" | qid
    withdrawn_by: str | None = None

    def missing(self) -> list[str]:
        return [k for k in ELEMENT_LEAVES[self.array] if k not in self.values]

    def element(self) -> dict:
        return {k: self.values[k] for k in ELEMENT_LEAVES[self.array]}


def _evidence_slots(draft: dict) -> dict[tuple[str, str], Slot]:
    """Slots for every sentence the draft touched, filled with its evidence."""
    order = {u["id"]: i for i, u in enumerate(draft["claim_units"])}
    slots: dict[tuple[str, str], Slot] = {}
    for f in draft["fields"]:
        array = f["path"].split("[]", 1)[0]
        if array not in ("validity", "rules") or not f["path"].startswith(f"{array}[]."):
            continue
        key = (array, f["clause"])
        slot = slots.setdefault(key, Slot(array, f["clause"], order[f["clause"]]))
        if f["status"] == "evidence":
            leaf = f["path"].split("].", 1)[1]
            slot.values[leaf] = f["value"]
            slot.source[leaf] = "document"
    return slots


def _arrays(slots: dict) -> dict[str, list[Slot]]:
    """Complete, non-withdrawn slots per array, in document order."""
    out: dict[str, list[Slot]] = {name: [] for name in ELEMENT_LEAVES}
    for s in sorted(slots.values(), key=lambda s: (s.order, s.array)):
        if s.withdrawn_by is None and not s.missing():
            out[s.array].append(s)
    return out


# ── checks on one answer ────────────────────────────────────────────────────

def _envelope_errors(a: Any) -> list[str]:
    if not isinstance(a, dict):
        return ["an answer must be an object"]
    errs = [f"unexpected field {k!r}" for k in sorted(set(a) - _ENVELOPE_KEYS)]
    who = a.get("who")
    if not isinstance(who, str) or not _IDENT.fullmatch(who) or len(who) > MAX_IDENT_CHARS:
        errs.append(f"who must be an identifier of 1-{MAX_IDENT_CHARS} characters [A-Za-z0-9._:-], "
                    f"not starting with a dot; got {who!r}")
    when = a.get("when_ms")
    if not isinstance(when, int) or isinstance(when, bool) or when <= 0:
        errs.append(f"when_ms must be a positive integer (milliseconds since the epoch); got {when!r}")
    why = a.get("why")
    if not isinstance(why, str) or not why.strip():
        errs.append("why must say why, in words")
    elif len(why) > MAX_WHY_CHARS:
        errs.append(f"why is {len(why)} characters; at most {MAX_WHY_CHARS}")
    elif _CONTROL.search(why):
        errs.append("why contains control characters")
    has_answer, na = "answer" in a, a.get("not_applicable")
    if na not in (None, True):
        errs.append("not_applicable, if given, must be true")
    if has_answer == (na is True):
        errs.append("give exactly one of answer or not_applicable")
    return errs


def _in_quote(word: str, quote: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(word)}(?!\w)", quote, re.IGNORECASE) is not None


def _copied_words(path: str, answer: Any, quote: str) -> list[str]:
    """Word lists must be copied from the quoted sentence (B1 says so)."""
    if path == "required_inputs.*":
        words = [c for item in answer for c in item["cues"]]
        what = "short name"
    else:
        words, what = list(answer), "term"
    errs = []
    for w in words:
        if not w.strip():
            errs.append(f"an empty {what} teaches nothing")
        elif not _in_quote(w, quote):
            errs.append(f"{what} {w!r} is not written in the quoted sentence")
    return errs


def _provenance(path: str, answer: Any, quote: str) -> list[str]:
    """Numbers the compiler would use from this answer, absent from the quote."""
    if path not in _PROBE_AT:
        return []
    where, how = _PROBE_AT[path]
    probe = {"out_of_scope_limits": [], "validity": [], "rules": [],
             "correction": {"template": "none"}, "limit": {"template": "none"}}
    probe[where] = [answer] if how == "list" else answer
    return [f"{b['value']!r} (as {b['field'].split('.', 1)[-1]}) is not stated in the quoted sentence"
            for b in provenance_check(probe, quote)]


# ── apply ───────────────────────────────────────────────────────────────────

def _check_file(answers_doc: Any, draft: dict, digest: str) -> None:
    if not isinstance(answers_doc, dict):
        raise ValueError("answers file must be a JSON object")
    extra = set(answers_doc) - {"schema", "session_id", "draft_sha256", "questions_sha256", "answers"}
    if extra:
        raise ValueError(f"answers file has unexpected field(s) {sorted(extra)}")
    if answers_doc.get("schema") != ANSWERS_SCHEMA:
        raise ValueError(f"answers schema {answers_doc.get('schema')!r}, expected {ANSWERS_SCHEMA!r}")
    if answers_doc.get("session_id") != draft["session_id"]:
        raise ValueError("the answers are for a different teach session")
    if answers_doc.get("draft_sha256") != draft_digest(draft):
        raise ValueError("the answers were given to a different draft "
                         f"(draft_sha256 {answers_doc.get('draft_sha256')!r}, expected {draft_digest(draft)})")
    if answers_doc.get("questions_sha256") != digest:
        raise ValueError("the answers were given to different questions than this draft produces "
                         f"(questions_sha256 {answers_doc.get('questions_sha256')!r}, expected {digest})")
    if not isinstance(answers_doc.get("answers"), list):
        raise ValueError("answers must be a list")


def apply(draft: dict, spec: dict, answers_doc: dict) -> dict:
    """Apply an answers file to a draft. Pure: no IO, no clock, no model.

    Raises ValueError for unusable input, DraftInconsistent if the draft's IR
    does not follow from its own fields, AnswersRefused if any answer fails a
    check (then nothing is applied).
    """
    questions = Q.generate(draft, spec)
    digest = questions_digest(questions)
    _check_file(answers_doc, draft, digest)
    by_qid = {q["qid"]: q for q in questions["questions"]}
    for q in questions["questions"]:
        if q["field_path"] not in ANSWERABLE_PATHS:
            raise ValueError(f"no answer mapping for question path {q['field_path']!r}")

    ir = copy.deepcopy(draft["ir"])
    slots = _evidence_slots(draft)
    arrays = _arrays(slots)
    for name in ("validity", "rules"):
        if [s.element() for s in arrays[name]] != draft["ir"][name]:
            raise DraftInconsistent(f"draft ir.{name} does not follow from the draft's evidence fields")

    # Envelope errors first, by position, so a malformed entry is reported
    # even when its qid is unusable.
    errors: list[dict] = []
    seen: dict[str, int] = {}
    good: list[tuple[dict, dict]] = []
    for i, a in enumerate(answers_doc["answers"]):
        qid = a.get("qid") if isinstance(a, dict) else None
        q = by_qid.get(qid)
        errs = _envelope_errors(a)
        if q is None:
            errs.append(f"no question {qid!r} was asked")
        elif qid in seen:
            errs.append(f"question {q['n']} is answered twice (entries {seen[qid] + 1} and {i + 1})")
        else:
            seen[qid] = i
        if errs:
            errors += [{"entry": i + 1, "qid": qid, "question": q and q["n"], "error": e} for e in errs]
        else:
            good.append((q, a))
    authors = sorted({a["who"] for _, a in good})
    if len(authors) > 1:
        errors.append({"entry": None, "qid": None, "question": None,
                       "error": f"one answers file has one author; found {authors}"})

    # Apply in question order, so the IR does not depend on the order the
    # answers were written in. The log keeps each answer's own `when_ms`.
    good.sort(key=lambda qa: qa[0]["n"])
    edits: list[dict] = []
    declined: list[dict] = []
    objects_set: dict[str, int] = {}

    def fail(q: dict, msg: str) -> None:
        errors.append({"entry": seen[q["qid"]] + 1, "qid": q["qid"], "question": q["n"], "error": msg})

    def record(q, a, address, value, schema, before):
        for path, v, kind in typed_leaves(value, schema, address):
            edits.append({"question": q["n"], "qid": q["qid"], "address": path, "path": None,
                          "type": kind, "before": before(path), "after": v,
                          "who": a["who"], "when_ms": a["when_ms"], "why": a["why"]})

    for q, a in good:
        path, quote = q["field_path"], q["quote"]
        if a.get("not_applicable"):
            declined.append({"question": q["n"], "qid": q["qid"], "who": a["who"],
                             "when_ms": a["when_ms"], "why": a["why"]})
            if path in SLOT_PATHS:
                slot = slots.setdefault((SLOT_PATHS[path][0], q["clause"]),
                                        Slot(SLOT_PATHS[path][0], q["clause"], _unit_order(draft, q)))
                slot.withdrawn_by = slot.withdrawn_by or q["qid"]
            continue
        answer = a["answer"]
        shape = S.validate(answer, q["answer_schema"])
        if shape:
            for e in shape:
                fail(q, e)
            continue
        problems = _provenance(path, answer, quote)
        if path in LIST_PATHS:
            problems += _copied_words(path, answer, quote)
        if problems:
            for e in problems:
                fail(q, e)
            continue

        if path in SLOT_PATHS:
            array, leaf_names = SLOT_PATHS[path]
            slot = slots.setdefault((array, q["clause"]), Slot(array, q["clause"], _unit_order(draft, q)))
            given = {k: answer[k] for k in leaf_names} if isinstance(answer, dict) else {leaf_names[0]: answer}
            taken = [k for k in given if k in slot.values]
            if taken:
                fail(q, f"{', '.join(taken)} of this {array[:-1] if array == 'rules' else 'range'} "
                        f"is already set ({', '.join(str(slot.source[k]) for k in taken)})")
                continue
            for k, v in given.items():
                slot.values[k], slot.source[k] = v, q["qid"]
            item = ir_schema(list(spec["outcomes"]))["properties"][array]["items"]
            record(q, a, f"{array}[@{q['clause']}]", given, item, lambda p: None)
        elif path in ELEMENT_PATHS:
            array = ELEMENT_PATHS[path]
            slot = slots.setdefault((array, q["clause"]), Slot(array, q["clause"], _unit_order(draft, q)))
            for k, v in answer.items():
                slot.values[k], slot.source[k] = v, q["qid"]
            record(q, a, f"{array}[@{q['clause']}]", answer, q["answer_schema"], lambda p: None)
        elif path in LIST_PATHS:
            name = LIST_PATHS[path]
            have = ir[name]
            dup = [x for x in answer if x in have] + [x for i, x in enumerate(answer) if x in answer[:i]]
            if name == "inputs":
                refs = [i["ref"] for i in have] + [i["ref"] for i in answer]
                dup += sorted({r for r in refs if refs.count(r) > 1})
            if dup:
                fail(q, f"already taught: {dup}")
                continue
            base = len(have)
            have.extend(copy.deepcopy(answer))
            item = ir_schema(list(spec["outcomes"]))["properties"][name]["items"]
            for j, x in enumerate(answer):
                record(q, a, f"{name}[{base + j}]", x, item, lambda p: None)
        elif path in OBJECT_PATHS:
            name = OBJECT_PATHS[path]
            if name in objects_set:
                fail(q, f"the {name} is already set by question {objects_set[name]}")
                continue
            objects_set[name] = q["n"]
            old = dict((p, v) for p, v, _ in typed_leaves(ir[name], q["answer_schema"], name))
            ir[name] = copy.deepcopy(answer)
            record(q, a, name, answer, q["answer_schema"], lambda p, old=old: old.get(p))
        else:  # SCALAR_PATHS
            name = SCALAR_PATHS[path]
            before = ir[name]
            ir[name] = answer
            record(q, a, name, answer, q["answer_schema"], lambda p, b=before: b)

    for s in slots.values():
        answered = [k for k, src in s.source.items() if src != "document"]
        if s.withdrawn_by and answered:
            q = by_qid[s.withdrawn_by]
            fail(q, f"says the sentence teaches no {s.array} entry, but {', '.join(answered)} "
                    f"of it {'is' if len(answered) == 1 else 'are'} answered elsewhere")
    arrays = _arrays(slots)
    seen_elements: dict[str, list[dict]] = {}
    for name, ss in arrays.items():
        for s in ss:
            el = s.element()
            answered_by = [v for v in s.source.values() if v != "document"]
            # A duplicate the document itself states is the draft's, already
            # in its IR; only a duplicate an answer creates is refused here.
            if el in seen_elements.setdefault(name, []) and answered_by:
                fail(by_qid[answered_by[0]], f"duplicates an {name} entry already taught: {el}")
            seen_elements[name].append(el)

    if errors:
        raise AnswersRefused(errors)

    return _result(draft, spec, questions, digest, ir, slots, edits, declined, authors, seen)


def _unit_order(draft: dict, q: dict) -> int:
    return [u["id"] for u in draft["claim_units"]].index(q["clause"])


def _result(draft, spec, questions, digest, ir, slots, edits, declined, authors, seen) -> dict:
    arrays = _arrays(slots)
    index = {}
    for name, ss in arrays.items():
        ir[name] = [s.element() for s in ss]
        for k, s in enumerate(ss):
            index[f"{name}[@{s.unit}]"] = f"{name}[{k}]"
    for e in edits:
        head, _, rest = e["address"].partition("]")
        resolved = index.get(head + "]") if "[@" in head else None
        e["path"] = (resolved + rest) if resolved else (None if "[@" in head else e["address"])

    elements = []
    for s in sorted(slots.values(), key=lambda s: (s.order, s.array)):
        status = "withdrawn" if s.withdrawn_by else ("incomplete" if s.missing() else "complete")
        elements.append({
            "array": s.array, "sentence": s.unit, "status": status,
            "path": index.get(f"{s.array}[@{s.unit}]"),
            "from_document": sorted(k for k, v in s.source.items() if v == "document"),
            "from_answers": sorted(k for k, v in s.source.items() if v != "document"),
            "missing": s.missing() if status == "incomplete" else [],
        })
    document_leaves = sum(len(e["from_document"]) for e in elements if e["status"] == "complete") + sum(
        1 for f in draft["fields"] if f["status"] == "evidence" and f["path"] in SCALAR_PATHS)

    asked = questions["questions"]
    unanswered = [{"question": q["n"], "qid": q["qid"], "field_path": q["field_path"], "quote": q["quote"]}
                  for q in asked if q["qid"] not in seen]
    checked = check_ir(ir, spec)
    cited = "\n".join(u["text"] for u in draft["claim_units"])
    unsupported = provenance_check(ir, cited) if checked["compiles"] else []
    ok = checked["compiles"] and not unsupported
    status = "COMPILES" if ok else ("NEEDS_MORE_ANSWERS" if unanswered else "ANSWERED_BUT_DOES_NOT_COMPILE")
    changed = [e for e in edits if e["before"] != e["after"]]
    return {
        "schema": SCHEMA,
        "session_id": draft["session_id"],
        "tenant": draft["tenant"],
        "task": draft["task"],
        "draft_sha256": draft_digest(draft),
        "questions_sha256": digest,
        "author": authors[0] if authors else None,
        "model_calls": 0,
        "ir": ir,
        "edits": edits,
        "not_applicable": declined,
        "unanswered": unanswered,
        "elements": elements,
        "counts": {
            "questions": len(asked),
            "answered": len(seen) - len(declined),
            "not_applicable": len(declined),
            "unanswered": len(unanswered),
            "leaves_set_by_answers": len(edits),
            "leaf_edits": len(changed),
            "leaves_from_document": document_leaves,
            "elements_complete": sum(e["status"] == "complete" for e in elements),
            "elements_incomplete": sum(e["status"] == "incomplete" for e in elements),
            "elements_withdrawn": sum(e["status"] == "withdrawn" for e in elements),
        },
        "ir_unfilled_required": unfilled(ir),
        "ir_schema_errors": checked["schema_errors"],
        "ir_compiles": checked["compiles"],
        "ir_compile_error": checked["compile_error"],
        "numbers_without_cited_provenance": unsupported,
        "scored": None,
        "scored_note": "NOT_MEASURED here: C1 scores the IR against the examples and the suite.",
        "status": status,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", type=Path)
    ap.add_argument("answers", type=Path)
    ap.add_argument("--task", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        draft = json.loads(a.draft.read_text())
        answers = json.loads(a.answers.read_text())
        spec = json.loads(a.task.read_text())
        out = apply(draft, spec, answers)
    except AnswersRefused as e:
        print(f"apply_answers: refused, nothing applied — {e}", file=sys.stderr)
        for x in e.errors:
            where = (f"question {x['question']}" if x["question"]
                     else f"entry {x['entry']}" if x["entry"] else "answers file")
            print(f"  {where}: {x['error']}", file=sys.stderr)
        return 3
    except (OSError, ValueError, KeyError) as e:
        print(f"apply_answers: {e}", file=sys.stderr)
        return 2
    text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text)
        c = out["counts"]
        print(f"apply_answers: {out['status']} -> {a.out}\n"
              f"  answered {c['answered']} of {c['questions']} questions "
              f"({c['not_applicable']} not applicable, {c['unanswered']} unanswered)\n"
              f"  {c['leaf_edits']} leaf edit(s) by the expert, {c['leaves_from_document']} leaves from the document\n"
              f"  elements: {c['elements_complete']} complete, {c['elements_incomplete']} incomplete, "
              f"{c['elements_withdrawn']} withdrawn; model calls {out['model_calls']}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
