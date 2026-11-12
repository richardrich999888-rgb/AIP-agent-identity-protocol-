#!/usr/bin/env python3
"""Tests for the plain-language question generator (B1).

The contract: every field A3a could not settle becomes exactly one question a
domain expert can answer; the answer's shape is the compiler's own schema; a
choice comes from the draft, task, compiler or bounded exclusion policy;
and a field with no template is refused rather than given a
generic question.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "research/capability-learning/harness"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import draft_from_session as D  # noqa: E402
import question_generator as Q  # noqa: E402
from ir_compiler import INPUT_REFS, OPS, VALUE_REFS, ir_schema  # noqa: E402
from test_draft_from_session import SPEC, clause, ingested_corpus_clauses, session  # noqa: E402

OUTCOMES = SPEC["outcomes"]

#: Every field path A3a can emit for an unsettled field. Kept explicit so a
#: new path in A3a fails here until it has a template.
UNSETTLED_PATHS = [
    "validity[].min/max", "validity[].ref", "validity[].outcome",
    "rules[].op", "rules[].number", "rules[].value", "rules[].outcome",
    "missing_input_outcome", "default_outcome",
] + [f"{k}.*" for k in D.DEFERRED_KINDS]


@pytest.fixture(scope="module")
def corpus():
    draft = D.draft(session(ingested_corpus_clauses()), SPEC)
    return draft, Q.generate(draft, SPEC)


def fake_question(path, candidates=(), ocr=False):
    return {"field_path": path, "clause": "p1#9", "citation": "doc p.1 [0:10]",
            "clause_text": "Some sentence.", "needs": "why", "candidates": list(candidates),
            "ocr_warning": ocr}


def fake_draft(questions):
    return {"schema": Q.DRAFT_SCHEMA, "session_id": "s" * 64, "tenant": "koravi-process",
            "task": "t", "outcomes": OUTCOMES, "questions": questions}


# ── coverage ────────────────────────────────────────────────────────────────

def test_every_unsettled_field_is_asked_or_listed_never_dropped(corpus):
    draft, out = corpus
    c = out["counts"]
    assert c["asked"] + c["not_asked"] == c["draft_unsettled_fields"] == len(draft["questions"])


def test_one_question_per_askable_field(corpus):
    draft, out = corpus
    askable = [q for q in draft["questions"] if q["field_path"] != "(none)"]
    assert len(out["questions"]) == len(askable)
    assert [a["field_path"] for a in out["questions"]] == [q["field_path"] for q in askable]


def test_the_real_corpus_numbers(corpus):
    _, out = corpus
    # 21 and 17, not 16 and 12: A3a now classifies every leaf of a rule, so
    # each of the four rules is asked which reading it compares.
    assert out["counts"] == {"draft_unsettled_fields": 21, "asked": 17, "not_asked": 4,
                             "with_closed_choices": 6, "with_ocr_warning": 0}


def test_sentences_that_state_nothing_are_listed_with_a_reason(corpus):
    _, out = corpus
    texts = [n["text"] for n in out["not_asked"]]
    assert "Confidential." in texts
    assert all(n["why"] for n in out["not_asked"])


@pytest.mark.parametrize("path", UNSETTLED_PATHS)
def test_every_path_a3a_can_emit_has_a_template(path):
    out = Q.generate(fake_draft([fake_question(path, ["<"] if path == "rules[].op" else [])]), SPEC)
    assert len(out["questions"]) == 1
    assert out["questions"][0]["question"]


def test_an_unknown_field_is_refused_not_given_a_generic_question():
    with pytest.raises(Q.TemplateError, match="no question template"):
        Q.generate(fake_draft([fake_question("something_new.*")]), SPEC)


# ── answers are shaped by the compiler, not by this module ──────────────────

@pytest.mark.parametrize("path,node", [
    ("scope_subject.*", ("topic_terms",)),
    ("scope_exclusion_terms.*", ("out_of_scope_terms",)),
    ("scope_limit.*", ("out_of_scope_limits", "items")),
    ("required_inputs.*", ("inputs",)),
    ("correction.*", ("correction",)),
    ("limit.*", ("limit",)),
])
def test_deferred_answers_use_the_compilers_own_schema(path, node):
    want = ir_schema(OUTCOMES)["properties"]
    for key in node:
        want = want[key]
    got = Q.generate(fake_draft([fake_question(path)]), SPEC)["questions"][0]["answer_schema"]
    assert got == want


def test_rule_number_answers_are_a_subset_of_the_compilers_rule_schema():
    rule = ir_schema(OUTCOMES)["properties"]["rules"]["items"]["properties"]
    got = Q.generate(fake_draft([fake_question("rules[].number")]), SPEC)["questions"][0]["answer_schema"]
    assert set(got["properties"]) <= set(rule)
    for k, v in got["properties"].items():
        assert v == rule[k]


# ── no invented choices ─────────────────────────────────────────────────────

def test_outcome_questions_offer_exactly_the_tasks_outcomes(corpus):
    _, out = corpus
    q = next(a for a in out["questions"] if a["field_path"] == "validity[].outcome")
    assert [c["code"] for c in q["choices"]] == OUTCOMES
    assert q["answer_schema"] == {"enum": OUTCOMES}
    assert {"code": "INVALID_TEST", "label": "invalid test"} in q["choices"]


def test_a_combined_condition_offers_only_its_own_comparisons(corpus):
    _, out = corpus
    q = next(a for a in out["questions"] if a["field_path"] == "rules[].op")
    assert [c["code"] for c in q["choices"]] == [">=", "<"]
    assert [c["label"] for c in q["choices"]] == ["at least", "below"]


def test_no_choice_is_outside_the_draft_task_or_compiler_vocabulary(corpus):
    draft, out = corpus
    allowed = set(OUTCOMES) | set(OPS) | set(VALUE_REFS) | set(INPUT_REFS)
    for q in draft["questions"]:
        allowed |= {c if isinstance(c, str) else json.dumps(c) for c in q["candidates"]}
    for a in out["questions"]:
        for c in a["choices"]:
            assert c["code"] in allowed, f"{a['qid']} invented {c['code']!r}"


def test_labels_change_only_case_and_underscores():
    for code in OUTCOMES:
        assert Q.label(code).replace(" ", "_").upper() == code


def test_every_ir_operator_and_reference_has_words():
    assert set(Q.OP_WORDS) == set(OPS)
    assert set(Q.REF_WORDS) == set(VALUE_REFS)


# ── plain language ──────────────────────────────────────────────────────────

def test_every_question_quotes_its_sentence_and_citation(corpus):
    _, out = corpus
    for a in out["questions"]:
        assert a["quote"] in a["question"]
        assert a["citation"] in a["question"]


@pytest.mark.parametrize("jargon", ["[]", ".*", " IR ", "hypothesis", "issue", "evidence", "schema"])
def test_questions_carry_no_internal_jargon(corpus, jargon):
    _, out = corpus
    for a in out["questions"]:
        assert jargon not in a["question"], f"{a['qid']}: {jargon!r}"


def test_an_ocr_sentence_carries_the_warning_and_others_do_not():
    out = Q.generate(fake_draft([fake_question("default_outcome", ocr=True),
                                 fake_question("missing_input_outcome", ocr=False)]), SPEC)
    a, b = out["questions"]
    assert Q.OCR_NOTE in a["question"] and a["ocr_warning"]
    assert Q.OCR_NOTE not in b["question"] and not b["ocr_warning"]
    assert out["counts"]["with_ocr_warning"] == 1


def test_an_ocr_clause_flows_through_from_the_draft():
    c = clause(1, 0, "Step 1 validity: the temperature must be between 10 and 75 degrees Celsius inclusive.",
               extraction="pdf_ocr")
    out = Q.generate(D.draft(session([c]), SPEC), SPEC)
    assert out["questions"] and all(a["ocr_warning"] for a in out["questions"])


# ── identity and refusals ───────────────────────────────────────────────────

def test_question_ids_are_unique(corpus):
    _, out = corpus
    ids = [a["qid"] for a in out["questions"]]
    assert len(ids) == len(set(ids))


def test_generation_is_deterministic(corpus):
    draft, out = corpus
    assert json.dumps(Q.generate(draft, SPEC), sort_keys=True) == json.dumps(out, sort_keys=True)


def test_no_model_is_called(corpus):
    assert corpus[1]["model_calls"] == 0


def test_a_foreign_draft_schema_is_refused():
    d = fake_draft([]); d["schema"] = "other/v1"
    with pytest.raises(ValueError, match="schema"):
        Q.generate(d, SPEC)


def test_a_draft_made_against_other_outcomes_is_refused():
    d = fake_draft([]); d["outcomes"] = ["YES", "NO"]
    with pytest.raises(ValueError, match="outcome vocabulary"):
        Q.generate(d, SPEC)


def test_the_cli_exits_3_on_a_field_with_no_template(tmp_path):
    f = tmp_path / "d.json"
    f.write_text(json.dumps(fake_draft([fake_question("something_new.*")])))
    task = ROOT / "research/capability-learning/tasks/ir_ep114.json"
    assert Q.main([str(f), "--task", str(task)]) == 3
