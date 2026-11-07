#!/usr/bin/env python3
"""Tests for the deterministic draft from a teach session (A3a).

The contract: every IR field the draft fills is read off the cited clause
text, and every field it does not fill is classified `hypothesis` (the clause
allows several values, which are enumerated) or `issue` (the clause fixes
nothing). Nothing is guessed, and no model is called.

The assertion that matters most is the negative one: no value appears in the
draft that is not in the clause it is attributed to. A drafter that invents a
threshold is worse than one that leaves it empty, because the empty field
gets a question and the invented one does not.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
HARNESS = ROOT / "research/capability-learning/harness"
sys.path.insert(0, str(HARNESS))

import atomic as A  # noqa: E402
import draft_from_session as D  # noqa: E402

SPEC = json.loads((ROOT / "research/capability-learning/tasks/ir_ep114.json").read_text())
CORPUS = ROOT / "research/capability-learning/data/ir-tasks-v1/corpus/koravi-ep-114.txt"
SHA = "a" * 64


def clause(page, index, text, start=0, extraction="txt"):
    return {
        "document": "koravi-ep-114.txt",
        "document_sha256": SHA,
        "page": page,
        "index": index,
        "text": text,
        "char_start": start,
        "char_end": start + len(text),
        "extraction": extraction,
    }


def session(clauses, *, tenant="koravi-process", rule="Follow EP-114 rev C.", examples=None):
    return {
        "schema": D.SESSION_SCHEMA,
        "session_id": "s" * 64,
        "tenant": tenant,
        "task": "ir_acceptance",
        "expert_id": "expert:koravi-elec-lead",
        "document": "koravi-ep-114.txt",
        "document_sha256": SHA,
        "pages": sorted({c["page"] for c in clauses}) or [1],
        "clauses": clauses,
        "rule": rule,
        "examples": examples or [],
        # Derived by the runtime, not by the caller; the drafter recomputes it
        # from the clauses, so a session fixture leaves it empty.
        "ocr_cited": [],
        "created_ms": 1,
    }


def ingested_corpus_clauses():
    """The real corpus, through the real A1 ingester."""
    import ingest_documents as I

    return [
        {
            "document": c.document,
            "document_sha256": c.document_sha256,
            "page": c.page,
            "index": c.index,
            "text": c.text,
            "char_start": c.char_start,
            "char_end": c.char_end,
            "extraction": c.extraction,
        }
        for c in I.ingest(CORPUS)
    ]


@pytest.fixture(scope="module")
def corpus_draft():
    return D.draft(session(ingested_corpus_clauses()), SPEC)


# ── the document's own answers ───────────────────────────────────────────────

def test_the_validity_range_is_read_off_the_clause(corpus_draft):
    # "the winding temperature must be between 10 and 75 degrees Celsius
    # inclusive." Both bounds and the unit are determined; nothing is chosen.
    got = {f["path"]: f["value"] for f in corpus_draft["fields"] if f["status"] == "evidence"}
    assert got["validity[].min"] == 10.0
    assert got["validity[].max"] == 75.0
    assert got["validity[].unit"] == "°C"
    assert got["validity[].ref"] == "temperature"


def test_the_two_single_outcome_fields_are_determined(corpus_draft):
    kinds = {c["kind"]: c["claim"] for c in corpus_draft["claims_determined"]}
    assert kinds["missing_input"] == {"outcome": "INSUFFICIENT_INPUT"}
    assert kinds["default_outcome"] == {"outcome": "PASS"}


def test_the_validity_claim_is_incomplete_because_its_outcome_is_elsewhere(corpus_draft):
    # The range is in one sentence and "the test is invalid" is in the next.
    # The honest result is a determined range with an unanswered outcome, not
    # a guessed INVALID_TEST.
    assert not any(c["kind"] == "validity" for c in corpus_draft["claims_determined"])
    outcome = [f for f in corpus_draft["fields"] if f["path"] == "validity[].outcome"]
    assert outcome and outcome[0]["status"] == "issue"


def test_what_the_clauses_do_not_determine_is_left_for_the_expert(corpus_draft):
    # These three are the model's job in A3b; the draft must not fill them.
    assert set(corpus_draft["ir_unfilled_required"]) == {"topic_terms", "inputs", "rules"}
    assert corpus_draft["status"] == "NEEDS_EXPERT_ANSWERS"


def test_no_model_is_called(corpus_draft):
    assert corpus_draft["model_calls"] == 0


def test_every_field_is_classified_and_counted(corpus_draft):
    counts = corpus_draft["field_counts"]
    assert set(counts) == {"evidence", "hypothesis", "issue"}
    assert sum(counts.values()) == len(corpus_draft["fields"])
    assert all(f["status"] in counts for f in corpus_draft["fields"])


def test_one_question_per_unsettled_field(corpus_draft):
    unsettled = [f for f in corpus_draft["fields"] if f["status"] != "evidence"]
    assert len(corpus_draft["questions"]) == len(unsettled)
    for q in corpus_draft["questions"]:
        assert q["needs"], "a question must say what it needs"
        assert q["clause_text"], "a question must quote the text it is about"


# ── the negative assertion: nothing is invented ─────────────────────────────

def test_no_filled_value_is_absent_from_the_text_it_is_attributed_to(corpus_draft):
    units = {u["id"]: u["text"] for u in corpus_draft["claim_units"]}
    for f in corpus_draft["fields"]:
        if f["status"] != "evidence":
            continue
        text = units[f["clause"]]
        value = f["value"]
        if isinstance(value, float):
            # The number itself must appear, in the spelling the clause uses.
            nums = {float(n.value) for n in A.clause_numbers(text)}
            assert value in nums, f"{f['path']}={value} is not a number in {text!r}"
        elif f["path"].endswith(".unit"):
            assert value in A.units_mentioned(text) or value == "none"
        elif f["path"].endswith("outcome") or f["path"] == "default_outcome":
            assert value in A.outcome_match(text, SPEC["outcomes"])


def test_nothing_is_filled_from_the_experts_prose_rule():
    # The rule states a range the clauses do not; it must not reach the IR.
    clauses = [clause(1, 0, "Confidential.")]
    d = D.draft(
        session(clauses, rule="Reject anything below 999 megohm and above 42 degrees Celsius."),
        SPEC,
    )
    blob = json.dumps(d["ir"])
    assert "999" not in blob and "42" not in blob
    assert d["expert_rule"].startswith("Reject anything")  # recorded, for B1


# ── unit inheritance ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text,expect",
    [
        ("the temperature must be between 10 and 75 degrees Celsius inclusive.", "°C"),
        ("valid between 10 degrees Celsius and 75 degrees Celsius inclusive.", "°C"),
    ],
)
def test_a_stated_range_shares_one_unit(text, expect):
    nums, unit = D._range_numbers(text)
    assert unit == expect
    assert sorted(float(n.value) for n in nums) == [10.0, 75.0]


def test_a_unit_is_not_inherited_without_the_word_between():
    # "at least 10, up to 75 megohm" is two separate statements, not a range,
    # so the untagged 10 keeps no unit and the draft must not invent one.
    _, unit = D._range_numbers("at least 10, up to 75 megohm.")
    assert unit is None


def test_a_range_with_two_different_units_is_not_a_range():
    _, unit = D._range_numbers("between 10 kV and 75 megohm.")
    assert unit is None


# ── the citation / claim segmentation bridge ────────────────────────────────

def test_clauses_split_at_a_colon_are_rejoined_for_claim_extraction():
    # A1 splits "Step 1 validity:" away from the numbers. Fed separately, the
    # word "validity" and the numbers never meet and nothing is determined.
    parts = [
        clause(1, 0, "Step 1 validity:", 0),
        clause(1, 1, "the winding temperature must be between 10 and 75 degrees Celsius inclusive.", 17),
    ]
    units = D.claim_units({c["id"]: c for c in [dict(p, id=f"p1#{i}", page=1, index=i) for i, p in enumerate(parts)]})
    assert len(units) == 1, units
    assert "validity" in units[0]["text"] and "75" in units[0]["text"]
    assert units[0]["sources"] == ["p1#0", "p1#1"]
    assert "validity" in A.plausible_kinds(units[0]["text"], SPEC["outcomes"])


def test_claim_unit_ids_are_unique(corpus_draft):
    ids = [u["id"] for u in corpus_draft["claim_units"]]
    assert len(ids) == len(set(ids)), [i for i in ids if ids.count(i) > 1]


def test_each_question_quotes_the_unit_it_is_about():
    # REGRESSION. One A1 clause spanning a line break becomes two claim units
    # with the same source. They used to share an id, so the first unit's
    # question quoted the second unit's sentence.
    c = clause(1, 0, "koravi-process|ep-114|restricted|EP-114 rev C\nConfidential.")
    d = D.draft(session([c]), SPEC)
    units = d["claim_units"]
    assert [u["text"] for u in units] == [
        "koravi-process|ep-114|restricted|EP-114 rev C",
        "Confidential.",
    ]
    assert units[0]["id"] != units[1]["id"]
    by_id = {u["id"]: u["text"] for u in units}
    for f, q in zip([f for f in d["fields"] if f["status"] != "evidence"], d["questions"]):
        assert q["clause_text"] == by_id[f["clause"]]


def test_a_claim_unit_remains_traceable_to_every_clause_it_came_from(corpus_draft):
    cited = {f"p{c['page']}#{c['index']}" for c in ingested_corpus_clauses()}
    for u in corpus_draft["claim_units"]:
        assert u["sources"], f"unit {u['id']} has no source clause"
        assert set(u["sources"]) <= cited


def test_questions_cite_every_source_clause(corpus_draft):
    for q in corpus_draft["questions"]:
        assert "koravi-ep-114.txt p.1 [" in q["citation"] or q["citation"] == q["clause"]


# ── classification of ambiguity ─────────────────────────────────────────────

def test_several_outcomes_in_one_clause_becomes_a_hypothesis_with_candidates():
    text = "If any input is missing the result is insufficient input or the test is invalid."
    st = D._outcome_state(text, SPEC["outcomes"], "missing_input_outcome", "p1#0")
    assert st.status == "hypothesis"
    assert sorted(st.candidates) == ["INSUFFICIENT_INPUT", "INVALID_TEST"]
    assert st.value is None


def test_no_outcome_in_the_clause_becomes_an_issue():
    st = D._outcome_state("The sky is blue.", SPEC["outcomes"], "default_outcome", "p1#0")
    assert st.status == "issue" and st.value is None


def test_a_clause_the_ir_cannot_express_is_recorded_not_dropped():
    d = D.draft(session([clause(1, 0, "Confidential.")]), SPEC)
    assert [f["status"] for f in d["fields"]] == ["issue"]
    assert "nothing the IR can express" in d["fields"][0]["basis"]


def test_a_rule_needs_exactly_one_comparator():
    # The IR has no conjunction, so "at least 1.5 but below 2.0" cannot be one
    # rule; the draft says so rather than picking a half.
    text = "If PI is at least 1.5 but below 2.0, accept for service with a retest in 30 days."
    claim, states = D._decision_rule({"id": "p1#0", "text": text}, SPEC["outcomes"])
    assert claim is None
    assert states[0].path == "rules[].op"
    assert states[0].status == "hypothesis"
    assert states[0].candidates == [">=", "<"]


# ── OCR provenance carries through ──────────────────────────────────────────

def test_an_ocr_clause_marks_its_questions():
    c = clause(1, 0, "Step 1 validity: the temperature must be between 10 and 75 degrees Celsius inclusive.",
               extraction="pdf_ocr")
    d = D.draft(session([c]), SPEC)
    assert d["clauses_ocr"] == ["p1#0"]
    assert d["questions"] and all(q["ocr_warning"] for q in d["questions"])


def test_a_text_layer_clause_marks_no_ocr_warning(corpus_draft):
    assert corpus_draft["clauses_ocr"] == []
    assert not any(q["ocr_warning"] for q in corpus_draft["questions"])


# ── refusals ────────────────────────────────────────────────────────────────

def test_a_foreign_session_schema_is_refused():
    s = session([clause(1, 0, "Confidential.")])
    s["schema"] = "something.else/v9"
    with pytest.raises(D.DraftError, match="schema"):
        D.draft(s, SPEC)


def test_a_session_from_another_tenant_is_refused():
    with pytest.raises(D.DraftError, match="tenant"):
        D.draft(session([clause(1, 0, "Confidential.")], tenant="someone-else"), SPEC)


def test_the_draft_is_deterministic(corpus_draft):
    again = D.draft(session(ingested_corpus_clauses()), SPEC)
    assert json.dumps(again, sort_keys=True) == json.dumps(corpus_draft, sort_keys=True)


def test_an_unevaluable_ir_reports_not_measured_rather_than_zero(corpus_draft):
    # Standing rule: never a zero for an unmeasured metric.
    assert corpus_draft["examples_checked"] is None
    assert "NOT_MEASURED" in corpus_draft["examples_note"]
