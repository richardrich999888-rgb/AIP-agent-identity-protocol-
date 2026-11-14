#!/usr/bin/env python3
"""Tests for answer application (B2).

The contract: every answer becomes typed leaf edits on the IR, each with who,
when and why; an answer that fails any check refuses the whole file and
nothing is applied; an element enters the IR only when every leaf is filled.

The fixture is the real EP-114 corpus through A1 and A3a, answered with the
recorder's table (read off the document by the engineer, not an expert).
"""
import copy
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
HARNESS = ROOT / "research/capability-learning/harness"
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import apply_answers as B  # noqa: E402
import draft_from_session as D  # noqa: E402
import question_generator as Q  # noqa: E402
import record_answers as RA  # noqa: E402
from correct_ir import leaves  # noqa: E402
from test_draft_from_session import SPEC, ingested_corpus_clauses, session  # noqa: E402
from test_question_generator import UNSETTLED_PATHS  # noqa: E402

WHEN = 1_767_225_600_000  # 2026-01-01T00:00:00Z, a fixed clock for tests


@pytest.fixture(scope="module")
def corpus():
    draft = D.draft(session(ingested_corpus_clauses()), SPEC)
    return draft, Q.generate(draft, SPEC)


def answers(corpus, table=None):
    draft, qs = corpus
    return RA.answers_file(draft, qs, RA.SCRIPTED if table is None else table, WHEN)


def apply(corpus, doc):
    return B.apply(copy.deepcopy(corpus[0]), SPEC, doc)


def refused(corpus, doc) -> list[dict]:
    with pytest.raises(B.AnswersRefused) as e:
        apply(corpus, doc)
    return e.value.errors


def replace(table, path, frag, answer):
    out = [list(r) for r in table]
    (row,) = [r for r in out if r[0] == path and frag in r[1]]
    row[2] = answer
    return [tuple(r) for r in out]


def drop(table, *keep_out):
    return [r for r in table if (r[0], r[1]) not in keep_out]


def n_of(corpus, path, frag):
    return RA.qid_for(corpus[1], path, frag)["n"]


# ── happy path ──────────────────────────────────────────────────────────────

def test_every_question_has_somewhere_to_land():
    assert set(UNSETTLED_PATHS) <= B.ANSWERABLE_PATHS


def test_the_scripted_answers_compile(corpus):
    out = apply(corpus, answers(corpus))
    assert out["status"] == "COMPILES"
    assert out["ir_schema_errors"] == [] and out["ir_compile_error"] is None
    assert out["numbers_without_cited_provenance"] == []
    assert out["counts"] == {
        "questions": 17, "answered": 16, "not_applicable": 1, "unanswered": 0,
        "leaves_set_by_answers": 54, "leaf_edits": 50, "leaves_from_document": 13,
        "elements_complete": 6, "elements_incomplete": 0, "elements_withdrawn": 0,
    }


def test_rules_are_in_document_order_and_mix_document_and_answer_leaves(corpus):
    out = apply(corpus, answers(corpus))
    assert [(r["value"], r["op"], r["against"], r["number"], r["limit_fraction"], r["outcome"])
            for r in out["ir"]["rules"]] == [
        ("corrected", "<", "limit", 0, 0.5, "REJECT"),
        ("corrected", "<", "limit", 0, 1, "DRY_OUT"),
        ("cued_1", "<", "number", 1.5, 1, "DRY_OUT"),
        ("cued_1", "<", "number", 2.0, 1, "RETEST_30D"),
    ]
    first = out["elements"][2]
    assert first["sentence"] == "p1#16+p1#17"
    assert first["from_document"] == ["op", "outcome"]


def test_every_edit_is_typed_attributed_and_present_in_the_ir(corpus):
    out = apply(corpus, answers(corpus))
    for e in out["edits"]:
        assert e["who"] == RA.AUTHOR and e["when_ms"] >= WHEN and e["why"].strip()
        assert e["type"] in ("enum", "number", "string")
        assert RA.read_back(out["ir"], e["path"]) == e["after"]


def test_edit_types_follow_the_compilers_schema(corpus):
    out = apply(corpus, answers(corpus))
    kinds = {e["path"]: e["type"] for e in out["edits"]}
    assert kinds["rules[0].value"] == "enum"
    assert kinds["rules[0].limit_fraction"] == "number"
    assert kinds["topic_terms[0]"] == "string"
    assert kinds["inputs[3].cues[0]"] == "string"


def test_leaves_are_counted_the_way_v02_counted_them(corpus):
    # Comparability with V02_REPORT's leaf-edit counts: same leaf definition.
    answer = RA.SCRIPTED[4][2]
    q = RA.qid_for(corpus[1], "required_inputs.*", "Required inputs")
    typed = [p for p, _, _ in B.typed_leaves(answer, q["answer_schema"], "inputs")]
    assert typed == [p for p, _ in leaves(answer, "inputs")]


def test_unchanged_leaves_are_set_but_not_counted_as_edits(corpus):
    out = apply(corpus, answers(corpus))
    same = [e["path"] for e in out["edits"] if e["before"] == e["after"]]
    # The draft's neutral correction already had these values.
    assert sorted(same) == ["correction.by", "correction.rate", "correction.rate_unit", "correction.reference_unit"]


def test_the_ir_does_not_depend_on_the_order_answers_were_written(corpus):
    doc = answers(corpus)
    shuffled = copy.deepcopy(doc)
    random.Random(7).shuffle(shuffled["answers"])
    a, b = apply(corpus, doc), apply(corpus, shuffled)
    assert a["ir"] == b["ir"]
    assert [(e["path"], e["after"]) for e in a["edits"]] == [(e["path"], e["after"]) for e in b["edits"]]


def test_apply_is_pure(corpus):
    draft = copy.deepcopy(corpus[0])
    doc = answers(corpus)
    before = (json.dumps(draft, sort_keys=True), json.dumps(doc, sort_keys=True))
    a = B.apply(draft, SPEC, doc)
    assert (json.dumps(draft, sort_keys=True), json.dumps(doc, sort_keys=True)) == before
    assert B.apply(draft, SPEC, doc) == a


def test_no_answers_leaves_the_draft_as_it_was(corpus):
    out = apply(corpus, answers(corpus, []))
    assert out["ir"] == corpus[0]["ir"]
    assert out["edits"] == [] and out["counts"]["unanswered"] == 17
    assert out["status"] == "NEEDS_MORE_ANSWERS"
    assert out["author"] is None


def test_a_partly_answered_rule_is_reported_not_emitted(corpus):
    table = [r for r in RA.SCRIPTED if r[1] == "If it is below the minimum"] + \
            [r for r in RA.SCRIPTED if r[0] == "rules[].value" and r[1] == "PI is below 1.5"]
    out = apply(corpus, answers(corpus, table))
    assert len(out["ir"]["rules"]) == 1
    (pi,) = [e for e in out["elements"] if e["sentence"] == "p1#19"]
    assert pi["status"] == "incomplete" and pi["path"] is None
    assert pi["missing"] == ["against", "number", "unit", "limit_fraction"]
    # The edit is still recorded, with no place in the IR yet.
    (e,) = [e for e in out["edits"] if e["address"] == "rules[@p1#19].value"]
    assert e["path"] is None


def test_not_applicable_withdraws_a_rule(corpus):
    table = drop(RA.SCRIPTED, ("rules[].value", "PI is below 1.5"), ("rules[].number", "PI is below 1.5"))
    table.append(("rules[].value", "PI is below 1.5", None, "covered by the next rule"))
    out = apply(corpus, answers(corpus, table))
    assert [r["number"] for r in out["ir"]["rules"] if r["value"] == "cued_1"] == [2.0]
    (pi,) = [e for e in out["elements"] if e["sentence"] == "p1#19"]
    assert pi["status"] == "withdrawn"
    assert out["counts"]["elements_withdrawn"] == 1


# ── refusals: the whole file, at the right question ─────────────────────────

def test_an_answer_to_other_questions_is_refused(corpus):
    doc = answers(corpus)
    doc["questions_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="different questions"):
        apply(corpus, doc)


def test_answers_to_a_draft_changed_since_are_refused(corpus):
    # The validity bounds are document evidence, not in any question: only
    # the draft digest notices that they changed after the expert answered.
    doc = answers(corpus)
    draft = copy.deepcopy(corpus[0])
    (lo,) = [f for f in draft["fields"] if f["path"] == "validity[].min"]
    lo["value"] = 5.0
    assert B.questions_digest(Q.generate(draft, SPEC)) == doc["questions_sha256"]
    with pytest.raises(ValueError, match="different draft"):
        B.apply(draft, SPEC, doc)


def test_an_answer_for_another_session_is_refused(corpus):
    doc = answers(corpus)
    doc["session_id"] = "f" * 64
    with pytest.raises(ValueError, match="different teach session"):
        apply(corpus, doc)


@pytest.mark.parametrize("mutate,match", [
    (lambda d: d.update(schema="x/v9"), "answers schema"),
    (lambda d: d.update(extra=1), "unexpected field"),
    (lambda d: d.update(answers={}), "must be a list"),
])
def test_a_malformed_answers_file_is_refused(corpus, mutate, match):
    doc = answers(corpus)
    mutate(doc)
    with pytest.raises(ValueError, match=match):
        apply(corpus, doc)


def test_an_unknown_question_is_refused(corpus):
    doc = answers(corpus)
    doc["answers"][0]["qid"] = "p9#9:rules[].op"
    assert any("no question" in e["error"] for e in refused(corpus, doc))


def test_answering_twice_is_refused(corpus):
    doc = answers(corpus)
    doc["answers"].append(copy.deepcopy(doc["answers"][5]))
    errs = refused(corpus, doc)
    assert any("answered twice" in e["error"] and e["question"] == 6 for e in errs)


@pytest.mark.parametrize("field,value,match", [
    ("who", ".hidden", "who must be"),
    ("who", "a b", "who must be"),
    ("who", "x" * 65, "who must be"),
    ("who", None, "who must be"),
    ("when_ms", 0, "when_ms"),
    ("when_ms", -5, "when_ms"),
    ("when_ms", True, "when_ms"),
    ("when_ms", "1", "when_ms"),
    ("why", "   ", "why must say why"),
    ("why", "x" * 1001, "at most 1000"),
    ("why", "a\x00b", "control characters"),
    ("surprise", 1, "unexpected field"),
])
def test_an_answer_without_a_proper_who_when_why_is_refused(corpus, field, value, match):
    doc = answers(corpus)
    doc["answers"][0][field] = value
    errs = refused(corpus, doc)
    assert any(match in e["error"] and e["entry"] == 1 for e in errs), errs


def test_an_answer_needs_exactly_one_of_answer_or_not_applicable(corpus):
    doc = answers(corpus)
    doc["answers"][0]["not_applicable"] = True
    del doc["answers"][1]["answer"]
    errs = refused(corpus, doc)
    assert {e["entry"] for e in errs if "exactly one" in e["error"]} == {1, 2}


def test_one_file_has_one_author(corpus):
    doc = answers(corpus)
    doc["answers"][3]["who"] = "expert:someone-else"
    assert any("one author" in e["error"] for e in refused(corpus, doc))


@pytest.mark.parametrize("path,frag,bad,match", [
    ("validity[].outcome", "between 10 and 75", "INVALID", "is not one of"),
    ("rules[].number", "PI is below 1.5", {"against": "number", "number": 1.5, "unit": "none",
                                           "limit_fraction": 1, "note": "x"}, "unexpected field 'note'"),
    ("rules[].number", "PI is below 1.5", {"against": "number", "number": True, "unit": "none",
                                           "limit_fraction": 1}, "finite number"),
    ("rules[].op", "at least 1.5", "<=", "is not one of"),
])
def test_an_answer_outside_the_compilers_schema_is_refused(corpus, path, frag, bad, match):
    errs = refused(corpus, answers(corpus, replace(RA.SCRIPTED, path, frag, bad)))
    assert [e["question"] for e in errs] == [n_of(corpus, path, frag)]
    assert match in errs[0]["error"]


@pytest.mark.parametrize("path,frag,bad", [
    ("rules[].number", "at least 1.5", {"against": "number", "number": 2.5, "unit": "none", "limit_fraction": 1}),
    ("rules[].number", "below half", {"against": "limit", "number": 0, "unit": "none", "limit_fraction": 0.25}),
    ("correction.*", "Step 2", {**RA.SCRIPTED[6][2], "step": 15}),
    ("limit.*", "Step 3", {**RA.SCRIPTED[7][2], "offset": 2}),
    ("scope_limit.*", "Scope: induction", {"ref": "voltage", "op": ">", "value": 33, "unit": "kV"}),
])
def test_a_number_the_sentence_does_not_state_is_refused(corpus, path, frag, bad):
    errs = refused(corpus, answers(corpus, replace(RA.SCRIPTED, path, frag, bad)))
    assert [e["question"] for e in errs] == [n_of(corpus, path, frag)]
    assert "not stated in the quoted sentence" in errs[0]["error"]


def test_an_unused_number_needs_no_source(corpus):
    # `number` is ignored when a rule compares with the limit, as `rate` is for
    # a multiplicative correction; neither is a threshold anyone relies on.
    table = replace(RA.SCRIPTED, "rules[].number", "below half",
                    {"against": "limit", "number": 99, "unit": "none", "limit_fraction": 0.5})
    assert apply(corpus, answers(corpus, table))["status"] == "COMPILES"


@pytest.mark.parametrize("path,frag,bad,match", [
    ("scope_subject.*", "Scope: induction", ["synchronous motors"], "term 'synchronous motors'"),
    ("scope_subject.*", "Scope: induction", ["induction"], None),  # a word of the sentence is fine
    ("scope_subject.*", "Scope: induction", [" "], "empty term"),
    ("scope_exclusion_terms.*", "does not apply", ["transformers", "switchgear"], "term 'switchgear'"),
    ("required_inputs.*", "Required inputs", [{"ref": "cued_1", "unit": "none", "cues": ["IR"]}], "short name 'IR'"),
])
def test_words_must_be_copied_from_the_sentence(corpus, path, frag, bad, match):
    doc = answers(corpus, replace(RA.SCRIPTED, path, frag, bad))
    if match is None:
        apply(corpus, doc)
        return
    errs = refused(corpus, doc)
    assert [e["question"] for e in errs] == [n_of(corpus, path, frag)]
    assert match in errs[0]["error"]


def test_a_word_is_matched_whole_not_inside_another():
    assert not B._in_quote("PI", "a PIPE")
    assert B._in_quote("PI", "polarization index (PI)")
    assert B._in_quote("induction motors", "Scope: Induction Motors rated")


def test_the_same_scope_limit_taught_twice_is_refused(corpus):
    table = replace(RA.SCRIPTED, "scope_limit.*", "does not apply",
                    {"ref": "voltage", "op": ">", "value": 11, "unit": "kV"})
    errs = refused(corpus, answers(corpus, table))
    assert [e["question"] for e in errs] == [n_of(corpus, "scope_limit.*", "does not apply")]
    assert "duplicates" in errs[0]["error"]


def test_the_same_input_declared_twice_is_refused(corpus):
    inputs = RA.SCRIPTED[4][2] + [{"ref": "voltage", "unit": "V", "cues": []}]
    errs = refused(corpus, answers(corpus, replace(RA.SCRIPTED, "required_inputs.*", "Required inputs", inputs)))
    assert "already taught" in errs[0]["error"] and "voltage" in errs[0]["error"]


def test_withdrawing_a_rule_while_answering_part_of_it_is_refused(corpus):
    table = RA.SCRIPTED + []
    table = replace(table, "rules[].value", "PI is below 1.5", None)
    errs = refused(corpus, answers(corpus, table))
    assert [e["question"] for e in errs] == [n_of(corpus, "rules[].value", "PI is below 1.5")]
    assert "teaches no rules entry" in errs[0]["error"]


def test_every_problem_is_listed_and_nothing_is_applied(corpus):
    errs = refused(corpus, answers(corpus, RA.with_faults(RA.SCRIPTED)))
    assert len(errs) == len(RA.FAULTS)
    assert sorted(e["question"] for e in errs) == sorted(n_of(corpus, p, f) for p, f, _, _ in RA.FAULTS)


def test_a_draft_whose_ir_does_not_follow_from_its_fields_is_refused(corpus):
    draft = copy.deepcopy(corpus[0])
    draft["ir"]["validity"] = [{"ref": "temperature", "min": 0, "max": 99, "unit": "°C", "outcome": "PASS"}]
    # Answers made for this very draft, so the digests match and only the
    # draft's own inconsistency is left to catch (a drafter bug, not tampering).
    doc = RA.answers_file(draft, Q.generate(draft, SPEC), [], WHEN)
    with pytest.raises(B.DraftInconsistent):
        B.apply(draft, SPEC, doc)


def test_a_complete_rule_from_the_document_needs_no_answer():
    draft = D.draft(session([
        {"document": "koravi-ep-114.txt", "document_sha256": "a" * 64, "page": 1, "index": 0,
         "text": "If the resistance is below 5 megohms, reject the motor.", "char_start": 0,
         "char_end": 55, "extraction": "txt"}]), SPEC)
    qs = Q.generate(draft, SPEC)
    out = B.apply(draft, SPEC, RA.answers_file(draft, qs, [], WHEN))
    assert out["ir"]["rules"] == draft["ir"]["rules"] and len(out["ir"]["rules"]) == 1
    assert out["elements"][0]["from_document"] == sorted(B.ELEMENT_LEAVES["rules"])


def test_the_digest_binds_wording():
    a = {"questions": [{"question": "What is the result?"}]}
    b = {"questions": [{"question": "What is the outcome?"}]}
    assert B.questions_digest(a) != B.questions_digest(b)
    assert B.questions_digest(a) == B.questions_digest(json.loads(json.dumps(a)))


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli(tmp_path, corpus, doc):
    (tmp_path / "draft.json").write_text(json.dumps(corpus[0]))
    (tmp_path / "answers.json").write_text(json.dumps(doc))
    task = ROOT / "research/capability-learning/tasks/ir_ep114.json"
    return subprocess.run([sys.executable, str(HARNESS / "apply_answers.py"), str(tmp_path / "draft.json"),
                           str(tmp_path / "answers.json"), "--task", str(task), "--out", str(tmp_path / "out.json")],
                          capture_output=True, text=True)


def test_cli_applies_and_counts_on_screen(tmp_path, corpus):
    r = _cli(tmp_path, corpus, answers(corpus))
    assert r.returncode == 0, r.stderr
    assert "COMPILES" in r.stdout and "answered 16 of 17" in r.stdout and "50 leaf edit(s)" in r.stdout
    assert json.loads((tmp_path / "out.json").read_text())["status"] == "COMPILES"


def test_cli_refusal_exits_3_and_writes_nothing(tmp_path, corpus):
    r = _cli(tmp_path, corpus, answers(corpus, RA.with_faults(RA.SCRIPTED)))
    assert r.returncode == 3
    assert "nothing applied" in r.stderr and "question 17" in r.stderr
    assert not (tmp_path / "out.json").exists()


def test_cli_bad_input_exits_2(tmp_path, corpus):
    doc = answers(corpus)
    doc["questions_sha256"] = "0" * 64
    assert _cli(tmp_path, corpus, doc).returncode == 2


def test_an_answer_may_not_overwrite_what_the_document_determined(corpus):
    # A3a never asks about a leaf it filled, but B2 reads the draft from a
    # file; a draft that both fills a leaf and asks about it must not let the
    # answer silently replace the document's value.
    draft = copy.deepcopy(corpus[0])
    draft["fields"].append({"path": "rules[].unit", "status": "evidence", "clause": "p1#19",
                            "basis": "crafted", "value": "MΩ", "candidates": []})
    qs = Q.generate(draft, SPEC)
    doc = RA.answers_file(draft, qs, RA.SCRIPTED, WHEN)
    with pytest.raises(B.AnswersRefused) as e:
        B.apply(draft, SPEC, doc)
    (err,) = e.value.errors
    assert err["question"] == n_of(corpus, "rules[].number", "PI is below 1.5")
    assert "unit of this rule is already set (document)" in err["error"]


def test_a_correction_is_taught_once(corpus):
    # Two sentences that each read as a correction must not both set it: the
    # second would silently replace the first.
    draft = copy.deepcopy(corpus[0])
    (q,) = [q for q in draft["questions"] if q["field_path"] == "correction.*"]
    draft["questions"].append({**q, "clause": q["clause"] + "/2"})
    qs = Q.generate(draft, SPEC)
    doc = RA.answers_file(draft, qs, [r for r in RA.SCRIPTED if r[0] != "correction.*"], WHEN)
    first, second = [x for x in qs["questions"] if x["field_path"] == "correction.*"]
    for x in (first, second):
        doc["answers"].append({"qid": x["qid"], "answer": RA.SCRIPTED[6][2], "who": RA.AUTHOR,
                               "when_ms": WHEN, "why": "the correction sentence"})
    with pytest.raises(B.AnswersRefused) as e:
        B.apply(draft, SPEC, doc)
    (err,) = e.value.errors
    assert err["question"] == second["n"] and "already set by question" in err["error"]
