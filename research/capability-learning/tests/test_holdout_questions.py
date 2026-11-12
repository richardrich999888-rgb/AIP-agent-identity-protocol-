#!/usr/bin/env python3
"""B3 on the v0.2 holdout (HU-TX-2), the deterministic half.

Preserves the original copied-plural control while checking the bounded,
explicit exclusion word-form policy. Historical recorded bytes stay intact.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
CL = ROOT / "research/capability-learning"
sys.path.insert(0, str(CL / "harness"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import apply_answers as B  # noqa: E402
import draft_from_session as D  # noqa: E402
import ingest_documents as I  # noqa: E402
import question_generator as Q  # noqa: E402
import record_answers as RA  # noqa: E402
import record_holdout as H  # noqa: E402
import schema_subset as S  # noqa: E402
from correct_ir import leaves  # noqa: E402
from test_draft_from_session import session  # noqa: E402

SPEC = json.loads(H.TASK.read_text())
CORPUS = CL / "data/tx-tasks-v1/corpus/halvorn-hu-tx-2.txt"


@pytest.fixture(scope="module")
def chain():
    clauses = [{"document": c.document, "document_sha256": c.document_sha256, "page": c.page,
                "index": c.index, "text": c.text, "char_start": c.char_start, "char_end": c.char_end,
                "extraction": c.extraction} for c in I.ingest(CORPUS)]
    draft = D.draft(session(clauses, tenant=SPEC["tenant"]), SPEC)
    return draft, Q.generate(draft, SPEC)


def owner(chain):
    (q,) = [q for q in chain[1]["questions"] if B.LIST_PATHS.get(q["field_path"]) == "out_of_scope_terms"]
    return q


def test_the_three_v02_edits_are_exclusion_terms():
    a = dict(leaves(json.loads(H.V02_CANDIDATE_IR.read_text())))
    b = dict(leaves(json.loads(H.V02_CORRECTED_IR.read_text())))
    changed = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    assert changed == [".out_of_scope_terms[1]", ".out_of_scope_terms[2]", ".out_of_scope_terms[3]"]


def test_one_question_owns_the_exclusion_list(chain):
    q = owner(chain)
    assert H.EXCLUSION_SENTENCE in q["quote"]
    assert "Copy each item exactly as it is written" in q["question"]


def test_b2_accepts_the_documents_plurals(chain):
    q = owner(chain)
    assert B._copied_words(q["field_path"], H.EXCLUSION_ALTERNATIVES["copied_as_written"], q["quote"]) == []


def test_b2_refuses_replacing_quoted_forms_with_variants(chain):
    q = owner(chain)
    errs = B._copied_words(q["field_path"], H.EXCLUSION_ALTERNATIVES["v02_expert_terms"], q["quote"])
    assert sorted(e.split("'")[1] for e in errs) == ["cable", "generator", "motor"]
    assert all("requires keeping quoted term" in e for e in errs)


def test_b2_accepts_explicit_both_number_forms(chain):
    q = owner(chain)
    assert B._copied_words(q["field_path"], H.EXCLUSION_ALTERNATIVES["both_numbers"], q["quote"]) == []


def test_the_subject_copied_whole_exceeds_the_term_limit(chain):
    q = RA.qid_for(chain[1], "scope_subject.*", "Scope: oil-immersed")
    assert S.validate(H.LONG_SUBJECT, q["answer_schema"]) == ["answer[0]: 38 characters, at most 32 allowed"]
    assert "at most 32 characters" in q["question"]


def test_the_scripted_answers_compile_through_b2(chain):
    draft, qs = chain
    out = B.apply(draft, SPEC, RA.answers_file(draft, qs, H.AS_INSTRUCTED, 1))
    assert out["status"] == "COMPILES"
    assert out["ir"]["out_of_scope_terms"] == ["motors", "cables", "generators", "dry-type transformers"]
