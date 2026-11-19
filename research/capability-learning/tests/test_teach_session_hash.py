#!/usr/bin/env python3
"""Does the Python reproduction of the teach-session hash agree with Rust (A2)?

The Rust tests prove the runtime agrees with itself: `session_id` is whatever
`content_hash()` returns. That cannot catch an accidental change to *which*
fields are hashed, because both sides of the comparison move together.

These tests compare against a session file produced by the real `syntriass`
binary, checked in as a fixture. Two things then hold:

1. the checked-in `session_id` is reproduced by an independent implementation
   (`record_teach_session.canonical` plus `hashlib`), so the stored id really
   does name the stored content; and
2. every hashed field is load-bearing — mutating any one of them changes the
   hash. A field that could be edited without changing the id would be a
   field an attacker could edit without detection.

If the Rust canonical encoding changes, these tests fail. That is the point:
such a change alters the identity of every session ever recorded, so it must
be a deliberate, reviewed act with a schema bump, not a silent edit.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
HARNESS = ROOT / "research/capability-learning/harness"
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(ROOT / "research/common"))

import record_teach_session as rec  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "teach_session.json"
#: Produced by `syntriass teach start` on the make_pdf_fixture PDF, page 2.
#: Regenerate with record_teach_session.py if the schema is deliberately bumped.
EXPECTED_ID = "877fe69755781670c84d37517a71584c37fed681c30dd2a5c8c83048db22edfa"


@pytest.fixture
def session() -> dict:
    return json.loads(FIXTURE.read_text())


def test_the_fixture_is_the_session_the_binary_produced(session):
    assert session["session_id"] == EXPECTED_ID
    assert session["schema"] == "syntriass.teach-session/v1"


def test_python_reproduces_the_rust_session_id(session):
    computed = hashlib.sha256(rec.canonical(session)).hexdigest()
    assert computed == session["session_id"]


def test_the_verifier_accepts_the_untouched_session(session):
    assert rec.verify_hash_independently(session) == session["session_id"]


def test_the_domain_separator_is_part_of_the_hash(session):
    # Without domain separation, a session's canonical bytes could be
    # presented as some other object's signed content.
    body = rec.canonical(session)
    assert body.startswith(rec.DOMAIN)
    bare = hashlib.sha256(body[len(rec.DOMAIN):]).hexdigest()
    assert bare != session["session_id"]


#: One mutation per hashed field, plus the nested fields inside a clause and
#: an example. Each must change the hash.
MUTATIONS = {
    "schema": lambda s: s.__setitem__("schema", "syntriass.teach-session/v2"),
    "tenant": lambda s: s.__setitem__("tenant", "other-tenant"),
    "task": lambda s: s.__setitem__("task", "other_task"),
    "expert_id": lambda s: s.__setitem__("expert_id", "expert:someone-else"),
    "document": lambda s: s.__setitem__("document", "other.pdf"),
    "document_sha256": lambda s: s.__setitem__("document_sha256", "f" * 64),
    "pages": lambda s: s.__setitem__("pages", [3]),
    "rule": lambda s: s.__setitem__("rule", s["rule"] + " "),
    "ocr_cited": lambda s: s.__setitem__("ocr_cited", ["p2#0"]),
    "created_ms": lambda s: s.__setitem__("created_ms", s["created_ms"] + 1),
    "clause.text": lambda s: s["clauses"][0].__setitem__("text", "tampered"),
    "clause.page": lambda s: s["clauses"][0].__setitem__("page", 3),
    "clause.index": lambda s: s["clauses"][0].__setitem__("index", 7),
    "clause.char_start": lambda s: s["clauses"][0].__setitem__("char_start", 1),
    "clause.char_end": lambda s: s["clauses"][0].__setitem__("char_end", 9999),
    "clause.extraction": lambda s: s["clauses"][0].__setitem__("extraction", "pdf_ocr"),
    "clause.document": lambda s: s["clauses"][0].__setitem__("document", "other.pdf"),
    "clause.document_sha256": lambda s: s["clauses"][0].__setitem__("document_sha256", "e" * 64),
    "clause order": lambda s: s["clauses"].reverse(),
    "clause dropped": lambda s: s["clauses"].pop(),
    "example.id": lambda s: s["examples"][0].__setitem__("id", "zz"),
    "example.text": lambda s: s["examples"][0].__setitem__("text", "something else"),
    "example.label": lambda s: s["examples"][1].__setitem__("label", "allowed"),
    "example.reason": lambda s: s["examples"][0].__setitem__("reason", "a different reason"),
    "example order": lambda s: s["examples"].reverse(),
    "example dropped": lambda s: s["examples"].pop(),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_every_hashed_field_changes_the_session_id(session, name):
    mutated = copy.deepcopy(session)
    MUTATIONS[name](mutated)
    assert mutated != session, f"{name}: mutation did not change the session"
    computed = hashlib.sha256(rec.canonical(mutated)).hexdigest()
    assert computed != session["session_id"], f"{name} is not covered by the hash"
    with pytest.raises(rec.Failure):
        rec.verify_hash_independently(mutated)


def test_a_reordered_json_file_still_hashes_the_same(session):
    # The canonical encoder reads fields by name in a fixed order, so the
    # order they happen to appear in on disk must not matter. Otherwise a
    # formatter rewriting the file would change every session's identity.
    shuffled = dict(reversed(list(session.items())))
    assert list(shuffled) != list(session)
    assert hashlib.sha256(rec.canonical(shuffled)).hexdigest() == session["session_id"]


def test_the_hashed_field_list_matches_the_fixture_exactly(session):
    # A field added to the Rust struct but not to HASHED_FIELDS would be
    # unprotected; one removed from the struct would make canonical() raise.
    # Either way this test is the tripwire.
    assert set(rec.HASHED_FIELDS) | {"session_id"} == set(session)
    assert set(rec.CLAUSE_FIELDS) == set(session["clauses"][0])
    assert set(rec.EXAMPLE_FIELDS) == set(session["examples"][0])
