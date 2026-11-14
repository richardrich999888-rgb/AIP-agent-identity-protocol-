"""No implicit scope widening, guessing, or bypass of the teaching bindings."""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness"))
import apply_answers as B  # noqa: E402
import exclusion_terms as E  # noqa: E402
import record_answers as RA  # noqa: E402
import record_holdout as H  # noqa: E402
from test_holdout_questions import SPEC, chain as holdout_chain, owner  # noqa: E402

chain = holdout_chain


@pytest.mark.parametrize("pair", E.PAIRS)
@pytest.mark.parametrize("reverse", [False, True])
def test_each_reviewed_pair_requires_its_cited_form(pair, reverse):
    source, other = pair[::-1] if reverse else pair
    quote = f"Does not apply to {source.upper()}."
    assert E.offered(quote) == [{"source_term": source.upper(), "term": other, "policy": E.POLICY}]
    assert E.errors([source, other.upper()], quote) == []
    assert "requires keeping" in E.errors([other], quote)[0]


@pytest.mark.parametrize("word", ["switchgear", "wirings", "cabl", "cabling", "motorized", "s", "cable motors"])
def test_unsupported_exclusions_are_not_inferred(word):
    assert E.errors(["cables", "motors", word], "Does not apply to cables or motors.")


@pytest.mark.parametrize("quote", ["motorcycle", "cables123", "xcables", "cables_", "cablés", "gases"])
def test_substrings_and_unknown_vocabulary_offer_nothing(quote):
    assert E.offered(quote) == []


def test_dry_type_qualifier_cannot_be_dropped_by_word_form_policy():
    assert E.offered("No dry-type transformers") == [
        {"source_term": "dry-type transformers", "term": "dry-type transformer", "policy": E.POLICY}]
    assert E.errors(["dry-type transformers", "transformer"], "No dry-type transformers")


@pytest.mark.parametrize("path,answer", [
    ("scope_subject.*", ["motors", "motor"]),
    ("required_inputs.*", [{"ref": "cued_1", "unit": "none", "cues": ["motors", "motor"]}]),
])
def test_variants_cannot_authorize_subjects_or_input_cues(path, answer):
    assert B._copied_words(path, answer, "motors")


def variant_answers(chain):
    draft, questions = chain
    table = copy.deepcopy(H.AS_INSTRUCTED)
    for i, (path, quote, value, reason) in enumerate(table):
        if path == "scope_exclusion_terms.*":
            table[i] = (path, quote, value + [c["term"] for c in owner(chain)["exclusion_word_forms"]],
                        "Explicitly select the offered exclusion forms; retain the quoted forms.")
    return RA.answers_file(draft, questions, table, 1)


def test_explicit_selection_preserves_quoted_terms_and_records_provenance(chain):
    draft, questions = chain
    before = copy.deepcopy(draft)
    out = B.apply(draft, SPEC, variant_answers(chain))
    assert out["status"] == "COMPILES"
    assert out["model_calls"] == 0
    q = owner(chain)
    selected = [e for e in out["edits"] if e.get("provenance")]
    assert len(selected) == 4
    for edit in selected:
        assert edit["qid"] == q["qid"]
        assert edit["provenance"]["citation"] == q["citation"]
        assert edit["provenance"]["policy"] == E.POLICY
        assert edit["provenance"]["source_term"] in out["ir"]["out_of_scope_terms"]
        assert edit["after"] == edit["provenance"]["term"]
    assert draft == before
    assert out["questions_sha256"] == B.questions_digest(questions)


def test_copied_answer_is_not_silently_expanded(chain):
    draft, questions = chain
    out = B.apply(draft, SPEC, RA.answers_file(draft, questions, H.AS_INSTRUCTED, 1))
    assert out["ir"]["out_of_scope_terms"] == H.EXCLUSION_ALTERNATIVES["copied_as_written"]
    assert not any(e.get("provenance") for e in out["edits"])


def test_policy_and_choices_are_bound_to_the_answers_digest(chain):
    draft, questions = chain
    doc = variant_answers(chain)
    forged = copy.deepcopy(questions)
    owner((draft, forged))["exclusion_word_forms"].append(
        {"source_term": "cables", "term": "switchgear", "policy": E.POLICY})
    doc["questions_sha256"] = B.questions_digest(forged)
    with pytest.raises(ValueError, match="different questions"):
        B.apply(draft, SPEC, doc)


def test_removing_paired_source_refuses_the_entire_file(chain):
    draft, _ = chain
    doc = variant_answers(chain)
    entry = next(a for a in doc["answers"] if a["qid"] == owner(chain)["qid"])
    entry["answer"].remove("cables")
    before = copy.deepcopy(draft)
    with pytest.raises(B.AnswersRefused) as error:
        B.apply(draft, SPEC, doc)
    assert "requires keeping quoted term 'cables'" in str(error.value.errors)
    assert draft == before


def test_questions_describe_matching_and_variant_limits(chain):
    q = owner(chain)
    assert q["exclusion_word_form_policy"] == E.POLICY
    assert q["exclusion_word_forms"] == E.offered(q["quote"])
    assert "No variant is added automatically" in q["question"]
    assert "literal and whole-word" in q["answer_note"]
    assert "at most 32 characters" in q["question"]
    assert all("exclusion_word_forms" not in other for other in chain[1]["questions"]
               if other["field_path"] != "scope_exclusion_terms.*")
