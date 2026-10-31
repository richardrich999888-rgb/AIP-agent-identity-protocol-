"""Unit tests for the atomic-claim pipeline (pure parts). Dev families only."""
import os
import sys
from fractions import Fraction

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "harness"))
import atomic as A  # noqa: E402
from ir_compiler import compile_ir, provenance_check  # noqa: E402

DATA = os.path.join(HERE, "..", "data")
IR_OUT = ["PASS", "RETEST_30D", "DRY_OUT", "REJECT", "INVALID_TEST", "OUT_OF_SCOPE", "INSUFFICIENT_INPUT"]
SPEC = {"outcomes": IR_OUT, "capability_id": "t", "intended_task": "t", "tenant": "t", "clearance": "restricted",
        "domain": "d", "doc_id": "ep-114", "policy_version": "p", "proposed_by": "test"}


def doc(path):
    return open(os.path.join(DATA, path)).read().split("\n", 1)[1]


EP = doc("ir-tasks-v1/corpus/koravi-ep-114.txt")
CL = {c.cid: c for c in A.segment(EP)}


def by_text(prefix):
    return next(c for c in CL.values() if c.text.startswith(prefix))


# ── segmentation and typed numbers ──

def test_segment_spans_are_exact_citations():
    for c in CL.values():
        assert EP[c.start:c.end] == c.text


def test_decimals_do_not_split_sentences():
    bt = A.segment(doc("bt-tasks-v1/corpus/halvorn-hu-bt-4.txt"))
    assert any("below 2.10 volts" in c.text for c in bt)


def test_numbers_are_typed_and_section_numbers_excluded():
    nums = A.clause_numbers("Step 1 validity: between 10 and 75 degrees Celsius")
    assert [(float(n.value), n.unit) for n in nums] == [(10.0, "none"), (75.0, "°C")]


def test_fraction_and_number_words_are_exact():
    nums = A.clause_numbers("below one third of the minimum, two raised")
    assert Fraction(1, 3) in [n.value for n in nums] and Fraction(2) in [n.value for n in nums]
    assert not any(n.value == 1 for n in nums)  # "one" of "one third" is not a separate number


def test_identifier_digits_are_not_numbers():
    assert A.clause_numbers("procedure EP-114 revision C") == []


def test_number_enum_rejects_unstated_constants_by_construction():
    sch = A.claim_schema("decision_rule", by_text("If PI is at least"), IR_OUT)
    allowed = sch["properties"]["conditions"]["items"]["properties"]["number"]["enum"]
    assert set(allowed) == {0.0, 1.0, 1.5, 2.0, 30.0}


# ── lexicons ──

def test_comparators_in_order_longest_phrase_wins():
    assert [op for _, op in A.comparators("If PI is at least 1.5 but below 2.0")] == [">=", "<"]
    assert [op for _, op in A.comparators("rated up to and including 11 kV")] == ["<="]


def test_outcome_match_unique_and_day_tokens():
    assert A.outcome_match("dry out the winding and retest", IR_OUT) == ["DRY_OUT"]
    assert A.outcome_match("accept for service with a retest in 30 days", IR_OUT) == ["RETEST_30D"]
    assert A.outcome_match("Confidential.", IR_OUT) == []


# ── verification: evidence, repair, hypothesis, issue ──

def test_wrong_op_is_repaired_when_clause_determines_it():
    c = by_text("If it is below the minimum")
    v = A.verify_claim("decision_rule", {"conditions": [{"subject": "corrected", "op": ">", "against": "limit", "number": 1}],
                                         "outcome": "DRY_OUT"}, c, IR_OUT, {"cues": {"cued_1": ["PI"]}, "prev_subject": "corrected"})
    assert v.claim["conditions"][0]["op"] == "<" and v.fields["conditions[0].op"] == "repaired" and not v.issues


def test_pronoun_subject_resolves_to_previous_rule():
    c = by_text("If it is below the minimum")
    v = A.verify_claim("decision_rule", {"conditions": [{"subject": "resistance", "op": "<", "against": "limit", "number": 1}],
                                         "outcome": "DRY_OUT"}, c, IR_OUT, {"cues": {}, "prev_subject": "corrected"})
    assert v.claim["conditions"][0]["subject"] == "corrected"


def test_unsupported_term_is_removed_and_recorded():
    c = by_text("This procedure does not apply")
    v = A.verify_claim("scope_exclusion_terms", {"terms": ["cables", "pumps"]}, c, IR_OUT, {})
    assert v.claim["terms"] == ["cables"] and v.repairs


def test_condition_count_follows_the_clause_comparators():
    c = by_text("If PI is at least")
    v = A.verify_claim("decision_rule", {"conditions": [{"subject": "cued_1", "op": "<", "against": "number", "number": 2.0}],
                                         "outcome": "RETEST_30D"}, c, IR_OUT, {"cues": {"cued_1": ["PI"]}})
    assert not v.issues
    assert [(x["op"], x["number"]) for x in v.claim["conditions"]] == [(">=", 1.5), ("<", 2.0)]
    assert any(r["field"] == "conditions" for r in v.repairs)


def test_unsupported_condition_count_without_comparators_is_an_issue():
    c = by_text("Otherwise pass")
    v = A.verify_claim("decision_rule", {"conditions": [{"subject": "cued_1", "op": "<", "against": "number", "number": 0.0}],
                                         "outcome": "PASS"}, c, IR_OUT, {"cues": {}})
    assert v.issues


def test_abbreviation_defines_cues_uniquely():
    c = by_text("Required inputs")
    v = A.verify_claim("required_inputs", {"inputs": [{"ref": "cued_1", "unit": "none", "cues": ["insulation resistance"]}]},
                       c, IR_OUT, {})
    refs = {i["ref"]: i for i in v.claim["inputs"]}
    assert set(refs) == {"voltage", "resistance", "temperature", "cued_1"}
    assert refs["cued_1"]["cues"] == ["PI", "polarization index"] and not v.issues


def test_limit_template_from_wording():
    c = by_text("Step 3 minimum")
    v = A.verify_claim("limit", {"template": "constant", "coefficient": 10, "input": "voltage", "offset": 1}, c, IR_OUT, {})
    assert v.claim["template"] == "coefficient_times_input_plus_offset" and v.fields["template"] == "repaired"


def test_ambiguous_multiply_numbers_stay_hypotheses_unless_pattern_fixes_them():
    c = by_text("Step 2 temperature correction")
    v = A.verify_claim("correction", {"template": "multiply_power_per_degree", "target": "resistance", "by": "temperature",
                                      "reference": 40, "rate": 0, "base": 2, "step": 10}, c, IR_OUT, {})
    assert v.fields["base"] == "evidence" and v.fields["step"] == "evidence" and not v.issues


# ── assembly, precedence, consistency ──

def ideal_claims():
    r = lambda subj, op, ag, n, out: {"conditions": [{"subject": subj, "op": op, "against": ag, "number": n}], "outcome": out}
    return [
        {"kind": "scope_subject", "claim": {"terms": ["induction motors"]}, "clause": "a"},
        {"kind": "scope_limit", "claim": {"ref": "voltage", "op": "<=", "value": 11, "meaning": "in_scope_when_true", "unit": "kV"}, "clause": "b"},
        {"kind": "scope_exclusion_terms", "claim": {"terms": ["transformers", "cables", "generators"]}, "clause": "c"},
        {"kind": "required_inputs", "claim": {"inputs": [{"ref": "voltage", "unit": "kV", "cues": []},
                                                          {"ref": "resistance", "unit": "MΩ", "cues": []},
                                                          {"ref": "temperature", "unit": "°C", "cues": []},
                                                          {"ref": "cued_1", "unit": "none", "cues": ["PI"]}]}, "clause": "d"},
        {"kind": "missing_input", "claim": {"outcome": "INSUFFICIENT_INPUT"}, "clause": "e"},
        {"kind": "validity", "claim": {"ref": "temperature", "min": 10, "max": 75, "unit": "°C", "outcome": "INVALID_TEST"}, "clause": "f"},
        {"kind": "correction", "claim": {"template": "multiply_power_per_degree", "target": "resistance", "by": "temperature",
                                         "reference": 40, "reference_unit": "°C", "rate": 0, "rate_unit": "°C", "base": 2, "step": 10}, "clause": "g"},
        {"kind": "limit", "claim": {"template": "coefficient_times_input_plus_offset", "coefficient": 10, "input": "voltage",
                                    "offset": 1, "unit": "MΩ"}, "clause": "h"},
        {"kind": "decision_rule", "claim": r("corrected", "<", "limit", 0.5, "REJECT"), "clause": "i"},
        {"kind": "decision_rule", "claim": r("corrected", "<", "limit", 1, "DRY_OUT"), "clause": "j"},
        {"kind": "decision_rule", "claim": r("cued_1", "<", "number", 1.5, "DRY_OUT"), "clause": "k"},
        {"kind": "decision_rule", "claim": {"conditions": [{"subject": "cued_1", "op": ">=", "against": "number", "number": 1.5},
                                                           {"subject": "cued_1", "op": "<", "against": "number", "number": 2.0}],
                                            "outcome": "RETEST_30D"}, "clause": "l"},
        {"kind": "default_outcome", "claim": {"outcome": "PASS"}, "clause": "m"},
    ]


def test_precedence_drops_implied_lower_bound_and_compiles():
    ir, simp, issues = A.assemble(ideal_claims())
    assert not issues and len(simp) == 1 and simp[0]["dropped_condition"]["op"] == ">="
    assert ir["out_of_scope_limits"] == [{"ref": "voltage", "op": ">", "value": 11, "unit": "kV"}]
    compile_ir(ir, SPEC)
    assert provenance_check(ir, EP) == []
    assert A.consistency(ir, IR_OUT, ["REJECT", "DRY_OUT", "RETEST_30D", "PASS"]) == []


def test_unreduced_conjunction_is_an_issue():
    cl = ideal_claims()
    cl[11]["claim"]["conditions"][0]["number"] = 1.4  # lower bound no longer implied
    _, _, issues = A.assemble(cl)
    assert any("conjunction" in i["issue"] for i in issues)


def test_consistency_detects_unreachable_and_contradiction():
    ir, _, _ = A.assemble(ideal_claims())
    ir["rules"].insert(0, {"value": "cued_1", "op": "<", "against": "number", "number": 3.0, "unit": "none",
                           "limit_fraction": 1, "outcome": "DRY_OUT"})
    ir["rules"].append({"value": "cued_1", "op": "<", "against": "number", "number": 3.0, "unit": "none",
                        "limit_fraction": 1, "outcome": "REJECT"})
    issues = [i["issue"] for i in A.consistency(ir, IR_OUT, [])]
    assert any("unreachable" in i for i in issues) and any("contradicts" in i for i in issues)


def test_missing_default_is_reported_not_invented():
    _, _, issues = A.assemble([c for c in ideal_claims() if c["kind"] != "default_outcome"])
    assert any("default_outcome" in i["issue"] for i in issues)


def test_unreachable_document_outcome_is_reported():
    ir, _, _ = A.assemble([c for c in ideal_claims() if c["clause"] != "l"])
    assert any(i.get("outcome") == "RETEST_30D" for i in A.consistency(ir, IR_OUT, ["RETEST_30D"]))


# ── boundary probes and reference semantics ──

def test_reference_evaluator_matches_expert_working():
    ir, _, _ = A.assemble(ideal_claims())
    # 6.6 kV, 40 MΩ at 40 °C, PI 2.3: limit 10*(7.6)=76, 40 < 76 and >= 38 -> DRY_OUT
    assert A.evaluate_ir(ir, {"voltage": 6.6, "resistance": 40, "temperature": 40, "cued_1": 2.3}) == "DRY_OUT"
    assert A.evaluate_ir(ir, {"voltage": 6.6, "resistance": 37, "temperature": 40, "cued_1": 2.3}) == "REJECT"
    assert A.evaluate_ir(ir, {"voltage": 12, "resistance": 900, "temperature": 40, "cued_1": 2.3}) == "OUT_OF_SCOPE"
    assert A.evaluate_ir(ir, {"voltage": 6.6, "resistance": None, "temperature": 40, "cued_1": 2.3}) == "INSUFFICIENT_INPUT"


def test_boundary_points_are_deterministic_and_cover_every_threshold():
    ir, _, _ = A.assemble(ideal_claims())
    a, b = A.boundary_points(ir), A.boundary_points(ir)
    assert a == b
    probes = {p["probe"].rsplit(" ", 1)[0] for p in a}
    assert {"scope_limit[0]", "validity[0].min", "validity[0].max", "rule[0]", "rule[1]", "rule[2]", "rule[3]"} <= probes
    assert sum(p["probe"].startswith("missing") for p in a) == 4
    outs = {A.evaluate_ir(ir, p["inputs"]) for p in a}
    assert {"OUT_OF_SCOPE", "INVALID_TEST", "REJECT", "DRY_OUT", "RETEST_30D", "INSUFFICIENT_INPUT"} <= outs


def test_render_uses_parser_units_and_cues():
    ir, _, _ = A.assemble(ideal_claims())
    t = A.render(ir, {"voltage": 6.6, "resistance": 40, "temperature": 40, "cued_1": 2.3}, "motor")
    assert t == "motor: 6.6 kV, 40 MΩ, 40 °C, PI 2.3."


@pytest.mark.parametrize("kind", [k for k in A.KINDS if k != "none"])
def test_every_kind_has_a_closed_schema(kind):
    s = A.claim_schema(kind, by_text("Step 4 decision"), IR_OUT)
    assert s["type"] == "object" and s["required"]
