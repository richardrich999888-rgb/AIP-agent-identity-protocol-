"""P0-050: scope context is distinct from quantity parsing and evidence trust.

These tests require a real prebuilt syntriass binary. Missing prerequisites fail
visibly. The frozen datasets/labels are read unchanged; mutations deliberately
reintroduce broad routing or remove guards to prove the acceptance probes fail.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness"))
import apply_answers as B  # noqa: E402
from ir_compiler import compile_ir  # noqa: E402
from test_exclusion_terms import variant_answers  # noqa: E402
from test_holdout_questions import SPEC, chain as holdout_chain  # noqa: E402

chain = holdout_chain
FULL = "TX-30 11 kV, 260 megohms at 20 C, DAR 1.4"
CELL = "Cell 7 floats at 2.22 V at 25 C with SG 1.215."


@pytest.fixture(scope="module")
def capability(chain):
    draft, _ = chain
    answered = B.apply(draft, SPEC, variant_answers(chain))
    return compile_ir(answered["ir"], {**SPEC, "proposed_by": answered["author"], "demo_ids": []}).capability


@pytest.fixture(scope="module")
def binary():
    path = Path(os.environ.get("SYNTRIASS_BIN", Path(__file__).resolve().parents[3] / "target/debug/syntriass"))
    assert path.is_file(), "NOT READY: build syntriass or set SYNTRIASS_BIN before applicability acceptance"
    return path.resolve()


def execute(binary, tmp_path, cap, text, record=None):
    cp, cases = tmp_path / "cap.json", tmp_path / "cases.jsonl"
    cp.write_text(json.dumps(cap))
    case = {"id": "probe", "text": text, "label": "DIAGNOSTIC"}
    if record is not None:
        case["record"] = record
    cases.write_text(json.dumps(case) + "\n")
    proc = subprocess.run([str(binary), "cap-check", "--file", str(cp), "--cases", str(cases)],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["got"]


@pytest.mark.parametrize("text,expected", [
    (FULL, "ACCEPT"),
    ("distribution transformers 11 kV, 700 megohms at 20 C", "INSUFFICIENT_INPUT"),
    ("distribution transformers 11 kV, 700 megohms, DAR 1.5", "INSUFFICIENT_INPUT"),
    ("11 kV, 700 megohms, DAR 1.5", "INSUFFICIENT_INPUT"),
    ("11 kV, 700 megohms at 20 C, dielectric absorption ratio 1.5", "ACCEPT"),
    ("Cable C-4 11 kV, 700 megohms at 20 C", "OUT_OF_SCOPE"),
    ("dry-type transformer 11 kV, 700 megohms", "OUT_OF_SCOPE"),
    ("11 kV, 700 megohms at 20 C, DAR not measured", "INSUFFICIENT_INPUT"),
    ("11 kV and 12 kV, 700 megohms at 20 C, DAR 1.5", "AMBIGUOUS"),
    ("distribution transformers 11 kV, 700 unrecognized-ohms at 20 C", "INSUFFICIENT_INPUT"),
])
def test_context_missing_exclusion_and_ambiguity_are_distinct(binary, tmp_path, capability, text, expected):
    assert execute(binary, tmp_path, capability, text) == expected


@pytest.mark.parametrize("text", [
    CELL,
    "Sensor 0.00222 kV at 77 F with SG 1.215",
    "Unknown device 2.22 volts at 25 C",
    "Unknown device 11 kV, 700 megohms at 20 C",
    "Unknown device 11000 V, 0.7 GΩ at 68 F",
    "DARWIN 11 kV, 700 megohms at 20 C",
    "xDAR 11 kV, 700 megohms at 20 C",
    "distribution transformersXYZ 11 kV, 700 megohms at 20 C",
    "What are distribution transformers?",
    "Explain DAR",
    "Schedule a cable inspection",
])
def test_unrelated_units_substrings_and_no_measurement_requests_do_not_activate(binary, tmp_path, capability, text):
    assert execute(binary, tmp_path, capability, text) == "NOT_APPLICABLE"


def test_compiled_context_has_no_implicitly_added_unit_terms(capability):
    terms = capability["applicability"]["any_terms"]
    assert not {"V", "volt", "volts", "kV", "megohm", "megohms", "MΩ", "Mohm", "GΩ", "kΩ"} & set(terms)
    assert "distribution transformers" in terms and "DAR" in terms and "cable" in terms


def test_renaming_taught_context_changes_routing_without_equipment_special_cases(binary, tmp_path, chain):
    draft, _ = chain
    ir = B.apply(draft, SPEC, variant_answers(chain))["ir"]
    ir["topic_terms"] = ["invented synthetic device"]
    next(i for i in ir["inputs"] if i["ref"] == "cued_1")["cues"] = ["ZXQ"]
    cap = compile_ir(ir, {**SPEC, "proposed_by": "test:fixture", "demo_ids": []}).capability
    assert execute(binary, tmp_path, cap, FULL) == "NOT_APPLICABLE"
    assert execute(binary, tmp_path, cap, FULL.replace("DAR", "ZXQ")) == "ACCEPT"


def test_missing_signed_evidence_does_not_become_a_missing_input_decision(binary, tmp_path, capability):
    cap = {**capability, "evidence": "signed_record"}
    assert execute(binary, tmp_path, cap, FULL) == "EVIDENCE_REQUIRED"
    assert execute(binary, tmp_path, cap, CELL) == "NOT_APPLICABLE"


def test_untrusted_evidence_does_not_fall_back_to_plaintext(binary, tmp_path, capability):
    cap = {**capability, "evidence": "signed_record"}
    record = {"record_id": "forged", "tenant": SPEC["tenant"], "asset_id": "synthetic",
              "instrument_id": "unknown", "taken_at_ms": 1,
              "quantities": [{"physical": {"reading": "11 kV"}}], "signature_hex": "00" * 64}
    assert execute(binary, tmp_path, cap, FULL, record).startswith("FAILED:record rejected:")


@pytest.mark.parametrize("mutation,text,expected", [
    ("restore_unit_scope", CELL, "NOT_APPLICABLE"),
    ("drop_measurement_gate", "distribution transformers", "NOT_APPLICABLE"),
    ("drop_exclusions", "Cable 11 kV, 700 megohms at 20 C, DAR 1.5", "OUT_OF_SCOPE"),
    ("remove_evidence_requirement", FULL, "EVIDENCE_REQUIRED"),
])
def test_mutations_are_killed_by_behavioral_probes(binary, tmp_path, capability, mutation, text, expected):
    original = copy.deepcopy(capability)
    if mutation == "remove_evidence_requirement":
        original["evidence"] = "signed_record"
    assert execute(binary, tmp_path, original, text) == expected
    mutated = copy.deepcopy(original)
    if mutation == "restore_unit_scope":
        mutated["applicability"]["any_terms"].append("V")
    elif mutation == "drop_measurement_gate":
        mutated["applicability"]["min_inputs_present"] = 0
    elif mutation == "drop_exclusions":
        mutated["procedure"]["text_guards"] = []
    else:
        mutated["evidence"] = "text"
    assert execute(binary, tmp_path, mutated, text) != expected
