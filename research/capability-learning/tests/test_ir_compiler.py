"""Tests for the constrained capability compiler (pure) and its expressiveness ceiling.

The two hand-filled IRs below are TEST FIXTURES ONLY: they bound what the IR
can express. They are never shown to a proposer model and are not the
benchmark's candidate.
"""
import copy
import json
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "harness"))
from ir_compiler import IRError, compile_ir  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.environ.get("SYNTRIASS_BIN", os.path.join(ROOT, "target/release/syntriass"))


def spec(name):
    s = json.load(open(os.path.join(HERE, "..", "tasks", name)))
    return {**s, "proposed_by": "test:fixture", "demo_ids": []}


NOCORR = {"template": "none", "target": "voltage", "by": "temperature", "reference": 0, "reference_unit": "°C",
          "rate": 0, "rate_unit": "V", "base": 1, "step": 1}
NOLIM = {"template": "none", "coefficient": 0, "input": "voltage", "offset": 0, "unit": "kV"}


def rule(value, op, outcome, number=0, unit="none", against="number", frac=1):
    return {"value": value, "op": op, "against": against, "number": number, "unit": unit, "limit_fraction": frac, "outcome": outcome}


EP114_IR = {
    "topic_terms": ["insulation", "IR", "megger"],
    "inputs": [{"ref": "voltage", "unit": "kV", "cues": []}, {"ref": "resistance", "unit": "MΩ", "cues": []},
               {"ref": "temperature", "unit": "°C", "cues": []}, {"ref": "cued_1", "unit": "none", "cues": ["PI", "polarization index"]}],
    "out_of_scope_terms": ["transformer", "cable", "generator"],
    "out_of_scope_limits": [{"ref": "voltage", "op": ">", "value": 11, "unit": "kV"}],
    "missing_input_outcome": "INSUFFICIENT_INPUT",
    "validity": [{"ref": "temperature", "min": 10, "max": 75, "unit": "°C", "outcome": "INVALID_TEST"}],
    "correction": {"template": "multiply_power_per_degree", "target": "resistance", "by": "temperature", "reference": 40,
                   "reference_unit": "°C", "rate": 0, "rate_unit": "MΩ", "base": 2, "step": 10},
    "limit": {"template": "coefficient_times_input_plus_offset", "coefficient": 10, "input": "voltage", "offset": 1, "unit": "MΩ"},
    "rules": [rule("corrected", "<", "REJECT", against="limit", frac=0.5), rule("corrected", "<", "DRY_OUT", against="limit"),
              rule("cued_1", "<", "DRY_OUT", 1.5), rule("cued_1", "<", "RETEST_30D", 2.0)],
    "default_outcome": "PASS",
}
BT_IR = {
    "topic_terms": ["cell", "float", "battery"],
    "inputs": [{"ref": "voltage", "unit": "V", "cues": []}, {"ref": "temperature", "unit": "°C", "cues": []},
               {"ref": "cued_1", "unit": "none", "cues": ["SG", "specific gravity"]}],
    "out_of_scope_terms": ["lithium", "nickel-cadmium", "NiCd"],
    "out_of_scope_limits": [{"ref": "voltage", "op": ">", "value": 3, "unit": "V"}],
    "missing_input_outcome": "INSUFFICIENT_INPUT",
    "validity": [{"ref": "temperature", "min": 5, "max": 45, "unit": "°C", "outcome": "INVALID_TEST"}],
    "correction": {"template": "add_per_degree", "target": "voltage", "by": "temperature", "reference": 25,
                   "reference_unit": "°C", "rate": 0.003, "rate_unit": "V", "base": 1, "step": 1},
    "limit": NOLIM,
    "rules": [rule("corrected", "<", "REPLACE_CELL", 2.10, "V"), rule("corrected", "<", "EQUALIZE", 2.17, "V"),
              rule("corrected", ">", "REDUCE_FLOAT", 2.30, "V"), rule("cued_1", "<", "EQUALIZE", 1.200)],
    "default_outcome": "ACCEPT",
}


def test_ep114_expressions():
    c = compile_ir(EP114_IR, spec("ir_ep114.json")).capability
    d = {x["name"]: x["expr"] for x in c["procedure"]["derive"]}
    assert d["corrected"] == "resistance * 2.0 ^ ((temperature - 40.0) / 10.0)"
    assert d["limit"] == "10.0 * (voltage + 1.0)"
    assert c["procedure"]["rules"][0] == {"when": "temperature < 10.0 or temperature > 75.0", "outcome": "INVALID_TEST"}
    assert c["procedure"]["rules"][1]["when"] == "corrected < 0.5 * limit"


def test_units_are_converted_to_canonical():
    c = compile_ir(BT_IR, spec("bt_hubt4.json")).capability
    p = c["procedure"]
    assert p["numeric_guards"][0]["when"] == "voltage > 0.003"
    assert p["derive"][0]["expr"] == "voltage + 0.000003 * (temperature - 25.0)"
    assert float(p["rules"][1]["when"].split()[-1]) == 2.10 / 1000.0
    f = copy.deepcopy(BT_IR)
    f["validity"][0].update(min=41, max=113, unit="°F")
    assert compile_ir(f, spec("bt_hubt4.json")).capability["procedure"]["rules"][0]["when"] == "temperature < 5.0 or temperature > 45.0"


def test_threshold_arithmetic_matches_the_parser_at_boundaries():
    # Parser: "2.17 V" -> 2.17 / 1000. The compiled threshold must be the same float.
    c = compile_ir(BT_IR, spec("bt_hubt4.json")).capability
    assert float(c["procedure"]["rules"][2]["when"].split()[-1]) == 2.17 / 1000.0


def test_mechanical_repairs_never_touch_rules():
    a = compile_ir(BT_IR, spec("bt_hubt4.json"))
    stripped = copy.deepcopy(BT_IR)
    stripped["inputs"][2]["cues"] = ["SG", "sg", "specific gravity", "SPECIFIC GRAVITY"][:4]
    b = compile_ir(stripped, spec("bt_hubt4.json"))
    assert a.capability["procedure"]["rules"] == b.capability["procedure"]["rules"]
    assert a.capability["procedure"]["derive"] == b.capability["procedure"]["derive"]
    kinds = {r["kind"] for r in a.repairs}
    assert kinds <= {"cue_case_variants", "applicability_unit_and_cue_terms"}


@pytest.mark.parametrize("mutate, msg", [
    (lambda ir: ir["rules"].append(rule("resistance", "<", "EQUALIZE", 1, "MΩ")), "not a declared input"),
    (lambda ir: ir["inputs"][0].update(unit="MΩ"), "not a voltage unit"),
    (lambda ir: ir["rules"][0].update(outcome="APPROVE_PAYMENT"), "unknown outcome"),
    (lambda ir: ir.update(correction=NOCORR), "correction.template is 'none'"),
    (lambda ir: ir["rules"][0].update(against="limit"), "no limit is defined"),
    (lambda ir: ir["validity"][0].update(min=50, max=10), "min > max"),
    (lambda ir: ir["inputs"].append({"ref": "voltage", "unit": "V", "cues": []}), "declared twice"),
    (lambda ir: ir["inputs"][2].update(cues=[]), "needs at least one cue"),
    (lambda ir: ir["rules"][1].update(unit="MΩ"), "not a voltage unit"),
])
def test_structural_errors_are_rejected_not_repaired(mutate, msg):
    ir = copy.deepcopy(BT_IR)
    mutate(ir)
    with pytest.raises(IRError, match=msg):
        compile_ir(ir, spec("bt_hubt4.json"))


@pytest.mark.skipif(not shutil.which(BIN) and not os.path.exists(BIN), reason="syntriass binary not built")
@pytest.mark.parametrize("ir, task", [(EP114_IR, "ir_ep114.json"), (BT_IR, "bt_hubt4.json")])
def test_expressiveness_ceiling_on_demos(tmp_path, ir, task):
    s = spec(task)
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps(compile_ir(ir, s).capability, ensure_ascii=False))
    cases = tmp_path / "cases.jsonl"
    demos = [json.loads(l) for l in open(os.path.join(HERE, "..", s["data"], "demos.jsonl"))]
    cases.write_text("".join(json.dumps({"id": d["id"], "text": d["text"], "label": d["label"]}) + "\n" for d in demos))
    out = subprocess.run([BIN, "cap-check", "--file", str(cap), "--cases", str(cases)], capture_output=True, text=True, check=True).stdout
    rows = [json.loads(l) for l in out.splitlines()]
    wrong = {r["id"] for r in rows if r["got"] != r["expected"]}
    # Known runtime-parser limit (not the IR): a word between a cue and its
    # number ("SG only 1.185") is not read, so the input is missing.
    known = {"demo-4"} if task == "bt_hubt4.json" else set()
    assert wrong == known, rows


def test_identifier_style_cues_are_respelled_without_changing_rules():
    ir = copy.deepcopy(BT_IR)
    ir["inputs"][2]["cues"] = ["specific_gravity"]
    out = compile_ir(ir, spec("bt_hubt4.json"))
    cues = next(i["cues"] for i in out.capability["procedure"]["inputs"] if i["name"] == "cued_1")
    assert "specific gravity" in cues and "specific_gravity" not in cues
    assert out.capability["procedure"]["rules"] == compile_ir(BT_IR, spec("bt_hubt4.json")).capability["procedure"]["rules"]
    assert any(r["kind"] == "cue_underscore_to_space" for r in out.repairs)
