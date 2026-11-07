#!/usr/bin/env python3
"""Tests for the shared "does this IR compile" check (A3a and B2)."""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "research/capability-learning/harness"))

import ir_check as C  # noqa: E402

SPEC = json.loads((ROOT / "research/capability-learning/tasks/ir_ep114.json").read_text())
MODEL_IR = json.loads((ROOT / "research/capability-learning/results/v02/attempt3_ir/ir.json").read_text())


def test_an_ir_the_compiler_accepted_compiles():
    assert C.check_ir(MODEL_IR, SPEC) == {"schema_errors": [], "compiles": True, "compile_error": None}


def test_the_bare_task_spec_is_enough():
    # Regression: compile_ir reads spec["proposed_by"] after validating the
    # IR; with the bare task spec every IR "failed" with KeyError.
    assert "proposed_by" not in SPEC
    assert C.check_ir(MODEL_IR, SPEC)["compiles"] is True


def test_an_ir_without_rules_does_not_compile_even_though_compile_ir_would_accept_it():
    ir = copy.deepcopy(MODEL_IR)
    ir["rules"] = []
    out = C.check_ir(ir, SPEC)
    assert out["compiles"] is False
    assert out["schema_errors"] == ["ir.rules: 0 item(s), at least 1 required"]
    assert out["compile_error"] == C.NOT_ATTEMPTED


def test_a_compiler_error_is_reported_as_one():
    ir = copy.deepcopy(MODEL_IR)
    ir["correction"]["template"] = "none"  # rules still use 'corrected'
    out = C.check_ir(ir, SPEC)
    assert out["schema_errors"] == [] and out["compiles"] is False
    assert "'corrected' but correction.template is 'none'" in out["compile_error"]


def test_the_check_proposer_names_no_person():
    assert C.CHECK_PROPOSER.startswith("check-only:")
