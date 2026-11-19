#!/usr/bin/env python3
"""Tests for the strict schema-subset validator answers are checked with."""
import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "research/capability-learning/harness"))

import schema_subset as S  # noqa: E402
from ir_compiler import ir_schema  # noqa: E402

SPEC = json.loads((ROOT / "research/capability-learning/tasks/ir_ep114.json").read_text())
MODEL_IR = ROOT / "research/capability-learning/results/v02/attempt3_ir/ir.json"


def _keywords(node):
    if isinstance(node, dict):
        yield from (k for k in node if k != "properties")
        for k, v in node.items():
            if k == "properties":
                for sub in v.values():
                    yield from _keywords(sub)
            elif isinstance(v, dict):
                yield from _keywords(v)


def test_every_keyword_the_compiler_schema_uses_is_supported():
    # If ir_schema grows a keyword, this fails before the validator can skip it.
    assert set(_keywords(ir_schema(SPEC["outcomes"]))) <= S.SUPPORTED


def test_a_real_ir_the_compiler_accepted_is_valid():
    assert S.validate(json.loads(MODEL_IR.read_text()), ir_schema(SPEC["outcomes"]), "ir") == []


@pytest.mark.parametrize("value", [0, 1.5, -3, 10**6])
def test_numbers(value):
    assert S.validate(value, {"type": "number"}) == []


@pytest.mark.parametrize("value", [True, False, "1", None, math.nan, math.inf, -math.inf])
def test_not_numbers(value):
    assert S.validate(value, {"type": "number"})


def test_enum_membership_is_type_strict():
    assert S.validate("PASS", {"enum": ["PASS"]}) == []
    assert S.validate("pass", {"enum": ["PASS"]})
    assert S.validate(True, {"enum": [1]}), "True == 1 in Python; not here"


def test_string_length_is_bounded():
    assert S.validate("a" * 32, {"type": "string", "maxLength": 32}) == []
    assert S.validate("a" * 33, {"type": "string", "maxLength": 32})
    assert S.validate(5, {"type": "string"})


def test_array_bounds_and_items():
    sch = {"type": "array", "items": {"type": "number"}, "minItems": 1, "maxItems": 2}
    assert S.validate([1], sch) == []
    assert S.validate([], sch) == ["answer: 0 item(s), at least 1 required"]
    assert S.validate([1, 2, 3], sch) == ["answer: 3 item(s), at most 2 allowed"]
    assert S.validate([1, "x"], sch) == ["answer[1]: expected a finite number, got 'x'"]
    assert S.validate("x", sch)


def test_objects_hold_only_declared_fields_and_all_required_ones():
    sch = {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}, "required": ["a"]}
    assert S.validate({"a": 1}, sch) == []
    assert S.validate({"a": 1, "c": 2}, sch) == ["answer: unexpected field 'c'"]
    assert S.validate({"b": 1}, sch) == ["answer: missing field 'a'"]
    assert S.validate([], sch)


def test_nested_errors_name_their_place():
    errs = S.validate({"rules": [{"x": 1}]}, {"type": "object", "properties": {"rules": {
        "type": "array", "items": {"type": "object", "properties": {"x": {"type": "string"}}}}}})
    assert errs == ["answer.rules[0].x: expected text, got 1"]


def test_an_unknown_keyword_raises_rather_than_being_skipped():
    with pytest.raises(S.UnsupportedSchema, match="pattern"):
        S.validate("x", {"type": "string", "pattern": "^y$"})


def test_a_node_without_type_or_enum_raises():
    with pytest.raises(S.UnsupportedSchema):
        S.validate("x", {})


def test_an_array_schema_without_items_raises():
    with pytest.raises(S.UnsupportedSchema):
        S.validate([1], {"type": "array"})
