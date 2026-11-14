"""Strict validator for the JSON-schema subset the IR compiler's schema uses.

`ir_compiler.ir_schema` is the contract an answer must meet (B1 lifts each
question's `answer_schema` from it). This module checks a value against that
contract and nothing looser:

- **An unknown keyword raises** `UnsupportedSchema`. A validator that skips
  keywords it does not understand accepts values the schema forbids; that is
  the default behaviour of general-purpose validators, and it fails open.
- **An object may hold only the properties its schema declares.** The
  compiler's schema does not say `additionalProperties: false`, but an
  undeclared key in an answer can only be a typo or a smuggled field, and
  either way it is not part of the leaf edit the expert is recorded as making.
- **Booleans are not numbers** (Python's `True == 1`), and NaN/infinity are
  refused: the compiler's `_num` cannot write them.

Why not the `jsonschema` package: one more dependency for the eight keywords
below, with the two fail-open defaults above.
"""

from __future__ import annotations

import math
from typing import Any

#: Every keyword `ir_compiler.ir_schema` uses. Anything else raises.
SUPPORTED = frozenset(
    {"type", "enum", "properties", "required", "items", "minItems", "maxItems", "maxLength"}
)


class UnsupportedSchema(ValueError):
    """The schema uses a keyword this validator does not implement."""


def _same(value: Any, member: Any) -> bool:
    """Enum membership without Python's cross-type equality (True == 1)."""
    return type(value) is type(member) and value == member


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate(value: Any, schema: dict, where: str = "answer") -> list[str]:
    """Every way `value` violates `schema`, as readable messages; [] if none.

    Raises `UnsupportedSchema` for a keyword outside `SUPPORTED` or a node
    with neither `type` nor `enum`, because silently accepting is the failure
    this module exists to prevent.
    """
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise UnsupportedSchema(f"{where}: unsupported schema keyword(s) {sorted(unknown)}")

    if "enum" in schema:
        if any(_same(value, m) for m in schema["enum"]):
            return []
        return [f"{where}: {value!r} is not one of {schema['enum']}"]

    kind = schema.get("type")
    if kind == "number":
        return [] if _is_number(value) else [f"{where}: expected a finite number, got {value!r}"]
    if kind == "string":
        if not isinstance(value, str):
            return [f"{where}: expected text, got {value!r}"]
        limit = schema.get("maxLength")
        if limit is not None and len(value) > limit:
            return [f"{where}: {len(value)} characters, at most {limit} allowed"]
        return []
    if kind == "array":
        return _validate_array(value, schema, where)
    if kind == "object":
        return _validate_object(value, schema, where)
    raise UnsupportedSchema(f"{where}: schema node has no supported type or enum: {schema!r}")


def _validate_array(value: Any, schema: dict, where: str) -> list[str]:
    if not isinstance(value, list):
        return [f"{where}: expected a list, got {value!r}"]
    errors = []
    lo, hi = schema.get("minItems"), schema.get("maxItems")
    if lo is not None and len(value) < lo:
        errors.append(f"{where}: {len(value)} item(s), at least {lo} required")
    if hi is not None and len(value) > hi:
        errors.append(f"{where}: {len(value)} item(s), at most {hi} allowed")
    item_schema = schema.get("items")
    if item_schema is None:
        raise UnsupportedSchema(f"{where}: array schema without items")
    for i, item in enumerate(value):
        errors += validate(item, item_schema, f"{where}[{i}]")
    return errors


def _validate_object(value: Any, schema: dict, where: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{where}: expected an object, got {value!r}"]
    props = schema.get("properties", {})
    errors = [f"{where}: unexpected field {k!r}" for k in sorted(set(value) - set(props))]
    errors += [f"{where}: missing field {k!r}" for k in schema.get("required", []) if k not in value]
    for key, sub in props.items():
        if key in value:
            errors += validate(value[key], sub, f"{where}.{key}")
    return errors
