#!/usr/bin/env python3
"""Unit tests for gen_layer.py — happy path, edge cases, failure modes.

Run: python3 gen_layer_test.py   (exit 0 = all passed, 1 = a failure)
No third-party test runner: stdlib asserts, matching this tree's harness style.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import gen_layer as g

HERE = Path(__file__).resolve().parent


def _rows(text: str):
    return g.parse_rows(text)


def test_parse_ignores_comments_and_blanks() -> None:
    text = "# header\n\nT1059\texecution\tShell\tprocess_exec\tattributed\tphase1-sealed\n"
    rows = _rows(text)
    assert len(rows) == 1, rows
    assert rows[0]["technique_id"] == "T1059"


def test_parse_rejects_wrong_field_count() -> None:
    try:
        _rows("T1059\texecution\tShell\tprocess_exec\tattributed\n")  # 5 fields
    except g.MapError:
        return
    raise AssertionError("a short row must be rejected, not padded")


def test_parse_rejects_unknown_class() -> None:
    try:
        _rows("T1059\texecution\tShell\tprocess_exec\tmostly\tphase1-sealed\n")
    except g.MapError:
        return
    raise AssertionError("an unknown coverage class must be rejected")


def test_parse_rejects_non_attack_id() -> None:
    try:
        _rows("X9\texecution\tShell\tprocess_exec\tattributed\tphase1-sealed\n")
    except g.MapError:
        return
    raise AssertionError("a non-ATT&CK id must be rejected")


def test_empty_map_is_an_error() -> None:
    try:
        _rows("# only comments\n")
    except g.MapError:
        return
    raise AssertionError("an empty map must fail, not emit an empty layer")


def test_class_colours_are_fixed_and_distinct() -> None:
    colors = {c: style[0] for c, style in g.CLASS_STYLE.items()}
    assert len(set(colors.values())) == 3, "each class must have a distinct colour"
    assert colors["attributed"] == "#2e7d32"
    assert colors["not-covered"] == "#9e9e9e"


def test_layer_is_sorted_and_byte_stable() -> None:
    text = (
        "T1071\tcommand-and-control\tALP\tsocket_connect\teffect-observed\tphase1-sealed\n"
        "T1059\texecution\tShell\tprocess_exec\tattributed\tphase1-sealed\n"
    )
    rows = _rows(text)
    layer = g.build_layer(rows)
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == ["T1059", "T1071"], f"techniques must be sorted by id: {ids}"
    # Byte-stable across two independent builds.
    assert g.render(g.build_layer(rows)) == g.render(g.build_layer(list(reversed(rows))))


def test_not_covered_is_present_and_scored_zero() -> None:
    text = "T1620\tdefense-evasion\tReflective Code Loading\tnone\tnot-covered\tblind-spot\n"
    layer = g.build_layer(_rows(text))
    t = layer["techniques"][0]
    assert t["score"] == 0
    assert t["color"] == "#9e9e9e"
    assert "not-covered" in t["comment"]


def test_valid_navigator_shape() -> None:
    layer = g.build_layer(_rows("T1059\texecution\tShell\tprocess_exec\tattributed\tphase1-sealed\n"))
    for key in ("name", "versions", "domain", "techniques", "gradient", "legendItems"):
        assert key in layer, f"missing Navigator key {key}"
    assert layer["domain"] == "enterprise-attack"
    # round-trips as JSON
    json.loads(g.render(layer))


def test_the_committed_map_builds_and_reflects_blind_spots() -> None:
    rows = _rows((HERE / "coverage.tsv").read_text())
    layer = g.build_layer(rows)
    classes = {m["value"] for t in layer["techniques"] for m in t["metadata"] if m["name"] == "aip_coverage_class"}
    assert {"attributed", "effect-observed", "not-covered"} <= classes, (
        "the real map must contain all three classes, including honest blind spots"
    )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
