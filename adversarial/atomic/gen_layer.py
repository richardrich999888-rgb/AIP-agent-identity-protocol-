#!/usr/bin/env python3
"""Phase 4 — generate an ATT&CK Navigator layer from the AIP coverage map.

# What this produces, and what it does not

It reads `coverage.tsv` (the auditable technique->coverage map in this
directory) and emits a MITRE ATT&CK Navigator layer JSON, colouring each
technique by the AIP observer's *coverage class*:

  attributed      green   the observer records the primitive and binds it to
                          a process instance (strongest).
  effect-observed amber   the effect is recorded; attribution may be partial.
  not-covered     grey    no AIP sensor observes the primitive. Shown, not
                          hidden: a coverage map with no grey is a lie.

It does NOT execute any atomic and it emits no "verdict". A verdict is the
result of executing a technique and reconciling it against a signed
expectation; that only happened for the primitives demonstrated live in
Phase 1 (`evidence == phase1-sealed`). Everything else is a statement about
what the sensor architecture can observe, cited to `atomics/<ID>/` in the
pinned Atomic Red Team corpus for reproduction — never a claim it ran here.

Determinism: techniques are sorted by technique id and the JSON is emitted
with sorted keys and a fixed indent, so the same map always produces
byte-identical output (an auditor diffs two layers meaningfully).

Usage:
    gen_layer.py [coverage.tsv] > aip-attack-coverage.layer.json
Exit:
    0  layer written
    2  the map could not be read or a row was malformed
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Coverage class -> (Navigator colour, score, human label). Fixed, not derived,
# so the palette cannot drift between runs.
CLASS_STYLE: dict[str, tuple[str, int, str]] = {
    "attributed": ("#2e7d32", 3, "Attributed: primitive recorded and bound to a process instance"),
    "effect-observed": ("#f9a825", 2, "Effect observed: recorded, attribution may be partial"),
    "not-covered": ("#9e9e9e", 0, "Not covered: no AIP sensor observes this primitive"),
}

# ATT&CK / Navigator versions this layer targets. Stable identifiers, not
# fetched at runtime; bump deliberately when the corpus mapping is revised.
ATTACK_VERSION = "15"
NAVIGATOR_VERSION = "4.9.5"
LAYER_VERSION = "4.5"


class MapError(Exception):
    """A coverage row that cannot be trusted; never silently skipped."""


def parse_rows(text: str) -> list[dict[str, str]]:
    """Parse the tab-separated coverage map into validated rows.

    Blank lines and `#` comments are ignored. Every data row must have exactly
    six tab-separated fields and a known coverage class, or the whole parse
    fails — a half-read map would produce a layer that lies by omission.
    """
    rows: list[dict[str, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            raise MapError(f"line {i}: expected 6 tab-separated fields, got {len(parts)}")
        tid, tactic, name, primitive, cls, evidence = (p.strip() for p in parts)
        if cls not in CLASS_STYLE:
            raise MapError(f"line {i}: unknown coverage class {cls!r}")
        if not tid.startswith("T"):
            raise MapError(f"line {i}: technique id {tid!r} does not look like an ATT&CK id")
        rows.append(
            {
                "technique_id": tid,
                "tactic": tactic,
                "name": name,
                "primitive": primitive,
                "class": cls,
                "evidence": evidence,
            }
        )
    if not rows:
        raise MapError("no data rows in coverage map")
    return rows


def technique_entry(row: dict[str, str]) -> dict[str, object]:
    """One Navigator technique object for a coverage row."""
    color, score, _label = CLASS_STYLE[row["class"]]
    comment = (
        f"{row['class']} via {row['primitive']}; evidence={row['evidence']}; "
        f"corpus=atomics/{row['technique_id']}/"
    )
    return {
        "techniqueID": row["technique_id"],
        "tactic": row["tactic"],
        "score": score,
        "color": color,
        "comment": comment,
        "enabled": True,
        "metadata": [
            {"name": "aip_coverage_class", "value": row["class"]},
            {"name": "aip_primitive", "value": row["primitive"]},
            {"name": "aip_evidence", "value": row["evidence"]},
        ],
    }


def build_layer(rows: list[dict[str, str]]) -> dict[str, object]:
    """Assemble the full Navigator layer. Pure over `rows`; deterministic."""
    techniques = [technique_entry(r) for r in sorted(rows, key=lambda r: r["technique_id"])]
    legend = [
        {"label": label, "color": color}
        for color, _score, label in (CLASS_STYLE[c] for c in ("attributed", "effect-observed", "not-covered"))
    ]
    return {
        "name": "AIP observer coverage vs Atomic Red Team (ATT&CK)",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            "AIP kernel-observer coverage by technique, coloured by coverage "
            "class (attributed / effect-observed / not-covered). This is a "
            "capability map, not a run log: it asserts what the observer's "
            "sensors record, not that each atomic executed. Verdicts exist "
            "only for primitives demonstrated live (evidence=phase1-sealed)."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#9e9e9e", "#f9a825", "#2e7d32"],
            "minValue": 0,
            "maxValue": 3,
        },
        "legendItems": legend,
        "sorting": 0,
        "hideDisabled": False,
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def render(layer: dict[str, object]) -> str:
    """Byte-stable JSON: sorted keys, fixed indent, trailing newline."""
    return json.dumps(layer, sort_keys=True, indent=2) + "\n"


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else HERE / "coverage.tsv"
    try:
        rows = parse_rows(path.read_text())
    except (OSError, MapError) as e:
        print(f"gen_layer: {e}", file=sys.stderr)
        return 2
    sys.stdout.write(render(build_layer(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
