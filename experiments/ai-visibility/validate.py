#!/usr/bin/env python3
"""Dependency-free fixture checks; NOT a security or JSON Schema validator."""
import json
from pathlib import Path

base = Path(__file__).resolve().parent
schema = json.loads((base / "schema/event.schema.json").read_text())
required = set(schema["required"])
allowed = set(schema["properties"])
rows = [json.loads(line) for line in (base / "fixtures/events.jsonl").read_text().splitlines() if line.strip()]
assert rows, "no fixture events"
for row in rows:
    assert required <= row.keys(), f"missing fields: {required - row.keys()}"
    assert row.keys() <= allowed, f"unexpected fields: {row.keys() - allowed}"
    assert row["actor_type"] in schema["properties"]["actor_type"]["enum"]
    assert row["source"] in schema["properties"]["source"]["enum"]
    assert row["correlation_id"]
print(f"PASS: {len(rows)} fixture records structurally checked (not schema-validated)")
