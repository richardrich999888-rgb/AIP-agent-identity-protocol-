"""The published schemas must not drift from the implementation.

A schema nobody checks is documentation that rots. These tests do not
validate documents against the schemas — there is no JSON Schema validator in
the dependency budget, and validating shape would prove nothing about
signatures anyway. What they check is the part that actually goes stale: that
the enum codes, kind codes, domain tags and version numbers written in
``docs/schemas/`` are the ones the code uses.

If someone adds an event kind and forgets the schema, this fails.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vanian_airi import AIRI_EVENT_DOMAIN, AIRI_EVENT_VERSION, AIRI_PARAM_DOMAIN  # noqa: E402
from vanian_airi.events import (  # noqa: E402
    EXECUTION_IDENTITY_DOMAIN,
    AiriEventKind,
    PropagationBoundary,
    ReportedOutcome,
)

SCHEMAS = pathlib.Path(__file__).resolve().parents[3] / "docs" / "schemas"
EVENT_SCHEMA = json.loads((SCHEMAS / "airi-event.schema.json").read_text())
BUNDLE_SCHEMA = json.loads((SCHEMAS / "airi-bundle.schema.json").read_text())
ENCODING = (SCHEMAS / "airi-encoding.md").read_text()


class TestEventSchema(unittest.TestCase):
    def test_every_event_kind_appears_as_a_payload_variant(self) -> None:
        variants = set()
        for branch in EVENT_SCHEMA["properties"]["payload"]["oneOf"]:
            variants.update(branch["properties"].keys())
        expected = {
            "AgentExecutionStarted",
            "ModelInvocationRequested",
            "ModelInvocationObserved",
            "ToolInvocationRequested",
            "ToolExecutionReported",
            "SubprocessExecution",
            "ExecutionCompleted",
            "ExecutionFailed",
            "ExecutionContextPropagated",
        }
        self.assertEqual(variants, expected)
        self.assertEqual(len(variants), len(AiriEventKind))

    def test_the_schema_version_matches_the_code(self) -> None:
        self.assertEqual(EVENT_SCHEMA["properties"]["version"]["const"], AIRI_EVENT_VERSION)

    def test_outcome_enum_matches_the_code(self) -> None:
        names = {o.name.title().replace("_", "") for o in ReportedOutcome}
        for branch in EVENT_SCHEMA["properties"]["payload"]["oneOf"]:
            for body in branch["properties"].values():
                if "outcome" in body.get("properties", {}):
                    self.assertEqual(set(body["properties"]["outcome"]["enum"]), names)

    def test_boundary_enum_matches_the_code(self) -> None:
        names = {"".join(p.capitalize() for p in b.name.split("_")) for b in PropagationBoundary}
        for branch in EVENT_SCHEMA["properties"]["payload"]["oneOf"]:
            body = branch["properties"].get("ExecutionContextPropagated")
            if body:
                self.assertEqual(set(body["properties"]["boundary"]["enum"]), names)

    def test_required_fields_match_what_the_encoder_demands(self) -> None:
        # These are exactly the fields `_check_bounds` and the preimage
        # require. A schema that asked for less would let a producer build an
        # object the Rust verifier refuses.
        self.assertEqual(
            set(EVENT_SCHEMA["required"]),
            {
                "version",
                "agent_id",
                "execution_id",
                "sequence",
                "prev_event_hash",
                "emitted_at_ms",
                "framework",
                "payload",
                "signature",
            },
        )

    def test_the_schema_says_it_is_not_normative(self) -> None:
        # The single most important line in the file. If it is ever dropped,
        # somebody will validate JSON and believe they verified a signature.
        self.assertIn("NON-NORMATIVE", EVENT_SCHEMA["description"])
        self.assertIn("MUST check the preimage", EVENT_SCHEMA["description"])


class TestBundleSchema(unittest.TestCase):
    def test_the_bundle_refuses_an_empty_event_list(self) -> None:
        self.assertEqual(BUNDLE_SCHEMA["properties"]["events"]["minItems"], 1)

    def test_the_bundle_key_is_documented_as_a_claim_not_an_anchor(self) -> None:
        d = BUNDLE_SCHEMA["description"]
        self.assertIn("a claim, not an anchor", d)
        self.assertIn("mismatch is a finding", d)


class TestEncodingDoc(unittest.TestCase):
    def test_domains_match_the_code(self) -> None:
        for domain in (AIRI_EVENT_DOMAIN, AIRI_PARAM_DOMAIN, EXECUTION_IDENTITY_DOMAIN):
            self.assertIn(domain, ENCODING, f"{domain} is missing from airi-encoding.md")

    def test_kind_codes_match_the_code(self) -> None:
        table = dict(re.findall(r"\| `0x(0[1-9])` \| `(\w+)` \|", ENCODING))
        for kind in AiriEventKind:
            code = f"{int(kind):02x}"
            self.assertIn(code, table, f"kind code 0x{code} missing from the doc")
            self.assertEqual(
                table[code],
                kind.name.title().replace("_", ""),
                f"kind code 0x{code} names the wrong kind in the doc",
            )

    def test_the_nexora_package_version_is_stated(self) -> None:
        self.assertIn("package version **2**", ENCODING)

    def test_the_fixed_width_trap_is_documented(self) -> None:
        # This is the defect the parity vectors caught. It must stay written
        # down: it is the one mistake a new port is most likely to repeat.
        self.assertIn("appended raw, not", ENCODING)
        self.assertIn("exe_content_sha256", ENCODING)


if __name__ == "__main__":
    unittest.main(verbosity=2)
