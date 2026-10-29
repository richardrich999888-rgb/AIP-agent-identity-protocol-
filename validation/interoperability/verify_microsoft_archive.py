#!/usr/bin/env python3
"""Reproduce ACS input/receipt correlation with operator-supplied public context.

The result and its request IDs are application reports, not an authority source.
No credentials, signing keys, observer controls or network access are required.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "integrations/interoperability/src"))

from vanian_interop.microsoft_receipts import compare_microsoft_receipt
from vanian_interop.receipts import ReceiptVerifier
from vanian_interop.records import GovernanceEvent, SourceAuthenticity, json_bytes, strict_json


def verify_archive(result: dict, receipts: list[dict], context: dict, verifier: ReceiptVerifier) -> dict:
    references = result.get("governance_requests")
    if not references:
        raise ValueError("no same-run request references; do not infer a join from old archives")
    archived = {json_bytes(receipt) for receipt in receipts}
    comparisons, seen = [], set()
    for reference in references:
        request_id = reference["request_id"]
        if request_id in seen:
            raise ValueError("duplicate application request reference")
        seen.add(request_id)
        events = [e for e in result["microsoft_governance"] if e["event_id"] == request_id]
        if len(events) != 1:
            raise ValueError("exactly one pre-tool governance event required per request")
        raw = events[0]
        event = GovernanceEvent(**{**raw, "authenticity": SourceAuthenticity(**raw["authenticity"])})
        index = reference["receipt_result_index"]
        if type(index) is not int or index < 0:
            raise ValueError("invalid tool result reference")
        signed = result["tool_results"][index]["result"]["_meta"]["vanian"]["signed_receipt"]
        if json_bytes(signed) not in archived:
            raise ValueError("tool response receipt absent from this gateway archive")
        comparisons.append(compare_microsoft_receipt(event, verifier=verifier,
            signed_receipt=signed, expected_request_id=request_id,
            expected_decision_id=reference["decision_id"], **context))
    return {"schema": "vanian.interop.microsoft-archive.v1", "comparisons": comparisons,
        "all_reported_inputs_match": all(c["comparison"] == "AGREEMENT" for c in comparisons),
        "source_authenticity": "APPLICATION_REPORT_NOT_AUTHENTICATED_POLICY_AUTHORITY",
        "anchor_authority": "MUST_BE_ESTABLISHED_EXTERNALLY",
        "institutional_key_custody": "NOT_ESTABLISHED", "kernel_execution": "CANNOT_PROVE"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True, help="Operator-selected tenant, policy and alias context")
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    anchor = strict_json(args.anchor.read_bytes())
    context = strict_json(args.context.read_bytes())
    verifier = ReceiptVerifier(args.verifier, context.pop("tenant"), anchor["gateway_id"],
                               anchor["key_version"], anchor["public_key"])
    result = verify_archive(strict_json(args.result.read_bytes()),
        [strict_json(line) for line in args.receipts.read_bytes().splitlines() if line], context, verifier)
    with args.output.open("xb") as stream:
        stream.write(json_bytes(result) + b"\n")
    print(json_bytes(result).decode())
    return 0 if result["all_reported_inputs_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
