"""Adversarial checks against a real archived ACS/gateway operation.

Requires the pinned native ACS SDK and built Rust verifier; never substitutes a
mock policy engine, receipt signature or canonicalizer when either is absent.
"""
import copy
from dataclasses import replace
import os
from pathlib import Path
import sys

import pytest
from agent_control_specification import action_identity

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_microsoft_archive import ROOT, verify_archive
from vanian_interop.microsoft_receipts import compare_microsoft_receipt
from vanian_interop.receipts import ReceiptVerifier
from vanian_interop.records import GovernanceEvent, SourceAuthenticity, json_bytes, strict_json

ARCHIVE = Path(os.environ.get("VANIAN_MICROSOFT_ARCHIVE", str(
    ROOT / "validation/interoperability/results/20261028-receipt-join/combined")))


@pytest.fixture
def evidence():
    result = strict_json((ARCHIVE / "adk-a2a/result.json").read_bytes())
    receipts = [strict_json(line) for line in (ARCHIVE / "receipts.jsonl").read_bytes().splitlines()]
    context = strict_json((ARCHIVE / "governance-comparison-context.json").read_bytes())
    anchor = strict_json((ARCHIVE / "trust-anchor.json").read_bytes())
    verifier = ReceiptVerifier(ROOT / "target/debug/aip-tool-receipt", context.pop("tenant"),
        anchor["gateway_id"], anchor["key_version"], anchor["public_key"])
    ref = result["governance_requests"][0]
    raw = next(event for event in result["microsoft_governance"] if event["event_id"] == ref["request_id"])
    event = GovernanceEvent(**{**raw, "authenticity": SourceAuthenticity(**raw["authenticity"])})
    signed = result["tool_results"][ref["receipt_result_index"]]["result"]["_meta"]["vanian"]["signed_receipt"]
    config = {**context, "expected_request_id": ref["request_id"], "expected_decision_id": ref["decision_id"]}
    return result, receipts, context, verifier, event, signed, config


def compare(evidence, *, event=None, signed=None, config=None, verifier=None):
    return compare_microsoft_receipt(event or evidence[4], verifier=verifier or evidence[3],
        signed_receipt=signed or evidence[5], **(config or evidence[6]))


def mutate(evidence, change, rehash=False):
    event = evidence[4]
    value = strict_json(event.native_json)
    change(value)
    if rehash:
        value["input_identity"] = value["enforced_identity"] = action_identity(value["policy_input"])
    return replace(event, native_json=json_bytes(value).decode())


def test_live_archive_and_exact_native_input_match_without_promoting_authority(evidence):
    result = verify_archive(*evidence[:4])
    assert result["all_reported_inputs_match"]
    compared = result["comparisons"][0]
    assert compared["gateway"]["receipt_signature"] == "VERIFIED"
    assert compared["governance_source_authenticity"] == "NOT_ESTABLISHED"
    assert compared["logical_agent_mapping"] == "NOT_ESTABLISHED"
    assert compared["authorization"] == "NOT_ESTABLISHED"
    assert compared["kernel_execution"] == "CANNOT_PROVE"


def test_changed_policy_input_without_rehash_diverges(evidence):
    event = mutate(evidence, lambda v: v["policy_input"]["policy_target"]["value"].update(amount=1))
    assert compare(evidence, event=event)["comparison"] == "DIVERGENCE"


def test_rehashed_changed_arguments_still_diverge_from_signed_gateway(evidence):
    def change(value):
        value["policy_input"]["policy_target"]["value"]["amount"] = 1
        value["policy_input"]["snapshot"]["tool_call"]["args"]["amount"] = 1
    event = mutate(evidence, change, rehash=True)
    result = compare(evidence, event=event)
    assert result["comparison"] == "DIVERGENCE"
    assert result["gateway"]["request_comparison"]["differences"] == ["Arguments"]


@pytest.mark.parametrize("field,value", [("expected_gateway_agent", "other-agent"),
    ("expected_decision_id", "ff"*16), ("expected_request_id", "another-request"),
    ("expected_framework_agent", "other-framework-agent")])
def test_wrong_context_and_reused_receipt_diverge(evidence, field, value):
    config = {**evidence[6], field: value}
    assert compare(evidence, config=config)["comparison"] == "DIVERGENCE"


def test_cross_tenant_refused(evidence):
    with pytest.raises(ValueError, match="cross-tenant"):
        compare(evidence, event=replace(evidence[4], tenant="another-tenant"))


def test_tampered_receipt_refused(evidence):
    signed = copy.deepcopy(evidence[5])
    signed["receipt"]["parameter_commitment"][0] ^= 1
    with pytest.raises(ValueError, match="verification refused"):
        compare(evidence, signed=signed)


def test_wrong_gateway_anchor_refused(evidence):
    with pytest.raises(ValueError, match="verification refused"):
        compare(evidence, verifier=replace(evidence[3], public_key_hex="01"*32))


@pytest.mark.parametrize("field", ["input_identity", "enforced_identity"])
def test_missing_native_identity_is_insufficient(evidence, field):
    event = mutate(evidence, lambda value: value.pop(field))
    assert compare(evidence, event=event)["comparison"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("decision", ["transform", "warn", "escalate"])
def test_unsupported_decision_semantics_are_not_flattened(evidence, decision):
    event = mutate(evidence, lambda value: value["verdict"].update(decision=decision))
    assert compare(evidence, event=event)["comparison"] == "INSUFFICIENT_EVIDENCE"


def test_approval_cannot_be_treated_as_plain_allow(evidence):
    event = mutate(evidence, lambda value: value["verdict"].update(approval={"status": "approved"}))
    assert compare(evidence, event=event)["comparison"] == "INSUFFICIENT_EVIDENCE"


def test_policy_version_change_is_insufficient(evidence):
    assert compare(evidence, event=replace(evidence[4], policy_version="other"))["comparison"] == "INSUFFICIENT_EVIDENCE"


def test_denial_with_forwarded_receipt_is_reported_divergence(evidence):
    event = mutate(evidence, lambda value: value["verdict"].update(decision="deny"))
    result = compare(evidence, event=event)
    assert result["comparison"] == "DIVERGENCE"
    assert result["authorization"] == "NOT_ESTABLISHED"


def test_self_asserted_authenticity_does_not_authenticate_policy(evidence):
    event = replace(evidence[4], authenticity=SourceAuthenticity("SIGNATURE", "claimed-bank", "claimed-key", 1,
        signature_status="VERIFIED"))
    result = compare(evidence, event=event)
    assert result["comparison"] == "AGREEMENT"
    assert result["governance_source_authenticity"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("amount", [0.0, 2**53])
def test_unqualified_numeric_profiles_are_insufficient(evidence, amount):
    def change(value):
        value["policy_input"]["policy_target"]["value"]["amount"] = amount
        value["policy_input"]["snapshot"]["tool_call"]["args"]["amount"] = amount
    assert compare(evidence, event=mutate(evidence, change, rehash=True))["comparison"] == "INSUFFICIENT_EVIDENCE"


def test_snapshot_target_disagreement_is_detected(evidence):
    event = mutate(evidence, lambda value: value["policy_input"]["snapshot"]["tool_call"]["args"].update(amount=True), rehash=True)
    assert compare(evidence, event=event)["comparison"] == "DIVERGENCE"


def test_no_join_is_inferred_for_old_archive(evidence):
    result, receipts, context, verifier = evidence[:4]
    result.pop("governance_requests")
    with pytest.raises(ValueError, match="no same-run"):
        verify_archive(result, receipts, context, verifier)


def test_duplicate_request_references_refused(evidence):
    result, receipts, context, verifier = evidence[:4]
    result["governance_requests"] *= 2
    with pytest.raises(ValueError, match="duplicate"):
        verify_archive(result, receipts, context, verifier)


def test_receipt_must_be_in_gateway_archive(evidence):
    result, _, context, verifier = evidence[:4]
    with pytest.raises(ValueError, match="absent"):
        verify_archive(result, [], context, verifier)
