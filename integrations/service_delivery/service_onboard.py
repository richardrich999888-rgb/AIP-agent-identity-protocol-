#!/usr/bin/env python3
"""Plan a bounded, customer-controlled Sniffer Dog engineering evaluation.

This is an offline onboarding/configuration verifier, not a kernel observer,
security policy engine, evidence validator, enrollment service, or proof of
pilot completion. It NEVER reads secrets or opens network connections.
"""

import argparse
import json
from pathlib import Path
import re
import sys

SCHEMA_VERSION = "vanian.enterprise-service.v1"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")
SUPPORTED_CONNECTORS = {
    "linux_probe", "contextforge", "evidence_api", "python_sdk",
    "typescript_sdk", "evidence_mcp", "siem_cef",
}


class ManifestError(ValueError):
    """A manifest is malformed or describes unsupported assurance."""


def object_with_keys(value, required, optional, location):
    if not isinstance(value, dict):
        raise ManifestError(f"{location} must be a JSON object")
    missing = set(required) - set(value)
    extras = set(value) - set(required) - set(optional)
    if missing or extras:
        raise ManifestError(f"{location}: missing={sorted(missing)} unsupported={sorted(extras)}")
    return value


def identifier(value, location):
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ManifestError(f"{location} must be a lower-case identifier (3-64 characters)")
    return value


def exact_bool(value, expected, location):
    if type(value) is not bool or value is not expected:
        raise ManifestError(f"{location} must be JSON {str(expected).lower()}")


def validate(manifest):
    object_with_keys(manifest,
        ["schema_version", "tenant_id", "deployment_name", "deployment_mode", "agent_hosts",
         "collector", "integrations", "safety", "data_policy"], [], "manifest")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ManifestError("unsupported schema_version")
    identifier(manifest["tenant_id"], "tenant_id")
    identifier(manifest["deployment_name"], "deployment_name")
    if manifest["deployment_mode"] not in ("customer_on_prem", "customer_private_cloud"):
        raise ManifestError("deployment_mode: only customer-managed modes are supported")
    hosts = manifest["agent_hosts"]
    if not isinstance(hosts, list) or not (1 <= len(hosts) <= 20):
        raise ManifestError("agent_hosts must contain 1-20 approved hosts")
    host_ids = set()
    admin_groups = set()
    for n, host in enumerate(hosts):
        object_with_keys(host, ["host_id", "admin_group", "os"], [], f"agent_hosts[{n}]")
        host_id = identifier(host["host_id"], f"agent_hosts[{n}].host_id")
        admin_groups.add(identifier(host["admin_group"], f"agent_hosts[{n}].admin_group"))
        if host_id in host_ids:
            raise ManifestError("agent host IDs must be unique")
        host_ids.add(host_id)
        if host["os"] != "linux":
            raise ManifestError("the current kernel observer requires Linux")
    collector = object_with_keys(manifest["collector"],
        ["host_id", "admin_group", "key_custody"], [], "collector")
    collector_id = identifier(collector["host_id"], "collector.host_id")
    collector_admin = identifier(collector["admin_group"], "collector.admin_group")
    if collector_id in host_ids:
        raise ManifestError("collector must not share an agent host")
    if collector_admin in admin_groups:
        raise ManifestError("collector must have a separate administrator group")
    if collector["key_custody"] != "wrapped_file":
        raise ManifestError("this planner only qualifies existing wrapped_file custody; HSM is not validated")

    integrations = object_with_keys(manifest["integrations"],
        ["linux_probe", "contextforge", "evidence_api", "python_sdk", "typescript_sdk",
         "evidence_mcp", "siem_cef", "network_connector", "inline_guardrails"], [], "integrations")
    for key in SUPPORTED_CONNECTORS:
        if type(integrations[key]) is not bool:
            raise ManifestError(f"integrations.{key} must be a boolean")
    exact_bool(integrations["linux_probe"], True, "integrations.linux_probe")
    exact_bool(integrations["network_connector"], False, "integrations.network_connector")
    exact_bool(integrations["inline_guardrails"], False, "integrations.inline_guardrails")
    if integrations["evidence_mcp"] and not integrations["evidence_api"]:
        raise ManifestError("evidence_mcp requires evidence_api")
    if (integrations["python_sdk"] or integrations["typescript_sdk"]) and not integrations["evidence_api"]:
        raise ManifestError("customer SDKs require evidence_api")

    safety = object_with_keys(manifest["safety"],
        ["mode", "transaction_gating", "automatic_containment"], [], "safety")
    if safety["mode"] != "observer_only":
        raise ManifestError("only observer_only safety mode is qualified for evaluation")
    exact_bool(safety["transaction_gating"], False, "safety.transaction_gating")
    exact_bool(safety["automatic_containment"], False, "safety.automatic_containment")
    data = object_with_keys(manifest["data_policy"],
        ["residency", "capture_prompts", "capture_transaction_payloads"], [], "data_policy")
    if data["residency"] != "customer_controlled":
        raise ManifestError("customer-controlled evidence residency is required")
    exact_bool(data["capture_prompts"], False, "data_policy.capture_prompts")
    exact_bool(data["capture_transaction_payloads"], False, "data_policy.capture_transaction_payloads")
    return manifest


def plan(manifest):
    m = validate(manifest)
    integrations = m["integrations"]
    return {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": m["tenant_id"],
        "deployment_name": m["deployment_name"],
        "configuration": "VALIDATED_PLANNING_INPUT_ONLY",
        "institutional_pilot": "NOT_VERIFIED",
        "coverage": "UNAVAILABLE_UNTIL_SIGNED_ACTIVE_HEALTH_AND_LIVE_JOIN",
        "service_planes": {
            "DISCOVER": {"status": "LIMITED_TO_ENROLLED_WORKLOADS", "limitation": "No enterprise-wide shadow-agent/network scanning is implemented."},
            "OBSERVE": {"status": "CONFIGURED_NOT_EXECUTED", "limitation": "Live Linux sensor, separate-host custody, coverage and auditor checks remain mandatory."},
            "CONTROL": {"status": "GATEWAY_INTEGRATION_REQUIRES_LIVE_VALIDATION" if integrations["contextforge"] else "NOT_CONFIGURED", "limitation": "No organization-wide cross-provider allowlist or general agent enforcement is established."},
            "PROTECT": {"status": "NOT_IMPLEMENTED", "limitation": "No inline prompt-injection, jailbreak or data-tokenization guardrail is claimed."},
            "PROVE": {"status": "REQUIRES_SAME_RUN_EVIDENCE", "limitation": "Signature integrity alone does not prove authorized execution or business effects."},
        },
        "connectors_requested": sorted(name for name in SUPPORTED_CONNECTORS if integrations[name]),
        "mandatory_acceptance_gates": [
            "Bank security/privacy approval of hosts, sensors, egress and retention",
            "Clean-host install and actual kernel sensor capability test",
            "Genuinely separate collector administration and institution-approved key custody",
            "Signed Active observation coverage during one actual model-driven agent execution",
            "Authentic independent authorization and same-run gateway receipt comparison where integrated",
            "Reconciled supported effects with explicit gaps and no invented authorization/business result",
            "Bank auditor reproduces offline verification using independently provisioned anchors",
            "Performance, capacity, failure-recovery and external security assessment before production",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline VANIAN enterprise evaluation service planner")
    parser.add_argument("manifest", type=Path, help="JSON configuration manifest (no secrets)")
    parser.add_argument("--output", type=Path, help="Optional JSON output file")
    args = parser.parse_args(argv)
    try:
        if args.manifest.stat().st_size > 65536:
            raise ManifestError("manifest exceeds 64 KiB")
        result = plan(json.loads(args.manifest.read_text(encoding="utf-8")))
        serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(serialized, encoding="utf-8")
        else:
            print(serialized, end="")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"INVALID SERVICE PLAN: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
