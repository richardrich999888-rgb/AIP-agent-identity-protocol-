#!/usr/bin/env python3
"""Read-only enterprise evidence posture report using VANIAN's existing SDK.

No agent discovery, private-key access, authentication bypass, risk scoring,
policy enforcement, independent audit or bank readiness claim occurs here.
"""

import argparse
import json
import os
from pathlib import Path
import sys

# Reuse the tested customer SDK for TLS, redirects, bounded reads and auth.
SDK = Path(__file__).resolve().parents[2] / "sdk" / "python"
sys.path.insert(0, str(SDK))
from vanian import VanianClient  # noqa: E402


class PostureError(ValueError):
    pass


def collect(client):
    access = client.access()
    if not isinstance(access, dict) or access.get("role") != "reader":
        raise PostureError("requires an institution-scoped Reader credential")
    tenant = access.get("tenant_id")
    if not isinstance(tenant, str) or not tenant:
        raise PostureError("service did not provide an authenticated tenant")
    page = client.list_agents(limit=25, offset=0)
    coverage = client.get_coverage()
    health = client.get_health()
    if not isinstance(coverage, dict) or not isinstance(health, dict):
        raise PostureError("incomplete service health/coverage response")
    if not isinstance(page.items, list):
        raise PostureError("invalid agent page")
    agents = []
    for a in page.items:
        if not isinstance(a, dict) or not isinstance(a.get("agent_id"), str):
            raise PostureError("invalid agent inventory record")
        agents.append({
            "agent_id": a["agent_id"],
            "identity_source": a.get("identity_source", "unknown"),
            "independent_identity_verified": False,
        })
    return {
        "report_type": "VANIAN_EVALUATION_POSTURE_ONLY",
        "tenant_id": tenant,
        "service_health": "api_reported_ok" if health.get("status") == "ok" else "api_reported_unhealthy_or_unknown",
        "observer_health": health.get("probe_health", "unknown"),
        "collector_health": health.get("collector_health", "unknown"),
        "coverage": {
            "service_reported_status": str(coverage.get("status", "unknown")),
            "independent_coverage_assessment": "NOT_PERFORMED",
            "independently_verified_execution": False,
        },
        "agent_inventory": {
            "provenance": "AGENT_SIGNED_EVIDENCE_PACKET_IDENTIFIERS_ONLY",
            "source_pagination_complete": page.next_offset is None,
            "page_limit": page.limit,
            "items": agents,
        },
        "audit_qualification": "NOT_ESTABLISHED",
        "limitations": [
            "No enterprise-wide shadow AI, MCP server or agent discovery is performed.",
            "Agent IDs listed by the evidence service are not independent workload identity attestation.",
            "Service-reported status is not independent proof of live sensor coverage.",
            "No same-run signed authorization / gateway / kernel reconciliation is verified here.",
            "No regulatory approval or production readiness is inferred from this report.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only VANIAN enterprise evidence posture report")
    parser.add_argument("--out", type=Path, help="Write report locally instead of stdout")
    parser.add_argument("--ca-file", type=str, help="Institution-approved TLS root bundle")
    args = parser.parse_args(argv)
    url = os.getenv("VANIAN_BASE_URL", "")
    token = os.getenv("VANIAN_API_TOKEN", "")
    if not url or not token:
        print("VANIAN_BASE_URL and VANIAN_API_TOKEN are required", file=sys.stderr)
        return 2
    try:
        client = VanianClient(url, lambda: token, ca_file=args.ca_file, retries=0)
        result = collect(client)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    except Exception as exc:
        # Never include the credential, URL, or raw service response in errors.
        print(f"Posture report unavailable: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
