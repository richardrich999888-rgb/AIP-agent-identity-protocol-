# VANIAN service-delivery evaluation planner

**Purpose:** Make enterprise onboarding repeatable without inventing security coverage. This is an offline JSON configuration preflight for customer-managed deployments. It does **not** install sensors, discover agents, contact the evidence API, authorize tools, verify signatures or certify a pilot.

Design and competitor comparison: [SERVICE_DELIVERY_MODEL.md](../../docs/enterprise/SERVICE_DELIVERY_MODEL.md).

## Quick start

```bash
python3 -B integrations/service_delivery/service_onboard.py \
  integrations/service_delivery/example.json \
  --output /tmp/vanian-service-plan.json

python3 -B -m unittest discover -s integrations/service_delivery/tests -v
```

Do not place credentials, prompts, real bank records or signing material in the input manifest. Unknown fields are refused. The manifest describes planned **approved integration surfaces**, not independently discovered agents or proven deployment coverage.

The planner requires supported Linux agent hosts, different collector host and administrator domain, wrapped-file key custody and observer-only safety. It rejects network-wide agentless discovery, inline prompt protection and transaction gating because those capabilities are not shipped in the current VANIAN evaluation build.

A successful plan says `VALIDATED_PLANNING_INPUT_ONLY`, `NOT_VERIFIED` institutional pilot, `CONFIGURED_NOT_EXECUTED` observation and `REQUIRES_SAME_RUN_EVIDENCE`. Only live signed evidence and independent evaluation can establish the security conclusions.

## Remaining engineering

1. Add tenant-scoped enrolled workload and authenticated connector inventories to the existing evidence service.
2. Connect signed live health to a read-only coverage summary; do not label historical signature verification as live observation.
3. Make SIEM forwarding and customer retention policies easy to configure under approved access controls.
4. Complete one genuine model-backed same-run authorization/observation/gateway/reconciliation flow verified offline by the institution.
5. Only then qualify optional network connectors, external guardrails and customer-managed cloud offering.

## Read-only evidence posture report

Once the institution has configured its existing `aip-service` API and a **Reader** credential, a security engineer can query its actual enrolled-record inventory and health without granting write or raw-export powers:

```bash
# Provide the URL and Reader token through the institution's secret manager.
export VANIAN_BASE_URL=https://vanian.bank.internal
# VANIAN_API_TOKEN must be injected from the approved credential source.
python3 -B integrations/service_delivery/posture_report.py \
  --ca-file /etc/institution/approved-ca.pem \
  --out /secure/bank-evaluation-posture.json
```

The tool reuses the existing Python customer SDK (HTTPS, redirect refusal, bounded reads, credential callback). It reads `/v1/access`, the first paginated 25-record `/v1/agents` page, `/v1/coverage` and `/v1/health`. It **never** claims full-enterprise discovery or independent verification based on those API statements. It reports API-advertised health separately from unverified coverage and reports only agent IDs originating in stored EvidencePackets.

It does not fetch transaction bodies or raw evidence. The output contains customer-specific agent identifiers and must remain under the institution's access/retention policy. Unit tests use an explicit API stub and are not live bank integration evidence.
