# VANIAN AI Visibility & Control — research scaffold

This is an **experimental, opt-in** integration layer, not a production enforcement gateway. It does not replace AIP, Sniffer Dog or existing enterprise branches.

## Commercial scope
- AI activity monitoring: model requests, MCP tool calls, workload execution, approvals, evidence references.
- Agent inventory: registered agents, owner, SPIFFE workload identity, parent delegation, last-seen, lifecycle.
- Shadow AI: observed activity without an approved inventory entry.
- Ghost AI: activity with no reliably attributable active identity; classify as *unattributed*, not necessarily malicious.
- Orphan AI: previously registered agent whose owner or delegation is no longer valid.
- Child AI: delegated/subagent ancestry and authorization inheritance; never assume a process tree alone proves delegation.
- FinOps: provider/model tokens, observed costs, budgets, anomaly alerts; distinguish estimates from invoices.
- Governance: explicit authorization, policy versions, approval and revocation.
- Gateway: signed, authenticated actor provenance (human, agent, service, unknown). **Never infer human vs AI from writing style or traffic alone.**

## Candidate upstream integrations (evaluate before adoption)
- agentgateway: https://github.com/agentgateway/agentgateway — MCP/A2A/LLM gateway.
- LiteLLM: https://github.com/BerriAI/litellm — model gateway and spend metering.
- Langfuse: https://github.com/langfuse/langfuse — agent traces.
- OpenTelemetry Collector: https://github.com/open-telemetry/opentelemetry-collector — ingestion.
- SPIRE: https://github.com/spiffe/spire — workload identities.
- OPA: https://github.com/open-policy-agent/opa — authorization decisions.
- Tetragon: https://github.com/cilium/tetragon — independent kernel observations.
- Falco: https://github.com/falcosecurity/falco — comparison detector.
- CycloneDX: https://github.com/CycloneDX/specification — inventory interoperability.
- in-toto: https://github.com/in-toto/in-toto — evidence provenance.

Do not vendor upstream code until license, CVE, maintenance and operational review. Keep upstream dependencies isolated behind adapters.

## Trust boundaries
1. Gateway observations are not complete visibility: direct API calls, encrypted traffic and unmanaged endpoints may bypass it.
2. Actor classification is based on authenticated credentials + attested workload/delegation evidence. Unknown stays unknown.
3. Sniffer Dog independent observations must be reconciled against gateway events and ground truth; do not fabricate attribution.
4. No prompt/response body storage by default; redact secrets and personal data, minimize retention.
5. The policy enforcement point must reject unauthorized tool actions **before** execution; after-the-fact observation is not enforcement.
6. Offline verification, replay protection, signed receipts, multi-tenant isolation and tamper tests are acceptance gates.

## Acceptance suite (future integration)
- 100 authorized and 100 unauthorized MCP calls; record false accepts/denials.
- Busy-host concurrent processes with ground-truth PID/cgroup/container/identity mapping.
- Parent-child delegation, revocation, owner departure, and unknown actors.
- Direct provider call bypassing gateway; report visibility gap.
- Metered token-cost reconciliation against provider invoice with price version.
- Tamper with receipts, policy versions and trace ancestry; offline verifier rejects.
- p50/p95/p99 gateway latency and throughput with/without observation.

## Status
Architecture and fixture scaffold only. No claim of production detection, customer readiness or independent validation.
