# VANIAN enterprise service delivery model — benchmarked against WitnessAI

**Status: engineering service-design and onboarding-planner implementation. This is not a deployed or independently audited banking service.**

## Public competitor evidence reviewed 28 October 2026

- [WitnessAI for Agents](https://witness.ai/for-agents/): agent, MCP and tool discovery, approved-tool governance, REST-based guardrails.
- [WitnessAI Agentic Control, 17 June 2026](https://witness.ai/resources/witnessai-introduces-agentic-control-to-secure-and-govern-ai-agents-and-mcp-servers/): network enforcement for tool traffic traversing its platform.
- [WitnessAI platform datasheet](https://witness.ai/wp-content/uploads/2025/05/WIT-Secure-AI-Enablement-Platform-OP.pdf): network connectors (Zscaler, Palo Alto Networks, Netskope, Fortinet and F5), remote-worker access, API, isolated environments and BYOK statements.
- [AWS Marketplace listing](https://aws.amazon.com/marketplace/pp/prodview-5h2rg6gvjyywg): SaaS contract and consumption terms; no verified universal per-agent price.

WitnessAI sells one enterprise experience to **observe, control and protect** supported AI activity. Its network/application control paths are **not** equivalent to Linux kernel observation and separate collector attestation. This project does not copy proprietary implementation, screen designs, branding or source code.

## Similar customer experience, distinct VANIAN assurance

| Buyer question | WitnessAI describes | VANIAN existing evaluation capability | What VANIAN does not establish |
|---|---|---|---|
| What AI is in use? | Discovery of AI tools, agents and MCP servers across supported traffic | AIBOM and identities listed in stored EvidencePackets | Network-wide shadow AI discovery; packet identity is not independent identity proof |
| What did the agent request? | Agent/tool activity audit | ContextForge plugin and Rust-signed `ToolReceipt` | Calls outside approved gateway paths; universal tool allowlisting |
| Who authorized it? | Identity-aware governance | Signed AIP authorization/delegation primitives | Same-run signed authority for every enterprise live agent |
| What actually ran? | Network/application telemetry, runtime controls | Linux `aip-probe` + separate `aip-collector` signed kernel evidence | Complete logical-agent attribution or zero observation gaps |
| What malicious content was blocked? | Prompt injection and data protection guardrails | No equivalent shipped inline detection or tokenization | No equivalent `PROTECT` claim; consider external integrations later |
| Can auditors inspect? | Centralized audit trails | Signed evidence with offline verifier under selected trust anchors | Production institutional key custody or full end-to-end customer qualification |
| How is it delivered? | Isolated SaaS/private-cloud, network connector, API and console | Customer-managed Linux package, ContextForge, service API, SDKs, read-only MCP, evaluation console | Agentless proxy, production managed SaaS, certified BYOK HSM, qualified Kubernetes/OS matrix |

The differentiated VANIAN promise is **source-separated, signed evidence of authorization, execution and gateway-received requests**, reconciled without inventing certainty. Valid signatures do not independently prove truthful capture or complete coverage.

## Proposed service catalog — not existing customer sales

**1. Agent inventory and authority assessment.** Fixed-scope assessment of *approved/enrolled* agent workloads, AIBOM declarations, tool permissions and visibility gaps. Do not market shadow-agent discovery until relevant network collectors exist.

**2. Sniffer Dog Evidence Assurance evaluation.** Customer-approved, observer-only Linux scope; separately administered collector; optional verified tool receipts; signed audit bundle and an independent validation report. No bank certification claim.

**3. Sniffer Dog recurring assurance.** Prospective annual subscription and support, with implementation/ingestion costs based on protected hosts, supported gateways, volume, storage and support. No public WitnessAI price is assumed. General availability requires production gates to pass.

**4. Optional governance and guardrails integration.** Future partnership connections to approved policy and runtime guardrail systems, e.g. OPA, OpenFGA or NVIDIA OpenShell. These systems are not integrated or claimed as shipped by this change. Their decisions remain separate from observed execution facts.

## Standard banking customer journey

1. **Scope:** bank CISO and AI platform team nominate one non-critical workload, systems owners, retention/data boundaries and technical acceptance criteria.
2. **Plan:** generate an offline evaluation configuration from `integrations/service_delivery/example.json`. A valid plan is only a configuration preflight, not proof of deployment.
3. **Install:** bank engineers deploy the existing runtime probe on supported Linux and the collector on a genuinely separate host/admin trust domain. Confirm clock, privileges, signatures and privacy.
4. **Integrate:** configure approved ContextForge tool flows, independently signed mandates and separate evidence API, SDK and restricted read-only MCP interfaces.
5. **Prove:** run a real model-backed task, independently observe supported events, obtain gateway receipts, reconcile actual same-run artifacts and have bank auditors verify under independently provisioned trust anchors.
6. **Operate:** feed signed verdict references into approved SIEM channels, grant appropriately scoped Reader access, define retention and outage handling. Do not promote `CANNOT_PROVE` to a pass.
7. **Expand:** only after independent assessment, performance measurements, customer approval, clean-host compatibility, backup/recovery and incident runbooks.

Customer private-cloud deployment is a *customer-operated* environment, not automatically WitnessAI-like managed SaaS. Customer prompts, model outputs or transaction payloads are not collected by the Linux observer by default. Event paths/endpoints can still be sensitive and require scope review.

## Proposed component map

```text
Customer Linux AI host ---> aip-probe ---authenticated transport---> customer-controlled collector
                                                            |
                                                            v
                                                  signed evidence archive
Institution decision authority ---> signed mandate          |
ContextForge plugin -----------> signed gateway receipt --> reconcile / evidence service
                                                            |
                                              API / SDK / read-only MCP / console
                                                            |
                                             independent offline bank auditor
```

VANIAN does not currently have endpoint-free enterprise-wide traffic interception. Its Linux host observer requires approved host-level installation, unlike WitnessAI's network-connectored paths.

## Bounded onboarding planner

Source: [service delivery planner](../../integrations/service_delivery/README.md).

Run:

```bash
python3 -B integrations/service_delivery/service_onboard.py integrations/service_delivery/example.json
python3 -B -m unittest discover -s integrations/service_delivery/tests -v
```

It rejects unqualified HSM claims, colocated workload/collector, shared administration, unsupported Windows/network connectors, inline prompt-guardrail claims, automatic containment, transaction gating and prompt/transaction-payload collection.

The generated report **always** states `institutional_pilot: NOT_VERIFIED` and `coverage: UNAVAILABLE_UNTIL_SIGNED_ACTIVE_HEALTH_AND_LIVE_JOIN`. Real evidence and independent assessment, not a customer-configured boolean, must establish readiness.

Before regulated production: demonstrate approved clean-host installation and key separation; same-run signed authorization, gateway receipts and kernel evidence; independent offline audit; coverage/false-positive and load testing; trusted ingress/identity; durable retention/backup/recovery; signed release and independent security assessment.

## Recommended product positioning

**WitnessAI-style enterprise buying and deployment experience; VANIAN-specific independent execution evidence.** Complement security-policy platforms rather than claiming those systems cannot observe or govern agents.
### Read-only customer posture summary

The [Reader posture report](../../integrations/service_delivery/README.md) uses the existing enterprise SDK to inspect a customer's actual `/v1` API health, historical packet identity list and coverage status. It never treats application-signed identity or API-reported health as independently proven runtime coverage. This is a supporting customer security workflow, not a network discovery engine or completed live integration.
