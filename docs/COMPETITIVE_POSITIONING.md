# COMPETITIVE / ADJACENT LANDSCAPE

**Companion to** `docs/ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md` §G
**Date:** 2026-09-07
**Research basis:** current public sources, September 2026. Sources listed in §6.

---

## 0. Method and honesty rules

Four rules govern this document, and they are the reason it is worth reading:

1. **A company is not a direct competitor merely because it is an AI-security
   company.** Category adjacency is not product overlap.
2. **No claim is made that any company *cannot* do something.** Every
   "not core" reading below is a statement about **public positioning**, from
   the sources cited — not about internal capability, roadmap, or unpublished
   work.
3. **The objective is to locate whitespace, not to manufacture competitor
   weakness.** Several vendors here are better than Vanian at what they do, and
   two categories are straightforwardly complementary.
4. **Anything unverified is marked as such.** Acquisition and funding facts are
   from the cited 2026 sources and should be re-confirmed before use in an
   investor document.

**Relationship classes**

| class | meaning |
|---|---|
| **Direct** | targets the same buyer with the same primary claim: accountability evidence about what an autonomous system actually did |
| **Adjacent** | overlapping buyer or overlapping mechanism, different primary claim |
| **Complementary** | solves a layer Vanian consumes or is consumed by; integration is the natural relationship |
| **Not actually competitive** | different problem; overlap is vocabulary only |

---

## 1. The landscape at a glance

| # | company / project | product | primary category | primary problem solved | software-only focus? | physical autonomy addressed? | independent runtime observation core? | observation integrity explicit? | execution/effect distinction explicit? | cryptographic accountability core? | relation to Vanian |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Palo Alto Networks | Prisma AIRS + Protect AI + CyberArk (acq. 2026) | AI security platform | discover, govern and secure AI agents across an enterprise estate | yes | no | not core (network/endpoint/posture) | not stated publicly | not stated publicly | not core | **Adjacent** |
| 2 | CrowdStrike | Falcon (AI/agent extensions) | endpoint & runtime security | detect and stop malicious behaviour on endpoints and workloads | yes | no | runtime telemetry is core; *independence as an evidence property* is not the claim | not stated publicly | no | no | **Adjacent** |
| 3 | Zscaler | AI/agent governance extensions | network & access security | control what agents can reach | yes | no | no | no | no | no | **Adjacent** |
| 4 | Zenity | agent security platform | AI agent security | discovery, posture, runtime defence across copilots and agents; analyses the agent's execution path, tool calls, memory access | yes | no | partial — execution-path visibility, sourced from the agent/platform layer | not stated publicly | not as an evidence boundary | not core | **Adjacent** |
| 5 | Noma Security | agentic AI security platform | AI agent security | AI discovery, agentic risk mapping, posture, red-teaming, runtime protection | yes | no | no | no | no | no | **Adjacent** |
| 6 | WitnessAI | AI security & governance | AI governance | network visibility, intent-based controls, runtime defence for employees, models, apps and agents | yes | no | no (network vantage) | no | no | no | **Not actually competitive** |
| 7 | Lasso Security | AI security platform | AI application security | secure adoption and governance of agents and LLM apps across the lifecycle | yes | no | no | no | no | no | **Adjacent** |
| 8 | XBOW | autonomous offensive security | offensive security | autonomous penetration testing | yes | no | n/a | n/a | n/a | no | **Not actually competitive** |
| 9 | Aembit | workload IAM | machine identity | runtime access decisions and policy enforcement between workloads | yes | no | no (access-time, not execution-time) | no | no | credentials, not evidence | **Complementary** |
| 10 | Astrix Security (Cisco, 2026) | NHI security | non-human identity | discovery, ownership and posture for machine credentials | yes | no | no | no | no | no | **Complementary** |
| 11 | Entro Security (SailPoint, 2026) | NHI security | non-human identity | secret and NHI lifecycle governance | yes | no | no | no | no | no | **Complementary** |
| 12 | Oasis Security (Cyera, 2026) | NHI lifecycle | non-human identity | NHI lifecycle and agentic access governance | yes | no | no | no | no | no | **Complementary** |
| 13 | SPIFFE / SPIRE (CNCF) | workload identity standard | machine identity | cryptographic workload identity within a trust domain | yes | partially (any workload) | no — identity issuance, not observation | no | no | **yes, for identity** | **Complementary** — a natural interop point for Vanian's identity layer |
| 14 | Okta | Agent SSO + Cross App Access (MCP Enterprise-Managed Authorization) | agent identity & authorization | how one app's agent calls another app's data on a user's behalf | yes | no | no | no | no | tokens, not evidence | **Complementary** |
| 15 | Auth0 | Auth for MCP | agent authorization | scoped agent access to APIs and MCP servers | yes | no | no | no | no | no | **Complementary** |
| 16 | Microsoft | Entra Agent ID | agent identity | directory-native identity for agents | yes | no | no | no | no | no | **Complementary** |
| 17 | Falco (CNCF / Sysdig) | Falco + Sysdig Secure | eBPF runtime security | syscall-level threat detection and alerting | yes | no | **yes — kernel-sourced observation is the mechanism** | no | no | no — alerts, not signed evidence | **Adjacent — closest neighbour on mechanism** |
| 18 | Tetragon (Cilium / Cisco) | Tetragon | eBPF security observability + enforcement | process-level observability and in-kernel enforcement | yes | no | **yes** | no | no | no | **Adjacent — and instructive** (see §3) |
| 19 | Tracee (Aqua) | Tracee | eBPF runtime detection | runtime detection and forensics | yes | no | yes | no | no | no | **Adjacent** |
| 20 | LangSmith (LangChain) | LangSmith | agent observability | tracing, evaluation and monitoring of agent runs | yes | no | **no — instrumented inside the actor's process** | no | no | no | **Not actually competitive** |
| 21 | Langfuse (ClickHouse, 2026) | Langfuse | agent observability | open-source, OTel-native LLM/agent tracing | yes | no | no — SDK-fed | no | no | no | **Not actually competitive** |
| 22 | Arize | Arize / Phoenix | ML & agent observability | drift detection, RAG and agent evaluation | yes | no | no | no | no | no | **Not actually competitive** |
| 23 | OpenTelemetry | GenAI semantic conventions, OBI | telemetry standards | vendor-neutral instrumentation | yes | no | no — transport and schema | no | no | no | **Complementary** |
| 24 | Sigstore (OpenSSF) | Sigstore / Rekor | cryptographic provenance | artifact signing with transparency-log verification | yes | no | no | no | no | **yes, for artifacts** | **Complementary** |
| 25 | in-toto / SLSA | attestation frameworks | supply-chain provenance | verifiable provenance for build pipelines and, increasingly, AI artifacts | yes | no | no | no | build-step, not runtime | **yes, for build steps** | **Complementary** |
| 26 | C2PA | Content Credentials | content provenance | provenance and authenticity for media | yes | no | no | no | no | yes, for content | **Not actually competitive** |
| 27 | VicOne | physical-AI cybersecurity (automotive + robots) | physical-AI security | risk assessment, pre-deployment validation and runtime protection for vehicles and AI robots | **no** | **yes** | runtime protection is core; independent *evidence* is not the stated claim | not stated publicly | no | not core | **Adjacent — nearest neighbour on the physical axis** |
| 28 | Alias Robotics | CAI (Cybersecurity AI), robot security services | robot security | robot vulnerability research, assessment and hardening (ROS2 ecosystem) | **no** | **yes** | no — offensive/assessment posture | no | no | no | **Adjacent** |
| 29 | Upstream Security | mobility XDR | automotive security | cloud-based detection across connected vehicle fleets | **no** | **yes** | fleet telemetry, vehicle-authored | no | no | no | **Adjacent** |
| 30 | Nozomi / Claroty / Dragos | OT security platforms | ICS/OT security | asset visibility and threat detection in industrial networks | **no** | **yes (industrial)** | network-vantage observation | no | no | no | **Adjacent** |
| 31 | Anduril | Lattice, Mission Autonomy | defence autonomy | edge mission autonomy and C2 for uncrewed systems | **no** | **yes** | n/a — it *is* the autonomy | n/a | n/a | no | **Complementary / target integration partner** |
| 32 | Shield AI | Hivemind | defence autonomy | autonomy software for uncrewed aircraft | **no** | **yes** | n/a | n/a | n/a | no | **Complementary / target integration partner** |
| 33 | Palantir | Foundry / Gotham (+ Anduril partnership) | mission data platform | data lineage, provenance and analytics for national-security workflows | mixed | yes (as data about physical systems) | no — data-layer lineage | no | no | lineage, not cryptographic re-derivation | **Adjacent / potential channel** |

---

## 2. Reading the table

**The AI-agent security market is dense and consolidating.** Zenity, Noma,
Lasso and WitnessAI all address a real and urgent problem — an enterprise
cannot see, govern or constrain the agents it is running — and the platform
vendors are buying into that problem at scale. Their output is *prevention,
posture and alerting*. Vanian's output is *evidence*. A buyer can want both;
they are not substitutes.

**The machine-identity market answered a different question and answered it
well.** Through 2026 it consolidated almost completely: Astrix into Cisco,
Entro into SailPoint, Oasis into Cyera, and CyberArk into Palo Alto. Combined
with Okta's Cross App Access being adopted as MCP's Enterprise-Managed
Authorization extension, Auth0's Auth for MCP, and Microsoft Entra Agent ID
reaching general availability, the ecosystem now has a workable answer to *how
does an agent prove who it is acting for*. **That is the layer Vanian
consumes.** It is a strategic argument for interop — SPIFFE identity in,
Vanian evidence out — rather than for competition.

**Agent observability is the category most often mistaken for Vanian, and is
the clearest non-competitor.** LangSmith, Langfuse, Arize and the OTel GenAI
conventions instrument the agent from inside its own process. Under Vanian's
first principle — *the actor should not control the evidence used to judge the
actor* — that telemetry is a claim, however well engineered. The AIRI
validation work says this explicitly of Langfuse: an SDK-fed trace is
"claim, durably stored". This is not a criticism of those products; it is a
statement about which question they answer.

**eBPF runtime security is the closest neighbour on mechanism.** Falco,
Tetragon and Tracee observe from the kernel, outside the workload, which is the
same structural insight Vanian's observation layer rests on. The difference is
what the observation is *for*: detection and enforcement, versus attested,
re-derivable evidence with a first-class `CANNOT_PROVE`. Falco is the most
mature and best-supported detection engine in this space and Vanian does not
compete with it on detection.

**Physical-AI security is the nearest neighbour on the other axis.** VicOne is
the most directly relevant, positioning explicitly around automotive and robot
security from design through runtime. Alias Robotics has published substantive
robot-security research including ROS2 communication-layer vulnerabilities.
Neither publicly positions around an accountability/evidence model with an
explicit execution-versus-effect boundary — but both address physical autonomy
today, which Vanian does not.

**Defence autonomy platforms are the destination, not the competition.**
Lattice and Hivemind are the autonomy. An accountability layer that can say
what a mission computer actually did, and prove it offline afterwards, is a
component such platforms would integrate or a capability their customers would
require — which is why they appear here as target integration partners.

---

## 3. The instructive case: Tetragon and A3S

The single most useful competitive fact in this document is not commercial.

Vanian's observation-integrity finding was produced by running a **third-party
eBPF observer** (A3S Observer, MIT) alongside Sniffer Dog. The co-resident
observer silently blinded Sniffer Dog by attaching a program to the same
tracepoint — a class of behaviour that any eBPF security tool, Tetragon
included, can exhibit **entirely benignly**.

Two consequences follow, and both are strategic:

1. **Benign and malicious interference are indistinguishable by effect.** The
   detector must therefore key on the *presence* of a foreign program, not on
   intent, and the fallback must be `INTEGRITY_UNKNOWN` rather than "attack".
   That is exactly what shipped.
2. **A deployment running a mainstream eBPF security tool is a deployment where
   this matters.** Any customer running Falco, Tetragon or Tracee alongside an
   observation-based accountability layer is in the reproduced scenario. This
   makes observation integrity a *co-existence* requirement, not only a security
   one — and it is the most concrete answer available to "why would an
   enterprise that already runs Falco need this?"

---

## 4. The whitespace

No vendor surveyed publicly positions the following combination:

| element | who else publicly claims it |
|---|---|
| Independent runtime observation, with the observer's key **off the observed host** | eBPF vendors observe from the kernel; the *keyless probe / off-host signing* split is not a positioning claim any surveyed vendor makes |
| **Observation integrity** as an explicit evidence-boundary state | none surveyed |
| **Execution ≠ effect** as a structural refusal (no event may assert an external effect) | none surveyed |
| **`CANNOT_PROVE` as a first-class outcome** rather than a gap in coverage | none surveyed |
| Offline, network-free, clock-free **re-derivation** of a verdict by a third party | closest analogue is transparency-log verification (Sigstore), for artifacts rather than runtime execution |
| **One accountability core across software and physical autonomy** | physical-AI vendors address physical; agent-security vendors address software; none surveyed positions one evidence model across both |

**This is a statement about public positioning as of September 2026, from the
sources in §6.** It is not a claim of technical exclusivity, and it should be
re-tested before each fundraising cycle — this category is moving fast enough
that a six-month-old landscape read is stale.

---

## 5. Strategic implications

1. **Do not sell against Falco, Zenity or Okta.** Sell alongside them. The
   integration story is stronger than the displacement story and is supported by
   the co-existence argument in §3.
2. **The identity layer is a partnership surface, not a build surface.** SPIFFE
   interop is a cheaper route to enterprise credibility than a proprietary
   identity plane.
3. **Physical autonomy is where the whitespace is widest and where Vanian is
   weakest.** That asymmetry is the entire argument for the physical-validation
   milestones in `docs/PRE_SERIES_A_10M_ROADMAP.md`.
4. **Defence and industrial autonomy vendors are the OEM channel.** The
   accountability layer is more valuable embedded than sold standalone, which is
   why M6 sits where it does on the milestone ladder.
5. **The category has to be named before it can be sold.** "Autonomous
   intelligence accountability" is not a market a buyer currently has a budget
   line for. Category creation is a cost of this position and should be
   budgeted, not assumed away.

---

## 6. Sources

Research conducted 2026-09-07.

- [AI Agent Observability & Governance: 2026 Market Reality](https://guptadeepak.com/ai-agent-observability-evaluation-governance-the-2026-market-reality-check/)
- [Agentic AI security startups, funding and M&A, 2026](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/)
- [Top 11 Agentic AI Security Solutions in 2026](https://www.linx.security/blog/top-agentic-ai-security-solutions)
- [Zenity — runtime protection for AI agents](https://www.businesswire.com/news/home/20251103687418/en/Zenity-Launches-Runtime-Protection-for-AI-Agents-Built-with-OpenAI-AgentKit)
- [WitnessAI](https://witness.ai/)
- [NHI Security Platform Comparison 2026: Astrix, Oasis, Entro, Clutch, GitGuardian](https://www.cremit.io/reports/rsac-2026-nhi)
- [2026 IAM vendors for AI agents — Aembit](https://aembit.io/blog/10-identity-security-vendors-for-ai-agents-strengths-tradeoffs-and-how-they-fit/)
- [SPIFFE: securing the identity of agentic AI and non-human actors — HashiCorp](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors)
- [AI Agent Identity Standards 2026: Cross App Access, MCP, and what is still missing](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)
- [MCP Enterprise Authorization goes stable](https://www.techtimes.com/articles/318708/20260619/mcp-enterprise-authorization-goes-stable-zero-touch-sso-okta-anthropic-vs-code.htm)
- [eBPF Runtime Security in 2026: Falco vs Tetragon vs Tracee](https://1337skills.com/blog/2026-06-24-ebpf-runtime-security-2026-falco-tetragon-tracee/)
- [Falco vs Tetragon: why kernel-time detection needs both](https://stribog.com/blog/falco-tetragon-kubernetes-runtime-threat-detection-ebpf)
- [Top LLM observability and evaluation platforms in 2026](https://www.marktechpost.com/2026/08/09/top-llm-observability-and-evaluation-platforms-in-2026-langfuse-langsmith-braintrust-arize-and-more-compared/)
- [Sigstore — OpenSSF](https://openssf.org/tag/sigstore/)
- [SLSA and build provenance](https://cloudrps.com/blog/slsa-build-provenance-supply-chain-security/)
- [VicOne — physical AI cybersecurity for automotive and robotics](https://vicone.com/)
- [Cybersecurity AI: hacking consumer robots in the AI era (Alias Robotics)](https://arxiv.org/html/2603.08665v1)
- [Anduril — Mission Autonomy](https://www.anduril.com/lattice/mission-autonomy)
- [Anduril and Palantir to accelerate AI capabilities for national security](https://www.anduril.com/news/anduril-and-palantir-to-accelerate-ai-capabilities-for-national-security)
- [How to implement security monitoring with eBPF (Falco, Tetragon)](https://oneuptime.com/blog/post/2026-01-07-ebpf-security-monitoring-falco-tetragon/view)
