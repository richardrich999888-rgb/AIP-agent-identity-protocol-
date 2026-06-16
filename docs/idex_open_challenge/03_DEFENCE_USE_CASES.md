# 03 — Defence Use Cases

AIP is use-case agnostic: anywhere an AI/autonomous system takes an action
that must later be accounted for, AIP produces verifiable evidence of the
authority behind it. Below are concrete scenarios, ordered by how cleanly
they map to the existing capability. The applicant will align to the
specific iDEX Problem Statement / sponsor on selection.

> In each case the structure is identical to the working demonstrator
> (`cargo run -p banking-demo`): **principal → delegated, attenuated
> authority → agent decision → action → tamper-evident, offline-verifiable
> EvidencePacket.**

## UC-1 — Accountability for AI decision-support in C2

**Scenario.** An AI decision-support agent in a command-and-control workflow
recommends or executes an action (e.g. re-tasking a sensor, prioritising a
track). A commander has delegated a bounded authority to the supporting
system.

**AIP role.** Each recommendation/action is sealed into an EvidencePacket
binding it to the commander's delegated authority and its limits. A
post-operation review or board of inquiry can verify — offline, from the
packet alone — exactly which authority permitted the action and that the
record is unaltered.

**Why it matters.** Converts "the system did X" into "the system did X under
authority delegated by Commander Z, within scope S, provably unaltered."

## UC-2 — Unmanned / autonomous platform tasking audit

**Scenario.** An unmanned platform or its tasking agent executes mission
steps under authority delegated from a mission commander through a ground
control system.

**AIP role.** The delegation chain (commander → GCS → on-platform agent) is
cryptographically represented; each consequential action is bound to the
most-attenuated scope. Evidence is generated **on-platform** and verifies
**offline** after recovery — no live link required.

**Why it matters.** Tasking accountability for platforms that operate
disconnected or in contested EM environments.

## UC-3 — Tamper-evident audit for multi-agent / agentic workflows

**Scenario.** A workflow chains several AI agents (e.g. ISR triage →
fusion → alerting). Sub-agents are spawned with narrowed authority.

**AIP role.** Depth-limited, per-hop-signed delegation guarantees no
sub-agent exceeds its parent's authority; the scoped audit chain records each
step's authorising delegation. Any later tampering with the chain is
detectable.

**Why it matters.** Prevents "confused-deputy" privilege escalation across
agent hand-offs and gives a single verifiable record of a multi-agent
operation.

## UC-4 — Cross-domain / coalition evidence exchange

**Scenario.** Two organisations (inter-service, or India + a partner force)
must each rely on a record of an automated action taken at a boundary.

**AIP role.** The acting side seals the EvidencePacket; the receiving side
**countersigns** the receipt, producing bilateral evidence each party can
verify independently against its own trusted keys. The open spec means
neither side depends on the other's software to verify.

**Why it matters.** Non-repudiable, mutually verifiable records across trust
boundaries without a shared central authority.

## UC-5 — Provenance and integrity for AI-generated intelligence products

**Scenario.** An AI system generates or enriches an intelligence product;
downstream consumers need to know which model/build produced it, under whose
tasking, and that it has not been altered.

**AIP role.** The provenance commitment + agent signature + decision record
bind the product's origin and authority; the hash chain detects alteration in
transit or at rest.

**Why it matters.** Trust and provenance for machine-generated products
moving through the intelligence cycle.

---

## Common defence-grade properties exploited across all use cases

- **Offline / air-gapped verification** (no call-home).
- **Tamper evidence** against insiders and intruders, not just accidents.
- **Authority attenuation** enforced mathematically across delegation.
- **Independent multi-party verifiability** via an open specification.
- **Indigenous, sovereign** implementation with no foreign service in the
  trust path.

## Out of scope (explicitly)

AIP is an **accountability/evidence** layer. It is **not** a weapons system,
not a targeting authority, not an autonomy/decision engine, and does not make
or approve operational decisions. It records and proves the authority and
integrity of actions taken by other systems. This separation is deliberate
and should be preserved in any integration.
