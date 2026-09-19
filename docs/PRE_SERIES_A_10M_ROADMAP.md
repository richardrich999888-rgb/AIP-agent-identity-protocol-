# COMMERCIALIZATION AND FUNDRAISING ROADMAP
## USD 10M Pre-Series A — target

**Companion to** `docs/ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md` §K–§M
**Date:** 2026-09-07

---

> **Framing discipline.** Every number in this document is a **TARGET** or a
> **PLANNING ASSUMPTION**. None is committed capital, a term sheet, an
> indication of interest, a third-party valuation, or a fairness opinion. No
> investor is named because none is evidenced. No customer is named because
> none exists.

> **ENGINEERING STATUS**
> TRL 5 overall; AIRI/Sniffer Dog software accountability core approaching TRL 6;
> physical autonomous-system validation pending.

---

## 1. Investment thesis

### THE PROBLEM

Autonomous systems increasingly act without continuous human supervision, and
their own logs and claims are often the evidence used to judge them. When an AI
agent reports that it called a tool, when a robot reports that it completed a
grasp, when a UAS reports that it flew a mission — the report and the actor are
the same party. A signature over that report proves authorship, not occurrence.

### THE VANIAN THESIS

> **The actor should not control the evidence used to judge the actor.**

This is not a slogan in this codebase. It is implemented as a structural
property: the probe on the observed host holds **no key** and has **no signing
method**; the collector holds the key **off-host**; and the verifier re-derives
the verdict rather than believing the one it is handed.

### THE PRODUCT

Identity + authority + execution accountability + independent observation +
observation integrity + evidence/proof.

Concretely, and with the evidence class attached:

| component | what it does | status |
|---|---|---|
| AIP core | identity, scoped authority, attenuating delegation bound issuer-to-grantee | CODE-PROVEN, TEST-PROVEN |
| AIRI | a framework-neutral, signed, hash-chained record of what an agent *says* it did | TEST-PROVEN, EXECUTION-PROVEN |
| Sniffer Dog 2.0 | kernel-sourced independent observation, keyless probe, off-host collector | EXECUTION-PROVEN |
| Observation integrity | the observer's own integrity carried inside its signed health record | EXECUTION-PROVEN |
| Reconciliation | one verdict, one choke point, fail-closed to `CANNOT_PROVE` | CODE-PROVEN, TEST-PROVEN |
| Effect boundary | request ≠ execution ≠ effect, enforced by the absence of any event that asserts an effect | CODE-PROVEN |
| NEXORA | offline, clock-free, network-free re-derivation of a verdict by a third party | EXECUTION-PROVEN |
| UAS / robotics profiles | the same core, specialised, adding no signer or verdict class | CODE-PROVEN, TEST-PROVEN, **no hardware validation** |

### THE EXPANSION

```
AI agents → robotics → UAS → autonomous vehicles → industrial autonomy
          → defence autonomy → critical infrastructure → space systems
```

The expansion is credible **because the core is environment-neutral by
construction**, not because a slide says so: `SystemType::UncrewedAerial`
existed at wire code `0x02` before the UAS profile was written, and the profile
added no identifier, record type, verdict class, key, signer or proof tree.

### THE MOAT

Not merely models. Not merely telemetry. Not merely IAM. Not merely
observability.

The moat is the **accountability architecture + security semantics +
independent observation + evidence/proof model + vertical expansion** — with
the qualification that the vertical expansion is, today, architecture and
documentation rather than validated capability.

---

## 2. The round

| item | value |
|---|---|
| Instrument | **TARGET: USD 10M Pre-Series A** |
| Status | **not raised, not committed, not term-sheeted** |
| Purpose | convert an evidence-strong software core into a validated physical-autonomy accountability layer with commercial references |

### What the round finances

1. **Physical validation** — roadmap stages 2–4, culminating in the first
   physical quantity established by an independent mechanism.
2. **Defence / industrial pilots** — the first deployments where evidence is
   consumed by someone with a reason to distrust it.
3. **Independent security validation** — third-party assessment and
   remediation; currently listed as a pre-deployment blocker.
4. **Hardware / edge deployment work** — including the hardware-rooted observer
   trust that ADR-002 only proposes today.
5. **OEM / strategic integrations** — the accountability layer inside someone
   else's autonomy stack.
6. **Production hardening** — the open items in `PRODUCTION_READINESS.md`:
   TLS, rate limiting, KMS/HSM, backups, DR/BCP, metrics, runbook.
7. **Compliance / certification** — control-framework mapping for the target
   jurisdictions and sectors.
8. **Deployment and field engineering** — the discipline of running this on
   someone else's machines.
9. **Expanded observer mechanisms** — remote and off-host observation, which
   the observation-integrity decision record explicitly deferred to a roadmap
   rather than shipping under time pressure.
10. **International go-to-market** — category creation is a real cost and is
    budgeted rather than assumed away.

---

## 3. Milestone-based capital deployment

Milestones are **evidence gates**, not calendar events. Each names what must
become true, and what remains untrue afterwards.

### MILESTONE 1 — AIRI + Sniffer Dog production validation
- **Becomes true:** a non-synthetic agent framework, under representative load,
  with corroboration rates measured and the false-positive rate of
  `uncorroborated` characterised.
- **Unlocks:** the software core can be described as TRL 6.
- **Still untrue:** anything physical.
- **Why it is first:** the AIRI migration plan gates its own stage 4 on exactly
  this measurement, and a detection signal whose false-positive rate has never
  been characterised should not be put in front of an operator.

### MILESTONE 2 — Physical robotics validation
- **Becomes true:** roadmap stages 2 → 3 → 4; an external mechanism produces an
  `ObservationRecord` for a physical quantity.
- **Unlocks:** physical autonomous-system accountability leaves TRL 2–3.
- **Still untrue:** that it generalises beyond one cell and one robot.
- **Why it is the pivotal one:** it is the single step that converts "one
  accountability core, many autonomous worlds" from a design statement into an
  engineering result.

### MILESTONE 3 — UAS / PX4 validation
- **Becomes true:** stages 5 → 6 → 7; a real flight with post-mission offline
  verification by a party that did not produce the package.
- **Still untrue:** that any navigation quantity is establishable without the
  stage-4 mechanism.

### MILESTONE 4 — First defence / industrial pilot
- **Becomes true:** an operationally representative deployment with operator-held
  anchors and an agreed false-positive budget.
- **Precondition:** the seven-item pre-production blocker list is closed and an
  independent security assessment has been completed and remediated.
- **Still untrue:** recurring revenue.

### MILESTONE 5 — Recurring paid deployments
- **Becomes true:** paid, renewing, referenceable customers.
- **Still untrue:** distribution leverage; this is direct sales.

### MILESTONE 6 — OEM / platform integration
- **Becomes true:** the accountability layer embedded in a third-party autonomy
  platform.
- **Why it matters most commercially:** the layer is worth more embedded than
  sold standalone, and the defence-autonomy platform vendors are the channel.

---

## 4. Value-creation logic

```
TECHNICAL DE-RISKING
  → PHYSICAL VALIDATION
    → DEFENCE / INDUSTRIAL PILOTS
      → PRODUCTION HARDENING
        → COMMERCIAL REFERENCES
          → RECURRING REVENUE
            → OEM INTEGRATION
              → NEXT INSTITUTIONAL ROUND
```

**Planning assumption for the next step:** a USD 8–10M institutional round at an
**illustrative** USD 40–60M pre-money range — **only if** the milestone evidence
supports it.

This is a planning framework. It is not a forecast, not a guarantee, and not a
statement that any investor has indicated such terms.

---

## 5. Valuation planning framework

**Internal strategic planning ranges. Not third-party valuations, not fairness
opinions, not guaranteed future company values. No independent valuer has
assessed this company.**

### Current

| frame | range |
|---|---|
| Engineering / technology reference assessment | **₹30–50+ Cr** internal strategic range |
| Institutional fundraising planning | **₹30–35 Cr** pre-money target range |
| Strategic floor | **approximately ₹25 Cr** pre-money |
| Potential strategic premium | **₹40 Cr+** where a highly strategic investor materially accelerates validation or adoption |

### Post-validation milestone ladder

Each rung is gated on evidence that does not yet exist. A rung is not reached
by time passing.

| milestone | planning class | evidence gate |
|---|---|---|
| Physical reference deployment | **₹50–80 Cr class** | a physical quantity established by an independent mechanism (roadmap stage 4) |
| Defence / industrial pilot | **₹75–120 Cr class** | operationally representative deployment, operator-held anchors, independent security assessment complete |
| Recurring commercial deployments | **₹150 Cr+ class** | paid, renewing, referenceable |
| OEM / platform integration | **₹300 Cr+ potential strategic scale** | the layer embedded in a third-party autonomy platform |

---

## 6. What a technical diligence team will find, stated first

A diligence process will surface all of the following. They appear here because
a document that omits them is worth less than one that does not.

1. **The strongest work is not on `main`.** 228 commits and every material
   capability live on an unmerged branch. A reviewer cloning the default branch
   sees a fraction of the system.
2. **No physical validation has occurred.** The robotics profile says *"No robot
   was involved."*
3. **No third-party security assessment has been performed.**
4. **No defence deployment, pilot, trial or contract is evidenced.**
5. **No post-quantum cryptography exists** on the branches that carry the
   product, despite PQC appearing in the patent dossier.
6. **No hardware root of trust exists.** ADR-002 is PROPOSED.
7. **Patent applications are pending and no filing particulars appear in the
   repository.** They must be obtained from counsel.
8. **The commits carrying the work have a single machine author identity**, and
   a human conception / reduction-to-practice record does not exist in the
   repository (audit finding IP-3).
9. **Root is assumed benign.** The observation-integrity mitigation defeats a
   `CAP_BPF` adversary, not a root or kernel-level one, and says so.
10. **Production readiness is incomplete** — TLS, rate limiting, KMS/HSM,
    backups, DR/BCP, metrics and a runbook are all open.

### What the same diligence will also find

1. **1,691 tests passing, 0 failing, 0 warnings** on the assessed head, across
   165 test binaries spanning the protocol *and* the service tier in one
   command.
2. **A reproduced attack on the accountability system's own observer**, closed
   in production without weakening `CANNOT_PROVE`, `EvidenceCeiling`, or the
   single reconciler authority.
3. **An offline verifier that refuses eight mutations of a live proof package**,
   as a separate process, with no clock and no network.
4. **An adversarial test posture that is unusual** — including a delegation hop
   validly signed by the genuine key that must still be rejected for
   over-delegating.
5. **A forensic audit of the codebase that the codebase then acted on**, with
   the two P0 findings closed and independently re-verified, and a third P0
   found by the remediation work itself and recorded rather than absorbed.

---

## 7. Use of proceeds — indicative allocation

**Indicative only. Not a budget, not a commitment.**

| area | indicative share | rationale |
|---|---|---|
| Physical validation engineering (stages 2–4) | ~30% | the pivotal milestone; everything above TRL 4 on the physical axis depends on it |
| Production hardening + independent security assessment | ~20% | the pre-production blocker list gates every pilot |
| Defence / industrial pilot delivery and field engineering | ~20% | the first deployment where evidence is consumed adversarially |
| UAS / PX4 validation (stages 5–7) | ~12% | parallel vertical, shares the software boundary |
| OEM / integration engineering and partnerships | ~10% | the channel that makes the layer worth more embedded |
| Compliance, certification mapping, IP prosecution | ~8% | jurisdiction-specific and unavoidable for defence and critical infrastructure |

---

## 8. Risk register for the round

| risk | severity | mitigation |
|---|---|---|
| Physical validation proves harder than modelled | **high** | stage 4 is scoped as the decisive gate and is funded first; the profiles already enumerate the five unobserved boundaries, so the difficulty is characterised rather than discovered late |
| Category does not exist as a budget line | **high** | sell alongside identity and runtime-security incumbents rather than against them; the co-existence argument (a co-resident eBPF tool blinds a tracepoint observer) is a concrete reason an existing Falco/Tetragon customer needs this |
| Platform consolidation absorbs the adjacent market | **medium** | the consolidators bought identity and posture, not execution evidence; the response is interop, not a race |
| Root/kernel adversary boundary is challenged in diligence | **medium** | it is stated, not hidden; off-host and hardware-rooted observation are on the roadmap with the trade-offs already analysed |
| Single-author commit history complicates IP | **medium** | establish the human conception record now, before it is asked for |
| Key material at rest | **medium** | KMS/HSM is an open production item; a passphrase-wrapped backend already exists as an interim |

---

## 9. The one-line summary

**Vanian makes autonomous systems cryptographically accountable** — demonstrated
today for software autonomy on a real Linux kernel against an independent
observer, including a reproduced attack on the observer itself and its
production mitigation; and designed, but **not yet validated**, for physical
autonomy. The USD 10M Pre-Series A target exists to close exactly that gap.
