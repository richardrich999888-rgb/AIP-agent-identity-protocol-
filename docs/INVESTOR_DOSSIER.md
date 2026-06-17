# AIP — Investor Dossier

**Agent Identity Protocol · "Accountability infrastructure for autonomous AI."**

> **Honesty notes (read first).** This dossier is written for technical
> diligence. Three disciplines apply throughout:
> 1. **Technical claims are code-backed.** Everything in §2 is implemented and
>    tested in this repository; commands to reproduce are given. Where a
>    capability is *not* built, it is labeled **ROADMAP**.
> 2. **Traction is stated truthfully.** AIP is **pre-revenue, pre-design-
>    partner.** There are no customers, no signed pilots, and no auditor
>    acceptance letter yet. The asset today is a working, independently
>    verifiable accountability stack + an open specification — engineering
>    traction, not commercial traction.
> 3. **Market/competitor figures are estimates.** TAM/SAM/SOM are
>    founder/analyst estimates with stated methodology, not audited data.
>    Competitor funding numbers and team bios are marked `[VERIFY]` /
>    `[FOUNDER INPUT]`. Only figures with a hard public source (e.g. EU AI Act
>    penalties) are asserted.

---

## SECTION 1 — EXECUTIVE SUMMARY

**Vision.** As enterprises hand consequential decisions to autonomous AI
agents, the binding question becomes not "what did the system log?" but "who
authorized this action, within what limits, and can we prove it to a
regulator or a court — years later, without trusting the vendor?" AIP exists
to make that answer **cryptographic** rather than a matter of trust.

**Mission.** Be the accountability layer of the agent economy: every
consequential agent action produces a portable, tamper-evident **EvidencePacket**
binding the action to the human-rooted chain of delegated authority behind it.

**Product & differentiation (one line).** Identity systems answer *who may
act*; observability answers *what happened*. AIP answers **"under whose
delegated authority, within what limits, and provably unaltered"** — and
emits that as an artifact a third party can verify **offline**. This is the
gap neither IAM (Okta/Entra) nor observability (Datadog/Splunk) fills.

**What exists today (verifiable).** A tested Rust stack: agent identity,
n-hop signed delegation with mathematical scope attenuation, a 14-rule
verification engine, an accountability graph, a **signed audit-export bundle**
an auditor verifies offline with a standalone CLI, an authenticated
multi-tenant HTTP service with a PostgreSQL backend, CI/security/release
pipelines, and an **open EvidencePacket specification.** `cargo test` is green
across the workspace; a ₹5-crore loan demo and the export→verify flow are
reproducible end-to-end.

**Market (estimate; see §3 for methodology).** AIP sits at the intersection of
three fast-growing markets — agentic AI platforms, AI governance/compliance,
and AI security. The *directly addressable* slice is **AI-accountability /
audit-evidence for regulated enterprises**, which barely exists as a named
category today. Illustrative sizing: SAM (regulated enterprises deploying
consequential agents, 2027–2030) on the order of **$1–4B**; near-term SOM
(design-partner + early enterprise, 24–36 months) in the **low tens of
millions of ARR** if the category forms. These are estimates requiring
validation, not forecasts.

**Status & milestones.** Phase 1 (Design-Partner Validation). Engineering
milestones **met**; commercial milestones **not yet started** (0 design
partners, 0 auditor acceptances, $0 ARR). The next three proof points are:
(1) one regulated design partner running read-only; (2) one auditor accepting
an EvidencePacket bundle as evidence; (3) first paid workflow.

**Investment thesis.** Right problem, right time, real engineering, no
distribution yet. The wager is on **(a)** the regulatory + agentic-deployment
wave making "prove what your agent did" a compulsory question within
18–36 months, and **(b)** AIP converting a genuine engineering head-start and
an open standard into category ownership before identity/observability
incumbents bolt on a "good-enough" feature. This is a bet on founder execution
and timing, supported by — not carried by — the code.

**The ask (proposal).** Pre-seed **$1.5–3.0M** for ~10–15%, 18-month runway.
Use of funds: ~55% engineering (productionize: KMS/HSM, client-side signing
SDK + ingest, IAM bridge, hardening), ~25% design-partner/GTM (land 2–3
regulated partners + an auditor acceptance), ~10% security/compliance
(independent assessment, control-framework mapping), ~10% G&A.
*Valuation/round are a proposal, not a term sheet; they should be priced on the
founder and the design-partner outcomes, with the repo as evidence of build
capability.*

**Why category-defining (if it works).** Accountability evidence compounds:
once an enterprise's audit procedures and a regulator's expectations are
written around your EvidencePacket format, and years of anchored evidence
accrue, switching means re-architecting compliance and abandoning history. You
can re-platform software; you cannot re-witness the past.

---

## SECTION 2 — TECHNICAL ARCHITECTURE

All claims here map to code in this repo. Reproduce:

```bash
cd aip-standalone && cargo test --workspace        # core/protocol/verify
cd ../aip-service && cargo test                     # service (auth, tenant, export)
cargo run -p aip-protocol --example loan_approval   # ₹5cr demo
```

### 2.1 The three layers

**Layer 1 — Identity (`aip-core`, `aip-crypto`).**
- Each agent has an `AIP-ID` derived as
  `aip1 · base58(SHA-256(pubkey ‖ provenance)[..26]) · base58(checksum)`.
  Cryptographic primitives: **Ed25519** (RFC 8032) signatures, **SHA-256**,
  Base58. Verifiers recompute the ID → it is bound to the key + a provenance
  commitment (model/env/toolchain hashes).
- Lifecycle: Pending→Active→Suspended→Revoked state machine; cascade
  revocation invalidates a token's whole subtree.
- **IAM integration (Okta/Entra): ROADMAP, not built.** Today identities are
  self-derived; bridging to enterprise IdPs (mapping AIP-IDs ↔ workforce
  identities, SCIM/OIDC) is a funded work item, not a current capability.
- **Honest limitation:** the provenance triple is a *caller-supplied
  commitment*, not a verified attestation that the hash equals a real model
  build. Verified model/TEE attestation is ROADMAP. (The current hardware-
  attestation module is flagged EXPERIMENTAL and performs structural checks
  only — see `AUDIT_CORRECTIONS.md`.)

**Layer 2 — Authority (`aip-core::delegation`, `::capability`).**
- A **scope** is `{allowed, denied}` action sets. Delegation computes the
  lattice **MEET** (intersection): a child's scope can never exceed its
  parent's; empty intersection (⊥) is rejected.
- Delegation chains are **n-hop, per-hop Ed25519-signed**, parent-linked by
  JTI, depth-limited (≤8), and offline-verifiable. Agent-to-agent delegation
  is `create_sub_delegation`.
- Validation (`verify_delegation_chain`) checks, per hop: signature, parent
  linkage, depth monotonicity, scope subset — returning the most-attenuated
  effective scope at the leaf.

**Layer 3 — Accountability (`aip-protocol`).**
- **EvidencePacket v1** (`AEP1`): agent identity, root authority + signed
  scoped token, delegation chain, decision (inputs/rationale by hash),
  per-action attestations (each signed and **bound to its decision**),
  optional trace + receipt bindings (counterparty can countersign), a
  **trust floor**, a SHA-256 `packet_hash` over a **canonical length-prefixed
  encoding**, and the agent's Ed25519 signature over that hash.
- **Verification engine:** 14 named rules (structure, ID binding, canonical
  hash, agent signature, root-token signature, delegation chain, authority-
  chain connectivity, scope authority, revocation, temporal validity, action
  attestations, trace/receipt bindings, trust-floor). No short-circuit; every
  rule reported. Trust floor is **derived from evidence**, never asserted:
  `UNVERIFIED → AGENT_SIGNED → AUTHORITY_BOUND → COUNTERPARTY_SIGNED`.
- **Accountability graph:** reconstructs Human→Authority→Agent→Decision→
  Action→Receipt; validates connectivity; exports JSON + Graphviz DOT.
- **Evidence Vault & retrieval:** `EvidenceStore` trait with JSONL and
  **PostgreSQL** backends (append-only, tenant-scoped, indexed; authority
  nodes/edges materialized). `aip-migrate` imports JSONL→PG idempotently.
- **Verification portal = the bundle + CLI.** `GET /v1/evidence/{id}/export`
  produces a **signed ZIP** (evidence, report JSON + plain-language Markdown,
  authority graph JSON/DOT, manifest, Ed25519 manifest signature).
  `aip-verify bundle.zip` verifies it **offline** (PASS/WARNING/FAIL); spec in
  `docs/AUDIT_EXPORT_SPEC.md`.

### 2.2 Technical differentiators

- **Not "logging with signatures."** A log records an event; an EvidencePacket
  binds an action to a *verified chain of delegated authority* and refuses to
  validate if the action exceeded that authority (lattice attenuation). The
  authority semantics — not the signature — are the point.
- **vs. IAM.** IAM gates access (who may call). AIP produces the *after-the-
  fact, portable, offline-verifiable proof* of who authorized what, which IAM
  does not emit. AIP sits *above* IAM and should consume its identities (the
  ROADMAP bridge), not replace it.
- **vs. observability.** Datadog/Splunk are mutable, central, and not
  authority-aware; they answer "what happened" for operations, not "prove it
  to a regulator." AIP is tamper-evident, offline-verifiable, and authority-
  bound. They are complementary (AIP can bind to an OTel trace id).

### 2.3 Technical risks & mitigations

| Risk | Mitigation / status |
|---|---|
| **Key custody** (today: single on-disk service key; agent keys handled app-side) | KMS/HSM + client-side signing SDK are the top funded items; bundle signature already separates "who exported" from "what happened" |
| **Provenance ≠ attestation** (commitment is self-declared) | Documented; verified TEE/model attestation is ROADMAP; does not weaken the authority/integrity guarantees, only the model-origin claim |
| **Authority-graph query cost** (per-query rebuild; ~475ms at 10k packets) | Authority tables already materialized in PG; indexed-query path is a follow-up (no schema change) |
| **Format/spec churn** breaking stored evidence | Wire format is versioned (`AEP1`/v1); verification is version-pinned; append-only store |
| **Crypto agility** (Ed25519 today) | Algorithm identifier reserved; PQC (ML-DSA) is a documented migration path |
| **Adoption/standard risk** (engineering, not technical) | Open spec + free offline verifier; see §5/§9 |

### 2.4 Technology stack

- **Language:** Rust (memory-safe; small auditable surface; static binaries
  suitable for air-gapped/edge).
- **Crypto:** `ed25519-dalek`, `sha2`, Base58; raw + enveloped signing.
- **Service:** `axum`/`tokio`; API-key auth (SHA-256-hashed, tenant+role,
  fail-closed); `EvidenceStore` over JSONL or `tokio-postgres`/`deadpool`.
- **Tooling:** `aip-verify` (clap CLI), `aip-migrate`, `banking_demo`.
- **Ops:** GitHub Actions (fmt, clippy `-D warnings`, test, `cargo audit`,
  `cargo deny`, coverage; gitleaks + trivy security workflow; multi-target
  release), Docker + compose (service + Postgres), `deny.toml`.
- **Production targets (ROADMAP):** KMS/HSM keys + rotation, client-side
  signing SDKs (TS/Python), IAM bridge, transparency-log anchoring of packet
  hashes, HA + backup/DR, SOC 2.

---

## SECTION 3 — MARKET OPPORTUNITY

### 3.1 Sizing (estimates — methodology stated; figures require validation)

We deliberately do **not** present a fabricated top-down TAM table with false
precision. Methodology instead:

- **Top-down anchors (directional, public forecasts vary widely):** agentic-AI
  platform spend, AI-governance/compliance tooling, and AI-security are each
  multi-billion and growing >40% CAGR per mainstream analyst commentary
  (Gartner/McKinsey/BCG have all published bullish agentic-AI adoption
  outlooks). `[VERIFY exact figures before use in a deck.]`
- **Bottom-up (the number that matters):** AIP's *directly addressable* buyers
  are regulated enterprises deploying **consequential** agent workflows.
  Estimate: ~2,000–5,000 such enterprises globally (GSIBs, large banks,
  insurers, health systems, gov) × an accountability/audit-evidence ACV of
  **$50k–$500k** → an order-of-magnitude SAM of **$1–4B** as the category
  matures (2027–2030). **SOM (24–36 mo):** capturing 20–50 of these at pilot→
  early-enterprise ACV → **low-tens-of-$M ARR**, *contingent on the category
  forming and on AIP landing the first auditor acceptance.*

> Intellectually honest stance: the category is **nascent to non-existent**
> today. The TAM is a bet that "agent accountability" becomes a budget line,
> not a measurement of one that exists.

### 3.2 Market drivers
- **Agentic deployment crossing from pilot to production** in regulated
  functions (payments, underwriting, claims, servicing) — where actions have
  legal/financial consequence and existing audit answers break.
- **Regulation forcing traceability/logging** (see §3.4).
- **"Shadow AI":** high-privilege agents as a new insider-threat class that
  current tooling cannot attribute or constrain provably.

### 3.3 Timing — why now
- **Not 3 years ago:** too few consequential agents in production; no
  regulatory forcing function; the pain was hypothetical.
- **Not in 3 years:** by then identity/observability incumbents or an open
  standard may have filled the gap; the category-naming window closes.
- **Now:** agent deployments are scaling *and* the EU AI Act's high-risk
  obligations phase in through **2026–2027**, creating a compliance deadline
  that converts "nice-to-have" into "required" — before a default winner
  exists. The window is roughly **18–36 months.**

### 3.4 Regulatory tailwinds
- **EU AI Act (hard facts):** penalties up to **€35M or 7% of global annual
  turnover** for prohibited-practice violations (lower tiers €15M/3% and
  €7.5M/1%); high-risk-system obligations — including **record-keeping,
  logging, traceability, and human oversight** — phase in, with key high-risk
  obligations landing around **2026–2027**. These map almost directly onto
  what an EvidencePacket provides. *(Exact dated milestones: `[VERIFY]` against
  the current Act text before publishing.)*
- **US:** no single federal AI law; a patchwork of state laws and sectoral
  guidance (e.g. model-risk expectations like SR 11-7 in banking, NIST AI RMF
  as a voluntary-but-influential framework). Demand here is audit/risk-driven
  rather than statute-driven.
- **India:** evolving AI-governance guidance (advisory/principles stage);
  relevant for a sovereign/defence angle (see the iDEX submission in
  `docs/idex_open_challenge/`).
- **How this creates AIP demand:** every regime that mandates *traceability of
  automated decisions* or *human accountability* turns AIP from a vitamin into
  a painkiller — provided an auditor will accept the evidence (the #1
  unproven assumption, §7.2).

---

## SECTION 4 — THE CUSTOMER

### 4.1 Primary buyer persona
- **Title:** Head of Internal Audit / Head of AI Governance / Chief Risk
  Officer (economic buyer); champion often the platform/security lead already
  piloting agents.
- **Company:** regulated enterprise with consequential agent workflows.
- **Pain:** cannot prove, to an auditor/regulator, who authorized an
  autonomous action or that the record is unaltered; mutable logs; "shadow AI."
- **Budget:** GRC / model-risk / security budgets (already exist).
- **Process:** champion-led pilot → risk/security/legal review → procurement.
- **Timeline:** **6–12 months** typical for regulated enterprise infra.

### 4.2 Segments (priority order; "why now" = consequential agents + audit scrutiny)
1. **Tier-1 banks / GSIBs** — highest scrutiny, biggest budgets, longest
   cycles; the reference logo that unlocks everything. Buyer: CRO/Head of
   Internal Audit. Budget: $100k–$500k+. Cycle: 9–12+ mo.
2. **Large/European banks** — EU AI Act exposure is the sharpest forcing
   function. Buyer: Head of Compliance/Model Risk. $75k–$300k. 6–12 mo.
3. **Insurers** — automated claims/underwriting decisions, dispute exposure.
   Buyer: Chief Risk/Compliance. $50k–$250k. 6–12 mo.
4. **Health systems** — HIPAA accountability, clinical-decision liability.
   Buyer: CISO/Compliance. $50k–$200k. 9–12 mo.
5. **Sovereign/defence (e.g. iDEX path)** — command accountability, non-
   repudiation, air-gapped verification. Buyer: program/security cell.
   Grant-funded pilots possible. Bespoke cycle.

> All "why they buy now," budgets, and named-account claims above are
> **founder hypotheses for discovery**, not validated pipeline.

### 4.3 Buying process
- **Champion:** internal audit / AI-governance lead.
- **Buyer:** CRO / Head of Compliance / CISO.
- **Influencers:** General Counsel, Chief Data Officer.
- **Implementer:** platform/security engineering.
- **Hurdles:** security review, data-processing/DPA, vendor-viability, on-prem
  requirement, certifications (SOC 2 — a gap).
- **Length:** 6–12 months; pilots can start faster if **non-gating** and
  **read-only**.

### 4.4 Design-partner path
- **Definition:** a regulated enterprise that deploys AIP read-only on one
  workflow, gives structured feedback, and (ideally) does a staged auditor
  walkthrough.
- **AIP offers:** free/low-cost pilot, white-glove integration, influence over
  the spec, an Evidence Vault for one workflow.
- **AIP asks:** access to a representative workflow, a security review slot, an
  auditor introduction, and a reference on success.
- **How many:** **2–3** is sufficient to validate Phase 1; **1 auditor
  acceptance** is the true unlock.
- **Success criteria:** see §7.

---

## SECTION 5 — COMPETITIVE LANDSCAPE

> Competitor funding/traction figures from the brief are **`[VERIFY]`** — do
> not assert them in front of investors without a source.

### 5.1 Direct / adjacent
Emerging "identity/access for AI agents" and "AI security/governance" startups
(e.g. agent-IAM and agent-security entrants). **Strength:** funded, access-
focused, some enterprise traction. **Weakness vs. AIP:** access control ≠
**portable, offline-verifiable accountability evidence.** None (to our
knowledge) makes the auditor's artifact the product. `[VERIFY competitor
positions.]`

### 5.2 Indirect (the real gravity)
- **Microsoft Entra (+ Copilot):** owns enterprise identity + the agents;
  **highest** threat — could ship "agent audit" as a checkbox. AIP's defense:
  neutrality (auditors prefer third-party attestation) + offline/open
  verification + cross-vendor scope.
- **Okta:** workforce identity; could extend to agents. Medium threat;
  partner/acquirer candidate.
- **Datadog / Splunk:** observability/logging; medium threat; complementary
  ("they show what happened; AIP proves it"); acquirer candidates.
- **Cloudflare / SPIFFE-SPIRE:** access/workload identity; SPIFFE is the
  substrate AIP should build *on*, not fight.

### 5.3 Differentiation / 5.4 Moat
- **Not another IAM/observability tool:** it's the **evidence** layer above
  both — the artifact a third party verifies without trusting the vendor.
- **Moats (aspirational, must be earned):** (a) **standard** — if the
  EvidencePacket format becomes what auditors ask for; (b) **switching cost** —
  compliance pipelines + years of anchored evidence; (c) **trust/references** —
  banking-first pilots are slow to win and slow for others to replicate;
  (d) **graph semantics** — authority relationships are non-trivial.
  **Honest:** the *code* is replicable by a strong team in a quarter; the moat
  is distribution + standard + accumulated evidence, none of which exist yet.

---

## SECTION 6 — BUSINESS MODEL

### 6.1 Revenue model (proposed)
| Tier | Price | For |
|---|---|---|
| Discovery | $0 | OSS verifier + SDK; developers/early adopters |
| Pro (Evidence) | ~$2k/mo | EvidencePacket generation + verification portal; compliance teams |
| Enterprise (Vault) | $10k+/mo | Authority graph, integrations, audit exports, on-prem; regulated buyers |

Land-and-expand: one high-risk workflow → many; per-workflow / per-evidence-
volume expansion.

### 6.2 Projections — **illustrative model, not a forecast**
The brief's ramp ($0.5M→$5M→$25M→$75M→$200M) is a **standard infra hockey-
stick template.** It is achievable *only if* Phase-1/2 proof points land. We
present it as a scenario, explicitly contingent on: first auditor acceptance
(year 1), ~repeatable sale (year 2), and standard traction (year 3). Treat
Year-1 ARR as **$0–0.5M** and everything beyond as conditional.

### 6.3 Unit economics (assumptions to validate)
- **ACV:** $24k (Pro) – $120k+ (Enterprise).
- **CAC:** high early (founder-led, 6–12 mo cycles) — likely **$50k–$150k**
  per enterprise logo initially; falls with references/channel.
- **LTV:** high if switching costs materialize (multi-year, expanding);
  **LTV:CAC > 3** is plausible *post*-reference, not at first sale.
- **Gross margin:** software-typical **80%+** (on-prem/support drags early).
- **Payback:** likely **>18 mo** for first logos; improves with land-and-expand.

### 6.4 Path to $1B ARR (necessary conditions, not a promise)
1. EvidencePacket adopted as a **de facto audit standard** (auditors request
   it).  2. Embedded in **agent frameworks/clouds** (distribution).
3. **Cross-party verification** network effects (A's agent ↔ B's systems).
4. Expansion from "evidence" to a governance control-plane.
Miss any one and the ceiling is a strong acquisition, not a standalone $1B.

---

## SECTION 7 — ROADMAP & MILESTONES

Engineering for Phases is **largely built**; the gating items are commercial
and hardening.

- **Phase 1 — Design-Partner Validation (M1–6):** 3 regulated enterprises
  running read-only ingest; ≥1 paid pilot. *Status: not started (0).*
  Prereqs done: working stack, demo, eval pack (`docs/design_partner/`).
- **Phase 2 — Auditor Validation (M4–8):** **written auditor acceptance of an
  EvidencePacket bundle.** *The single most important unlock; unproven.*
  Prereqs done: offline verifier + signed bundle + spec.
- **Phase 3 — First Paid Enterprise (M6–10):** $10k/mo; survives security/
  legal/procurement. Prereq gaps: SOC 2, KMS/HSM, IAM bridge.
- **Phase 4 — Expansion & Renewal (M10–12):** 3+ workflows, renewal, reference.
- **Phase 5 — Market Expansion (Y2–3):** adjacent regulated verticals;
  channel (audit/consulting firms); open the spec to drive adoption.
- **Phase 6 — Scale (Y3–5):** international; governance platform; exit/IPO
  optionality.

**PMF scores** in the brief's table are **forward-looking targets**, not
current state. Current honest PMF: **pre-PMF (<25%)** until a design partner
and an auditor say yes.

---

## SECTION 8 — TEAM

`[FOUNDER INPUT REQUIRED — do not ship to investors with placeholders.]`
- **Founders / technical team:** `[names, backgrounds — esp. cryptography,
  distributed systems, regulated-enterprise sales]`.
- **What the repo demonstrates about the team:** ability to ship a coherent,
  tested, secure Rust system with CI/security discipline and an open spec —
  credible *build* capability. Investors will still need the **GTM / regulated-
  sales** capability evidenced.
- **Key hires (0–12 mo):** (1) founding GTM/solutions lead with banking-audit
  relationships; (2) security/platform engineer (KMS, hardening); (3) part-
  time compliance/accreditation advisor.
- **Advisory board (target):** an ex-Big-4 audit partner, a bank CRO/model-risk
  leader, a cryptographer, an EU-AI-Act counsel. `[recruit]`

---

## SECTION 9 — COMPETITIVE ADVANTAGE

- **Defensibility (honest):** not the code. It is **(a)** first-mover on
  *accountability-as-evidence* with an open, offline-verifiable format;
  **(b)** banking/regulated trust + references that take years to earn;
  **(c)** accumulated, anchored evidence + compliance-pipeline lock-in once
  adopted.
- **Why incumbents don't do it in 6 months:** they *can* build the tech; what
  they cannot quickly manufacture is **neutral, third-party, offline-verifiable
  trust** (auditors structurally prefer independent attestation over "Microsoft
  audits its own agents") and an adopted **standard**. The risk that they ship
  "good enough" is real and is the top bear case.
- **Standard playbook:** open the spec + free verifier → get it into agent
  frameworks (MCP/LangGraph) → get **auditors to ask for it** (demand from the
  buyer's buyer). Standard = the format the verifier on the auditor's desk
  expects.
- **If not first:** the category likely consolidates into an identity or
  observability suite, and AIP becomes a feature/acqui-hire rather than a
  platform.

---

## SECTION 10 — RISKS

| Risk | Prob. | Impact | Mitigation |
|---|---|---|---|
| Incumbent ships "good-enough" agent audit | Med-High | High | Neutrality, open spec, offline verify, banking references |
| Open standard emerges from elsewhere | Med | High | **Lead** the standard; open-source core + verifier |
| Auditors won't accept the evidence | Med | **Existential** | Phase-2 is explicitly this proof; engage Big-4 early |
| Sales cycles slower than runway | High | High | Non-gating read-only pilots; land-and-expand; tight burn |
| Market timing early (few consequential agents yet) | Med | High | Defence/sovereign + early-adopter banks; keep burn low |
| Trust/vendor-viability barrier | High | Med | Open verifier + on-prem + portable, self-verifiable evidence |
| Key-management / security finding in diligence | Med | High | KMS/HSM + independent assessment are top funded items |

**Existential risks:** (1) auditors never treat it as evidence; (2) the agent-
accountability budget line never forms in the funding window; (3) an incumbent
makes it a free checkbox before references accrue. **Plan B:** the strongest
asset (offline-verifiable evidence + open spec) is an attractive **acquisition**
for an IAM/observability/GRC platform even if the standalone company stalls.

---

## SECTION 11 — INVESTMENT THESIS

**Why invest:** a real, tested accountability stack aimed at a question
regulation will force regulated enterprises to answer within ~18–36 months,
with no incumbent yet owning it and an open-standard wedge available.

**Bull case:** EvidencePacket becomes the audit standard for agent actions;
double-digit Fortune-500 adoption; $1B+ ARR in 7–10 yrs; category-defining
infra; $10B-class outcome.

**Bear case:** Microsoft/AWS/Okta ship a competitive feature; an open standard
emerges from elsewhere; enforcement slips; cycles outrun runway; "good enough"
wins. Probability-weighted, the **most likely** outcome today is a modest
acquisition; the **tail** is category-defining. That asymmetry is the
investment.

**The ask (proposal):** **$1.5–3.0M pre-seed**, ~10–15%, 18-mo runway.
**Use of funds:** Engineering ~55% (KMS/HSM, signing SDK + ingest, IAM bridge,
hardening, HA), GTM/design-partners ~25%, Security/Compliance ~10% (independent
assessment + control-framework mapping), G&A ~10%. **Milestone gates for a
seed:** 2–3 design partners live + **1 written auditor acceptance** + first
paid workflow.

---

## SECTION 12 — ONE-PAGE SUMMARY

1. **Problem:** organizations can't prove who authorized an autonomous AI
   action, within what limits, or that the record is unaltered.
2. **Solution:** AIP emits a tamper-evident, offline-verifiable EvidencePacket
   binding every consequential agent action to its human-rooted chain of
   delegated authority.
3. **Market:** an emerging "AI accountability / audit-evidence" category for
   regulated enterprises, pulled forward by the EU AI Act and agent deployment
   (SAM est. low-single-digit $B as it forms — to be validated).
4. **Traction (honest):** pre-revenue, pre-design-partner; a working, tested,
   independently verifiable stack + open spec + reproducible demos — and a CI/
   security/release pipeline. **0 customers, 0 auditor acceptances, $0 ARR.**
5. **Team:** demonstrated ability to ship secure, tested infrastructure;
   GTM/regulated-sales capability `[to be evidenced]`.
6. **Ask:** $1.5–3.0M pre-seed to land 2–3 regulated design partners and the
   first auditor acceptance, and to productionize (KMS, SDK, IAM bridge).
7. **Opportunity:** own the accountability layer of the agent economy — a
   standard + accumulated-evidence moat where you can re-platform code but
   never re-witness history.

---

### Appendix — verify the technical claims yourself
```bash
cd aip-standalone && cargo test --workspace
cargo run -p aip-protocol --example loan_approval        # build → verify → tamper-detect
cargo run -p aip-protocol --example loan_approval > /tmp/p.txt   # real EvidencePacket
cd ../aip-service && cargo test                          # auth, tenant isolation, HTTP export
# Offline auditor verification of a signed bundle:
#   aip-verify bundle.zip [--report|--json|--trust <id>=<hex>]
```
Source-of-truth documents: `AIP_SPEC.md`, `docs/AUDIT_EXPORT_SPEC.md`,
`docs/PRODUCTION_READINESS.md`, `AUDIT_CORRECTIONS.md`,
`docs/design_partner/`.
