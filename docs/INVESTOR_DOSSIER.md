# AIP — Investor Dossier (Full Edition)

**Agent Identity Protocol · "The accountability infrastructure for autonomous AI."**
**Stage:** Pre-PMF (Phase 1 — Design-Partner Validation) · **Round:** Pre-seed

---

> ## ⚠️ Reading contract (for technical diligence)
> This dossier is written to be scrutinized. Three rules hold throughout:
> 1. **Technical claims are code-backed** — every capability in §2 is
>    implemented and tested in this repository, with commands to reproduce.
>    Unbuilt items are labeled **ROADMAP**.
> 2. **Traction is stated truthfully** — AIP is **pre-revenue, pre-design-
>    partner**: 0 customers, 0 signed pilots, 0 auditor acceptances, $0 ARR.
>    The asset is a working, independently verifiable stack + an open spec.
> 3. **Market / competitor / financial figures are ESTIMATES** with stated
>    methodology — **not** audited data and **not** sourced forecasts unless
>    marked. Cells marked `[VERIFY]` must be sourced before external use; cells
>    marked `[FOUNDER INPUT]` need the founder. Only hard public facts (EU AI
>    Act penalties) are asserted outright.
>
> A reader should finish this document able to separate *what is built* (high
> confidence) from *what is believed about the market* (hypothesis).

---
---

# SECTION 1 — EXECUTIVE SUMMARY

## 1.1 Vision & mission
**Vision.** As enterprises delegate consequential decisions to autonomous AI
agents, the load-bearing question shifts from *"what did the system log?"* to
*"who authorized this action, within what limits, and can we prove it — to a
regulator or a court, years later, without trusting the vendor?"* Today that is
answered with mutable logs and trust. **AIP makes it cryptographic.**

**Mission.** Be the accountability layer of the agent economy: every
consequential agent action emits a portable, tamper-evident **EvidencePacket**
binding the action to the human-rooted chain of delegated authority behind it,
verifiable **offline** by any third party.

## 1.2 Core product & differentiation
Three layers; the customer buys Layer 3, Layers 1–2 are the machinery.

| Layer | Question | Customer sees |
|---|---|---|
| 1 — Identity | Who is the agent? | Agent registry |
| 2 — Authority | Who granted permission, and how did it flow? | Delegation graph |
| 3 — Accountability | What happened, and can you prove it? | **Evidence Vault + Verification Portal** |

**The one-line wedge:** identity systems answer *who may act*; observability
answers *what happened*. **AIP answers "under whose delegated authority, within
what limits, provably unaltered" — and emits it as an artifact a third party
verifies offline.** Neither IAM (Okta/Entra) nor observability (Datadog/Splunk)
produces that artifact.

## 1.3 Market opportunity (estimates — see §3 for methodology)
- **TAM (2030, blended agentic-AI + AI-governance + AI-security adjacency):**
  order of **$30–60B** (estimate; ranges vary widely by analyst). `[VERIFY]`
- **SAM (regulated enterprises deploying consequential agents, the
  accountability/audit-evidence slice, 2027–2030):** **$1–4B**.
- **SOM (24–36 months, design-partner → early enterprise):** **low tens of
  $M ARR**, contingent on the category forming and on a first auditor
  acceptance.

The category ("AI accountability / audit-evidence") is **nascent to non-
existent** today — the opportunity is to *name and own* it, not to take share
of a measured market.

## 1.4 Current status & milestones
| Track | Status |
|---|---|
| Engineering (identity, authority, accountability, vault, verifier, service, CI) | **Built & tested** (✅ `cargo test` green; see §2) |
| Open EvidencePacket specification + offline verifier CLI + signed audit bundle | **Shipped** |
| Design partners | **0** (not started) |
| Auditor acceptance | **0** (the key unlock — unproven) |
| Revenue | **$0** |

## 1.5 Investment thesis (one paragraph)
Right problem, right time, real engineering, **no distribution yet.** The wager
is that **(a)** regulation + agentic deployment make "prove what your agent did"
compulsory for regulated enterprises within **18–36 months**, and **(b)** AIP
converts a genuine engineering head-start + an open standard into category
ownership before identity/observability incumbents ship a "good-enough"
feature. The code de-risks *can they build it* (yes); the open questions are
*will an auditor accept it* and *can they distribute*.

## 1.6 The ask (proposal, not a term sheet)
- **Round:** Pre-seed **$1.5–3.0M**, ~10–15%, **18-month runway**.
- **Use of funds:** Engineering **55%** (KMS/HSM, client-side signing SDK +
  `/ingest`, IAM bridge, hardening, HA); Design-partner/GTM **25%**;
  Security/Compliance **10%** (independent assessment, control-framework
  mapping); G&A **10%**.
- **Seed gate:** 2–3 design partners live + **1 written auditor acceptance** +
  first paid workflow.

---
---

# SECTION 2 — TECHNICAL ARCHITECTURE

Reproduce everything in this section:
```bash
cd aip-standalone && cargo test --workspace
cargo run -p aip-protocol --example loan_approval     # build → verify → tamper-detect
cd ../aip-service && cargo test                        # auth, tenant isolation, HTTP export
# Offline auditor verification:  aip-verify bundle.zip [--report|--json|--trust id=hex]
```
Workspaces: `aip-standalone` (core libraries + CLI + demo) and `aip-service`
(deployable HTTP service). Language: **Rust**.

## 2.1 The three-layer architecture

### Layer 1 — Identity (`aip-core`, `aip-crypto`)
- **Generation/verification.** Each agent has an `AIP-ID`:
  `aip1 · base58(SHA-256(pubkey ‖ provenance)[..26]) · base58(checksum)`.
  Verifiers recompute it, binding the ID to the public key + a **provenance
  commitment** (SHA-256 of model / environment / toolchain).
- **Primitives.** **Ed25519** (RFC 8032) signatures; **SHA-256**; Base58. Both
  an enveloped signature (`sign_ed25519`, carries signer-id/timestamp/nonce/
  payload-hash) and a **raw** detached signature (`sign_ed25519_raw`, used for
  bundle manifests).
- **Revocation / rotation.** Lifecycle state machine
  (Pending→Active→Suspended→Revoked); **cascade revocation** invalidates a
  token's entire delegation subtree; per-token JTI revocation set checked at
  verification.
- **IAM integration (Okta / Azure AD / Entra): ROADMAP — not built.** Today
  identities are self-derived. The funded work is a bridge that maps AIP-IDs ↔
  workforce/workload identities (OIDC/SCIM; consume SPIFFE SVIDs where present)
  so the "authorizing party" resolves to a named, IdP-managed principal.
- **Honest limitation.** The provenance triple is a *caller-supplied
  commitment*, not a verified attestation that the hash equals a real model
  build. Verified model/TEE attestation is ROADMAP; today's hardware-
  attestation module is **EXPERIMENTAL** (structural checks only). See
  `AUDIT_CORRECTIONS.md`.

### Layer 2 — Authority (`aip-core::capability`, `::delegation`)
- **Delegation graph construction.** A **scope** = `{allowed[], denied[]}` over
  actions. A delegation's scope is the **lattice MEET** (intersection) of the
  parent scope and the requested scope; empty intersection (⊥) is rejected.
- **Authority-chain validation.** `verify_delegation_chain` checks, per hop:
  Ed25519 signature; parent-JTI linkage; depth monotonicity; scope ⊆ parent.
  Returns the **most-attenuated effective scope** at the leaf.
- **Scope attenuation.** Mathematically enforced: a child can **never** exceed
  its parent. This is the "confused-deputy" defense.
- **Agent-to-agent delegation.** `create_sub_delegation`; depth-limited (≤8) to
  bound chains; each hop independently signed and offline-verifiable.
- **Bounding.** Depth limit + scope subset + temporal validity (a child cannot
  outlive its parent) + revocation.

### Layer 3 — Accountability (`aip-protocol`)
- **EvidencePacket v1 format (`AEP1`):** header (magic/version/packet-id/
  created-at); agent identity summary; root authority (principal + signed
  scoped token); delegation chain; decision (action kind, summary, input-hash,
  rationale-hash); per-action attestations (each Ed25519-signed and **bound to
  the decision id** so it cannot be transplanted); optional trace binding;
  optional receipt binding (counterparty may **countersign**, bound to the
  decision); claimed trust floor; `packet_hash` = SHA-256 of a **canonical,
  length-prefixed** byte encoding; agent signature over that hash.
- **Cryptographic signing.** The packet hash covers a prefix-free canonical
  encoding (every variable field length-prefixed), so two distinct packets
  cannot collide. The agent signs the hash; per-action and counterparty
  signatures are independent and also covered.
- **Verification (14 rules, no short-circuit):** STRUCTURE, AGENT_ID_BINDING,
  CANONICAL_HASH, AGENT_SIGNATURE, ROOT_TOKEN_SIGNATURE, DELEGATION_CHAIN,
  AUTHORITY_CHAIN, SCOPE_AUTHORITY, REVOCATION, TEMPORAL_VALIDITY,
  ACTION_ATTESTATIONS, TRACE_BINDING, RECEIPT_BINDING, TRUST_FLOOR. The **trust
  floor is derived from evidence**, never asserted:
  `UNVERIFIED → AGENT_SIGNED → AUTHORITY_BOUND → COUNTERPARTY_SIGNED`.
- **Storage / retrieval.** `EvidenceStore` trait with **JSONL** and
  **PostgreSQL** backends (append-only, tenant-scoped, indexed on
  tenant/hash/created-at; authority nodes/edges materialized). `aip-migrate`
  imports JSONL→PG idempotently. Selected at runtime via `AIP_STORE_BACKEND`.
- **Verification portal = signed bundle + offline CLI.**
  `GET /v1/evidence/{id}/export` → a **signed ZIP**: `evidence.json`,
  `verification_report.json`, `verification_report.md` (plain-language),
  `authority_graph.json`, `authority_graph.dot`, `manifest.json` (per-file
  SHA-256 + bundle hash + signer public key), `bundle_signature.sig` (Ed25519
  over the manifest). `aip-verify bundle.zip` verifies it **offline** →
  PASS/WARNING/FAIL. Spec: `docs/AUDIT_EXPORT_SPEC.md`.

## 2.2 Technical differentiators
- **Not "logging with signatures."** A signed log line proves *a record
  existed*; an EvidencePacket proves *an action stayed within a verified chain
  of delegated human authority* and refuses to validate otherwise
  (`SCOPE_AUTHORITY` + `DELEGATION_CHAIN`). The authority semantics — not the
  signature — are the moat-relevant part.
- **Unique authority graph.** It is *cryptographically* reconstructable
  (Human→Authority→Agent→Decision→Action→Receipt) and connectivity-checked, not
  inferred from logs. Each edge is a signed delegation.
- **vs. IAM.** IAM gates access (who may call). It does **not** emit a portable,
  offline-verifiable, after-the-fact proof of who authorized what. AIP sits
  above IAM and should consume its identities (the ROADMAP bridge).
- **vs. observability.** Datadog/Splunk are mutable, central, operations-
  oriented, not authority-aware, and require trusting the platform. AIP is
  tamper-evident, offline-verifiable, authority-bound, and third-party-
  verifiable. Complementary: AIP can bind to an OTel `trace_id`.

## 2.3 Technical risks & failure modes
| Risk / failure mode | Mitigation / status |
|---|---|
| **Key custody** — single on-disk service signing key today; agent keys app-side | KMS/HSM + rotation and a client-side signing SDK are the top funded items; the bundle signature already separates *who exported* from *what happened* |
| **Provenance ≠ attestation** | Documented; verified TEE/model attestation is ROADMAP; does not weaken authority/integrity guarantees, only the model-origin claim |
| **Authority-graph query cost** — per-query rebuild (~475 ms at 10k packets, measured) | Authority tables already materialized in PG; indexed-query path is a follow-up (no schema change) |
| **Bundled report is integrity-level** (service holds no external trust keys at export) | By design; recipient runs `aip-verify --trust …` for full authority; documented in the spec so the exporter never over-claims |
| **Spec churn breaking stored evidence** | Versioned wire format (`AEP1`/v1); version-pinned verification; append-only store; re-verification after restore |
| **Crypto agility** (Ed25519 only) | Algorithm id reserved; ML-DSA (PQC) migration path documented |
| **Availability** — single-node service today | Stateless verify; non-gating pilot design; HA is ROADMAP |

## 2.4 Technology stack
**MVP (today):**
- Crypto: `ed25519-dalek`, `sha2`, `bs58`.
- Service: `axum` + `tokio`; API-key auth (SHA-256-hashed secrets, tenant+role,
  fail-closed); `EvidenceStore` over JSONL or `tokio-postgres` + `deadpool`.
- Tooling: `aip-verify` (clap), `aip-migrate`, `banking_demo` example.
- Ops: GitHub Actions CI (fmt, clippy `-D warnings`, test, `cargo audit`,
  `cargo deny`, coverage), Security workflow (audit + gitleaks + trivy),
  multi-target release; Docker + compose (service + Postgres); `deny.toml`.
- Tests: workspace green; 10k-packet PG benchmark (≈228 inserts/sec,
  0.29 ms indexed get, 456 ms tenant fetch).

**Production targets (ROADMAP):** KMS/HSM-backed keys + rotation; client-side
signing SDKs (TypeScript, Python); IAM bridge (OIDC/SCIM/SPIFFE);
transparency-log anchoring of packet hashes; HA + backup/DR; SOC 2 / CERT-In.

---
---

# SECTION 3 — MARKET OPPORTUNITY

## 3.1 Market sizing
> **BANNER: every number in this sub-section is an ESTIMATE.** Top-down ranges
> are blended from public analyst commentary (which varies widely) and are
> `[VERIFY]` before any external deck. The bottom-up SOM is the number that
> should drive the investment decision.

**Top-down (illustrative; USD, $B):**

| Market (estimate) | 2025 | 2026 | 2027 | 2028 | 2029 | 2030 |
|---|---|---|---|---|---|---|
| Agentic AI platforms/services | ~7 | ~12 | ~20 | ~30 | ~42 | ~55 |
| AI governance / TRiSM tooling | ~1 | ~1.8 | ~3 | ~5 | ~8 | ~12 |
| AI security | ~20 | ~26 | ~33 | ~42 | ~52 | ~65 |
| **AIP-addressable (accountability/evidence slice)** | ~0.05 | ~0.15 | ~0.5 | ~1.2 | ~2.5 | ~4 |

*(Adjacencies overlap; do not sum. The AIP row is the bottom-up estimate
below, not a fixed % of the others.)*

**Bottom-up (the decision-relevant number):**
- Universe: regulated enterprises running **consequential** agent workflows ≈
  **2,000–5,000** globally (GSIBs, large banks, insurers, health systems,
  government).
- Accountability/audit-evidence ACV: **$50k–$500k** (Pro→Enterprise+on-prem).
- **SAM (mature, 2027–2030):** 2,000–5,000 × $50k–$500k ⇒ order **$1–4B**.
- **SOM (24–36 mo):** 20–50 logos at pilot→early-enterprise ACV ⇒ **low tens of
  $M ARR**, gated on category formation + first auditor acceptance.

## 3.2 Market drivers
- **Pilot→production for consequential agents** in regulated functions
  (payments, underwriting, claims, servicing) — where the existing audit answer
  ("check the logs") breaks because logs are mutable and authority-blind.
- **Regulation mandating traceability/logging/human-oversight** (see §3.4).
- **"Shadow AI":** high-privilege agents as a new insider-threat class current
  tooling can't attribute or constrain provably.
- **Coalition / cross-party agent interactions** needing a neutral,
  mutually-verifiable record.

## 3.3 Market timing — why now
- **Not 3 years ago:** too few consequential agents in production; no regulatory
  forcing function; pain hypothetical.
- **Not in 3 years:** identity/observability incumbents or an open standard may
  fill the gap; the naming window closes.
- **Now:** agent deployments scale *and* EU AI Act high-risk obligations phase
  in (≈2026–2027), creating a compliance deadline that converts "nice-to-have"
  into "required" — **before** a default winner exists. Window: **18–36 months.**
- **If AIP doesn't capture it now:** the category consolidates into an identity
  or observability suite, and AIP becomes a feature/acqui-hire, not a platform.

## 3.4 Regulatory tailwinds
- **EU AI Act (hard facts):** penalties up to **€35M or 7% of global annual
  turnover** (prohibited practices); lower tiers **€15M/3%** and **€7.5M/1%**.
  High-risk-system obligations — **record-keeping, logging, traceability, human
  oversight** — phase in, with major high-risk duties around **2026–2027**.
  These map almost directly onto what an EvidencePacket provides. *(Exact dated
  milestones `[VERIFY]` against current Act text.)*
- **US:** no single federal AI statute; a patchwork of state laws + sectoral
  guidance — e.g. banking **model-risk (SR 11-7)** and the **NIST AI RMF**
  (voluntary but influential). Demand is audit/risk-driven.
- **India:** evolving AI-governance guidance (advisory/principles stage);
  relevant to a sovereign/defence wedge (see `docs/idex_open_challenge/`).
- **Others:** UK pro-innovation/sectoral; Canada AIDA (proposed); Singapore
  MAS/FEAT + AI Verify. `[VERIFY current status of each.]`
- **Mechanism → demand:** any regime mandating *traceability of automated
  decisions* or *human accountability* turns AIP from vitamin to painkiller —
  **conditional on an auditor accepting the evidence** (the #1 unproven
  assumption, §7).

---
---

# SECTION 4 — THE CUSTOMER

> Personas, "why they buy now," budgets, and named accounts below are
> **founder hypotheses for discovery**, not validated pipeline.

## 4.1 Primary buyer persona
- **Title:** Head of Internal Audit / Head of AI Governance / Chief Risk
  Officer (economic buyer). Champion is often the platform/security lead who is
  already piloting agents and feels the audit gap first.
- **Company:** regulated enterprise with consequential agent workflows.
- **Responsibilities:** defensible audit trails, model/AI risk, regulatory
  readiness, incident reconstruction.
- **Pain points:** cannot prove *who authorized* an autonomous action or that
  the record is unaltered; mutable logs; "shadow AI"; looming AI-Act exposure.
- **Budget authority:** GRC / model-risk / security budgets (already exist).
- **Decision process:** champion-led pilot → risk/security/legal review →
  procurement → production.
- **Procurement timeline:** **6–12 months** typical; faster if non-gating +
  read-only.

## 4.2 Target enterprise segments

**Tier 1 — Global Systemically Important Banks (GSIBs).**
- *Examples:* JPMorgan, HSBC, Deutsche Bank `[illustrative]`.
- *Why now:* highest regulatory scrutiny; first to deploy agents in
  consequential workflows under model-risk regimes.
- *Buyer:* CRO / Head of Internal Audit (champion: AI-governance lead).
- *Budget:* **$100k–$500k+**.
- *Procurement:* **9–12+ months** (the reference logo that unlocks the rest).

**Tier 2 — Large European banks.**
- *Examples:* Santander, UniCredit, ING `[illustrative]`.
- *Why now:* sharpest **EU AI Act** forcing function.
- *Buyer:* Head of Compliance / Model Risk.
- *Budget:* **$75k–$300k**. *Procurement:* **6–12 months.**

**Tier 3 — Healthcare systems.**
- *Examples:* Kaiser Permanente, NHS trusts, Mayo Clinic `[illustrative]`.
- *Why now:* HIPAA accountability; clinical-decision liability for AI.
- *Buyer:* CISO / Compliance. *Budget:* **$50k–$200k.** *Procurement:* **9–12 mo.**

**Tier 4 — Insurers.**
- *Examples:* AXA, Allianz, AIG `[illustrative]`.
- *Why now:* automated claims/underwriting decisions; dispute & fairness
  exposure.
- *Buyer:* Chief Risk / Compliance. *Budget:* **$50k–$250k.** *Procurement:*
  **6–12 mo.**

**Tier 5 — Sovereign / defence / regulators.**
- *Examples:* MAS, ECB, RBI, defence (iDEX) `[illustrative]`.
- *Why now:* command accountability, non-repudiation, **air-gapped/offline**
  verification; indigenous-IP preference.
- *Buyer:* program / security cell. *Budget:* grant-funded pilots possible.
  *Procurement:* bespoke, often longer.

## 4.3 The buying process
- **Champion:** Head of Internal Audit / AI-Governance lead.
- **Buyer (economic):** CRO / Head of Compliance / CISO.
- **Influencers:** General Counsel, Chief Data Officer.
- **Implementer:** platform / security engineering.
- **Hurdles:** security review, DPA/data-residency, vendor-viability,
  on-prem requirement, **SOC 2** (a gap), penetration test.
- **Sale length:** **6–12 months**; pilots start faster when **read-only and
  non-gating** (AIP records; it does not sit in the transaction's critical
  path).

## 4.4 The design-partner path
- **Definition:** a regulated enterprise deploying AIP read-only on one workflow,
  giving structured feedback and (ideally) hosting a staged auditor walkthrough.
- **AIP offers:** free/low-cost pilot, white-glove integration, influence over
  the spec, an Evidence Vault for one workflow.
- **AIP asks:** a representative workflow, a security-review slot, an auditor
  introduction, a reference on success.
- **How many:** **2–3** validates Phase 1; **1 auditor acceptance** is the true
  unlock.
- **Success criteria:** see §7 (3 partners live; ≥1 paid pilot; auditor
  acceptance letter).

---
---

# SECTION 5 — COMPETITIVE LANDSCAPE

> Competitor funding/traction numbers are **`[VERIFY]`** — do not assert without
> a source.

## 5.1 Direct / adjacent competitors
| Competitor `[VERIFY]` | Focus | Strengths | Weakness vs. AIP |
|---|---|---|---|
| Agent-IAM entrants (e.g. NewCore-type) | Identity/access for agents | Funded; enterprise access traction | Access control ≠ portable, offline-verifiable **accountability evidence** |
| Agent-access (e.g. Aembit-type) | Workload/agent access | Enterprise IAM traction | Not evidence/audit-artifact focused |
| AI-security/governance startups (Cyata/Lumia/Vijil-type) | Security / compliance posture | Category momentum | Early; not the auditor's verifiable artifact |

**Takeaway:** the adjacent field is "who/whether an agent may act." To our
knowledge none makes **the auditor's offline-verifiable artifact** the product.
That is AIP's lane.

## 5.2 Indirect competitors (the real gravity)
| Competitor | Focus | Threat | Note |
|---|---|---|---|
| **Microsoft Entra (+ Copilot)** | Identity + agents | **High** | Could ship "agent audit" as a checkbox; AIP's defense = neutrality + offline/open verification + cross-vendor scope |
| Okta | Workforce identity | Medium | Could extend to agents; partner/acquirer candidate |
| Datadog | Observability | Medium | Complementary ("shows what happened; AIP proves it"); acquirer candidate |
| Splunk | Log management | Medium | Same; mutable logs, not authority-aware |
| Cloudflare / SPIFFE-SPIRE | Access / workload identity | Medium | SPIFFE is the **substrate to build on**, not fight |

## 5.3 Differentiation / value proposition
- **Not another IAM tool:** it's the **evidence** layer above IAM — the artifact
  a third party verifies without trusting the vendor.
- **Not another observability tool:** tamper-evident, authority-bound, offline-
  verifiable; complements (does not replace) monitoring.
- **UVP:** *"Prove what your agent did and who authorized it — offline, to your
  auditor, without trusting us."*

## 5.4 The moat (aspirational — must be earned; honest)
- **Data/switching:** once a bank's audit procedures rely on the EvidencePacket
  schema, switching means re-architecting the compliance pipeline.
- **Graph:** authority relationships carry semantics that are non-trivial to
  model correctly.
- **Standard:** if the EvidencePacket format is what auditors request, you own
  the category.
- **Trust:** banking-first pilots and references are slow to win and slow to
  replicate.
- **Honest caveat:** the **code** is replicable by a strong team in a quarter.
  The durable moat = distribution + adopted standard + accumulated, anchored
  evidence — **none of which exist yet.**

---
---

# SECTION 6 — BUSINESS MODEL

## 6.1 Revenue model
| Tier | Price | Features | Buyer |
|---|---|---|---|
| Discovery (Free) | $0 | OSS verifier + SDK; agent discovery; basic dashboard | Startups, early adopters |
| Pro (Evidence) | **~$2,000/mo** | EvidencePacket generation + verification portal | Compliance teams |
| Enterprise (Vault) | **$10,000+/mo** | Full authority graph, integrations, audit exports, on-prem | Banks, healthcare, government |

Motion: **land** one high-risk workflow → **expand** to many (per-workflow /
per-evidence-volume) → **standardize** (auditors request the format).

## 6.2 Revenue projections
> **ILLUSTRATIVE MODEL, not a forecast.** This is the standard infra hockey-
> stick template, achievable **only if** the Phase-1/2 proof points land.

| Year | Customers | ARR (scenario) | Growth | Reality check |
|---|---|---|---|---|
| 1 | 5–10 | **$0–0.5M** | — | Treat as ~$0 until auditor acceptance |
| 2 | 50–100 | $5M | 10x | Requires a repeatable sale |
| 3 | 200–500 | $25M | 5x | Requires standard traction + channel |
| 4 | 500–1,000 | $75M | 3x | Requires international + platform |
| 5 | 1,000–2,000 | $200M | 2.7x | Requires category leadership |

Every row beyond Year 1 is **conditional**, not projected.

## 6.3 Unit economics (assumptions to validate)
- **ACV:** $24k (Pro) – $120k+ (Enterprise/on-prem).
- **CAC (early, founder-led, 6–12 mo cycles):** **$50k–$150k** per enterprise
  logo; falls sharply with references + channel.
- **LTV:** high *if* switching costs materialize (multi-year, expanding
  workflows); **LTV:CAC > 3** is plausible **post-reference**, not at first
  sale.
- **Payback:** likely **>18 months** for first logos; improves via land-and-
  expand.
- **Gross margin:** software-typical **80%+** (on-prem/support drags early).

## 6.4 Path to $1B ARR (necessary conditions, not a promise)
1. **Standard:** EvidencePacket becomes the de-facto audit-evidence format
   (auditors request it).
2. **Distribution:** embedded in agent frameworks / clouds (MCP, LangGraph,
   hyperscaler agent runtimes).
3. **Network effects:** cross-party verification (Org A's agent ↔ Org B's
   systems) recruits counterparties.
4. **Platform expansion:** from evidence to a governance control-plane.
5. **Vertical + geographic scale:** banking → insurance → health → gov; EU →
   US → APAC.
Miss any one of (1)–(3) and the realistic ceiling is a **strong acquisition**,
not a standalone $1B.

---
---

# SECTION 7 — ROADMAP & MILESTONES

Engineering for the phases is **largely built**; gating items are commercial +
hardening.

## 7.1 Phase 1 — Design-Partner Validation (M1–6)
- **Goal:** 3 regulated enterprises run AIP read-only on real logs.
- **Prove:** ingest without disruption; accurate identity/authority mapping;
  visibility is valuable enough to continue.
- **Success:** 3 partners active; ≥1 paid pilot ($2–5k/mo); positive dashboard/
  discovery feedback.
- **Status:** **not started (0).** Prereqs done (stack, demo, `docs/design_partner/`).

## 7.2 Phase 2 — Auditor Validation (M4–8) — **the key unlock**
- **Goal:** a regulated auditor reviews an EvidencePacket bundle and confirms it
  would be accepted as audit evidence.
- **Prove:** cryptographic verification is sound; authority chain complete/
  auditable; format meets regulatory expectations.
- **Success:** **written auditor acceptance.** *Unproven; existential.*
  Prereqs done (offline verifier, signed bundle, spec).

## 7.3 Phase 3 — First Paid Enterprise (M6–10)
- **Goal:** convert a partner to a paying enterprise customer.
- **Prove:** budget allocation; survives procurement/legal/security; production-
  sustainable.
- **Success:** first **$10k/mo** contract; EvidencePacket generation on ≥1
  high-risk workflow.
- **Prereq gaps:** SOC 2, KMS/HSM, IAM bridge.

## 7.4 Phase 4 — Expansion & Renewal (M10–12)
- **Goal:** first customer expands and renews.
- **Success:** 1→3+ workflows; Year-2 renewal; public reference/case study.

## 7.5 Phase 5 — Market Expansion (Y2–3)
- Adjacent regulated verticals (insurance, healthcare, government); channel
  (audit/consulting/tech partners); **open the core protocol** to drive
  adoption; push EvidencePacket toward an industry standard.

## 7.6 Phase 6 — Scale (Y3–5)
- International expansion; platform expansion (evidence → full AI governance);
  strategic acquisitions; IPO/exit optionality.

## 7.7 Milestone summary
| Milestone | Timeline | Success criteria | PMF target* |
|---|---|---|---|
| Design partners | M1–6 | 3 enterprises deployed | 65–75% |
| Auditor validation | M4–8 | Formal acceptance letter | 75–85% |
| First paid customer | M6–10 | $10k/mo contract | 80–88% |
| Expansion & renewal | M10–12 | 3+ workflows, renewal | 85–90% |
| Market expansion | Y2–3 | 100+ customers, $10M ARR | 90–92% |
| Scale | Y3–5 | 1,000+ customers, $100M+ ARR | 93–95% |

\*PMF scores are **forward-looking targets**, not current state. **Current
honest PMF: pre-PMF (<25%)** until a design partner and an auditor say yes.

---
---

# SECTION 8 — THE TEAM

> `[FOUNDER INPUT REQUIRED — do not ship to investors with placeholders.]`

- **Founders:** `[names, # , backgrounds]` — ideally spanning cryptography /
  distributed systems **and** regulated-enterprise sales.
- **Technical team:** `[#, key bios]`.
- **What the repository evidences about the team:** ability to ship a coherent,
  tested, secure Rust system with CI/security discipline and an open spec —
  credible **build** capability. Investors will still want demonstrated
  **GTM / regulated-sales** capability.
- **Key hires (0–6 mo):** (1) founding GTM/solutions lead with banking-audit
  relationships; (2) senior security/platform engineer (KMS, hardening).
- **Key hires (6–12 mo):** (3) developer-relations/SDK engineer (framework
  integrations); (4) part-time compliance/accreditation advisor.
- **Hiring strategy:** stay founder-led on first sales; hire the GTM lead only
  once a design partner is live; keep burn low until auditor acceptance.
- **Advisory board (targets, to recruit):** ex-Big-4 audit partner; bank CRO /
  model-risk leader; applied cryptographer; EU-AI-Act counsel. Each maps to a
  specific risk (auditor acceptance, banking credibility, crypto soundness,
  regulatory mapping).

---
---

# SECTION 9 — COMPETITIVE ADVANTAGE

## 9.1 Defensibility (honest)
Not the code. It is **(a)** first-mover on *accountability-as-evidence* with an
open, offline-verifiable format; **(b)** banking/regulated trust + references
that take years to earn; **(c)** accumulated, anchored evidence + compliance-
pipeline lock-in once adopted.

## 9.2 The standard moat
- **What "standard" means here:** the EvidencePacket format is what auditors and
  regulators *ask for*, and what agent frameworks emit by default.
- **How it creates defensibility:** a verifier on every auditor's desk + years
  of evidence in that format = demand from the buyer's buyer and un-migratable
  history.
- **Playbook:** open the spec + free offline verifier → integrate into agent
  frameworks (MCP/LangGraph) → get auditors to request the format.

## 9.3 First-mover advantage
- **Being first** = naming the category and shaping the format auditors adopt.
- **Capitalize:** banking-first references + open standard before incumbents
  react.
- **If not first:** category folds into an identity/observability suite; AIP
  becomes a feature or acqui-hire.

## 9.4 Why incumbents don't do it in 6 months
They can build the tech; they cannot quickly manufacture **neutral, third-party,
offline-verifiable trust** (auditors structurally prefer independent attestation
over "Microsoft audits its own agents") **or** an adopted standard. The real
risk is that they ship "good enough" and bundle it free — the top bear case
(§10/§11).

---
---

# SECTION 10 — RISKS

## 10.1 Risk register
| Risk | Prob. | Impact | Mitigation |
|---|---|---|---|
| Incumbent ships "good-enough" agent audit | Med-High | High | Neutrality; open spec; offline verify; banking references |
| Open standard emerges elsewhere | Med | High | **Lead** the standard; open-source core + verifier |
| **Auditors won't accept the evidence** | Med | **Existential** | Phase 2 is exactly this proof; engage Big-4 early |
| Sales cycles outrun runway | High | High | Non-gating read-only pilots; land-and-expand; tight burn |
| Market early (few consequential agents yet) | Med | High | Defence/sovereign + early-adopter banks; low burn |
| Trust / vendor-viability barrier | High | Med | Open verifier; on-prem; portable self-verifiable evidence |
| Security finding in diligence | Med | High | KMS/HSM + independent assessment are top funded items |
| Regulatory enforcement delayed | Low-Med | Med | Lead with security/audit value, not just compliance |

## 10.2 What could derail AIP
- **Existential:** (1) auditors never treat it as evidence; (2) the "agent-
  accountability" budget line never forms in the funding window; (3) an
  incumbent makes it a free checkbox before references accrue.
- **Realistic failure scenarios:** slow regulated sales burn the runway before
  proof; or the product is sound but undifferentiated once incumbents add a
  feature.
- **Plan B:** the strongest asset (offline-verifiable evidence + open spec) is
  an attractive **acquisition** for an IAM / observability / GRC platform even
  if the standalone company stalls.

---
---

# SECTION 11 — INVESTMENT THESIS

## 11.1 Why invest
A real, tested accountability stack aimed at a question regulation will force
regulated enterprises to answer within ~18–36 months, with no incumbent yet
owning it and an open-standard wedge available. The code removes "can they
build it"; the bet is on timing, auditor acceptance, and distribution.

## 11.2 Bull case
EvidencePacket becomes the audit standard for agent actions; double-digit
Fortune-500 adoption; $1B+ ARR in 7–10 yrs; category-defining infrastructure;
$10B-class outcome.

## 11.3 Bear case
Microsoft/AWS/Okta ship a competitive feature; an open standard emerges
elsewhere; enforcement slips; sales cycles outrun runway; "good enough" wins.
**Probability-weighted, the most-likely outcome today is a modest acquisition;
the tail is category-defining.** That asymmetry is the investment.

## 11.4 The ask (proposal)
- **Round size:** **$1.5–3.0M** pre-seed.
- **Valuation:** priced on founder + design-partner outcomes, with the repo as
  build evidence (`[negotiable]`; ~10–15% target).
- **Use of funds:** Engineering **55%** (KMS/HSM, signing SDK + ingest, IAM
  bridge, hardening, HA); Sales & GTM/design-partners **25%**; Security/
  Compliance **10%** (independent assessment + control-framework mapping);
  G&A **10%**.
- **Seed gate:** 2–3 design partners live + **1 written auditor acceptance** +
  first paid workflow.

---
---

# SECTION 12 — ONE-PAGE SUMMARY

1. **Problem:** organizations can't prove who authorized an autonomous AI
   action, within what limits, or that the record is unaltered.
2. **Solution:** AIP emits a tamper-evident, offline-verifiable EvidencePacket
   binding every consequential agent action to its human-rooted chain of
   delegated authority.
3. **Market:** an emerging "AI accountability / audit-evidence" category for
   regulated enterprises, pulled forward by the EU AI Act and agent deployment
   (SAM est. ~$1–4B as it forms — to validate).
4. **Traction (honest):** a working, tested, independently verifiable stack +
   open spec + reproducible demos + CI/security/release pipeline.
   **0 customers, 0 auditor acceptances, $0 ARR.**
5. **Team:** demonstrated ability to ship secure, tested infrastructure;
   GTM/regulated-sales capability `[to be evidenced]`.
6. **Ask:** $1.5–3.0M pre-seed to land 2–3 regulated design partners + the first
   auditor acceptance, and to productionize (KMS, SDK, IAM bridge).
7. **Opportunity:** own the accountability layer of the agent economy — a
   standard + accumulated-evidence moat where you can re-platform code but never
   re-witness history.

---

### Appendix A — verify the technical claims yourself
```bash
cd aip-standalone && cargo test --workspace
cargo run -p aip-protocol --example loan_approval          # build → verify → tamper-detect
cd ../aip-service && cargo test                             # auth, tenant isolation, HTTP export
# Offline auditor verification of a signed bundle:
#   aip-verify bundle.zip [--report | --json | --trust <id>=<hex>]
```
### Appendix B — source-of-truth documents
`AIP_SPEC.md` · `docs/AUDIT_EXPORT_SPEC.md` · `docs/PRODUCTION_READINESS.md` ·
`AUDIT_CORRECTIONS.md` · `docs/STRATEGY_TRUST_INFRASTRUCTURE.md` ·
`docs/design_partner/` · `docs/idex_open_challenge/`

### Appendix C — items to complete before external use
- §8 Team bios `[FOUNDER INPUT]`.
- §3 market figures + §5 competitor funding/traction `[VERIFY with sources]`.
- §3.4 EU AI Act dated milestones `[VERIFY against current text]`.
- Entity/cap-table/financials (data room) `[FOUNDER INPUT]`.
