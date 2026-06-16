# 07 — Customer Discovery (first design partner)

Written from four buyer personas: **Head of Internal Audit, Chief Risk
Officer, General Counsel, Big-4 Audit Partner.** Goal: the exact information
needed to secure the first design partner.

## 1. Discovery questions to ask the prospect

Qualify for *pain*, not interest. Ask:

1. Do you have AI agents taking **consequential, semi-autonomous actions** in
   production or near-production today? (If no → not yet a buyer.)
2. When an agent acts, can you currently prove **who authorized it** and that
   the record is **unaltered** — to an auditor or regulator?
3. Has an **auditor, regulator, or board** already asked you that question, or
   flagged agent activity? (This is the urgency trigger.)
4. Which workflow scares your risk/audit function the most? (payments,
   underwriting, claims, trading, access provisioning…)
5. Who signs off when an automated action goes wrong — and what evidence do
   they rely on today?
6. Is your audit/log infrastructure **mutable by administrators**? Do your
   auditors know that?
7. Are any agent workflows subject to **SOX, EU AI Act, model-risk (SR 11-7),
   HIPAA, or coalition/inter-agency** scrutiny?
8. What would a credible **non-gating pilot** need to look like to get approved
   internally?

## 2. Objections (and the honest response)

| Objection | Response |
|---|---|
| "Our logs already cover this." | Logs are mutable by admins and record *what*, not *under whose authority*. Demo: edit the ₹5cr amount + recompute the hash → AIP still fails verification; a log wouldn't. (`03_LOAN_DEMO.md`) |
| "Isn't this just SIEM/observability?" | Those tell you what happened; AIP gives cryptographic non-repudiation + authority binding, verifiable offline by a third party. Complementary, not competing. |
| "We use SPIFFE/Okta for identity." | Keep them. AIP is the *evidence* layer above identity; it binds an action to delegated authority and proves integrity — identity systems don't emit that artifact. |
| "You're a tiny vendor — what if you disappear?" | Verification is offline and the format/rules are open (`AIP_SPEC.md`). You can verify your evidence forever without us. |
| "Not certified (SOC 2/CERT-In)." | True today. Pilot is scoped + non-gating precisely so certification isn't a blocker to *evaluate*; certification is on the pre-production path (`04_PILOT_READINESS.md`). |
| "Will it gate/slow our transactions?" | No — in the pilot AIP records alongside the workflow; it is not in the critical path. |
| "Single vendor, single node?" | Acknowledged pilot limit; production needs DB/HA/HSM (listed openly). Pilot proves value before that investment. |

## 3. Pilot requirements (what they will demand)

- **Scoped**: one workflow, one team, time-boxed (e.g. 60–90 days).
- **Non-gating**: AIP observes/records; failure of AIP must not stop business.
- **On-prem / their cloud**: no data leaves their boundary; TLS at their ingress.
- **Independent verification**: their auditor verifies a packet without us.
- **Rollback**: trivially removable; no production dependency created.
- **Defined success metric**: e.g. "auditor accepts an AIP evidence bundle for
  N approvals" or "time-to-reconstruct authority drops from hours to seconds."
- **Data handling**: hash-only binding so no new sensitive data is stored.

## 4. Procurement concerns → what to prepare

| Concern | Prepare |
|---|---|
| Vendor viability / lock-in | Open spec + offline verifier story (verifier binary = MISSING, build it) |
| Security review | Threat/security model (READY); pen-test + CERT-In (MISSING) |
| Data processing agreement | On-prem, hash-only, no egress — draft a one-page DPA position |
| SLA / support | Pilot-level support commitment; no HA promised |
| Pricing | Define a simple pilot price (currently MISSING — decide before outreach) |
| Exit | Data is portable JSON, re-verifiable without us — state this explicitly |

## 5. Security concerns → status

Covered in `05_TOP_50_QUESTIONS.md` §C. The ones they will not waive for
production: **TLS+rate-limit, independent assessment, KMS/HSM + key rotation,
durable/backed-up storage.** For a *pilot*, the non-gating + on-prem +
scoped design makes these manageable risks, not blockers.

## 6. Compliance concerns → status

- **Traceability (EU AI Act / NIST AI RMF):** AIP directly supports it; formal
  control mapping is MISSING — write it for the target jurisdiction.
- **Authorization evidence (SOX/ICFR):** AIP provides cryptographic
  authorization evidence; map to a specific control objective for the pilot.
- **Model risk (SR 11-7):** provenance commitment links action to model/build;
  verified attestation is a gap (commitment ≠ measurement).
- **Records immutability:** append-only today; retention/immutability tooling
  is a pre-production gap.

## 7. What makes them BUY vs REJECT

**Buy when:**
- They already feel the pain (Q3 above = yes), and
- Their own auditor independently verifies a real packet and watches a tamper
  fail — on their machine, and
- The pilot is scoped, non-gating, on-prem, removable, with a crisp success
  metric.

**Reject when:**
- No agents in consequential production yet (too early — most common reason), or
- They mistake AIP for a decision/autonomy or detection product, or
- Procurement demands certifications that only matter at production, applied to
  a pilot, or
- They expect AIP to replace identity/SIEM rather than sit above them.

**Evidence that convinces:** the **reproducible tamper demo** (`03`), the
**offline independent verification** (`02` Q5), and the **honest readiness
report** (`04`) — credibility comes from stating limits, not hiding them.

## 8. The exact information required to secure the first design partner

1. **A reproducible 15-minute demo** on the prospect's own machine: generate a
   packet for *their* workflow shape, verify it, tamper it, watch it fail.
   *(Have today via the loan example; tailor the scenario.)*
2. **A one-page pilot proposal**: scope, non-gating design, success metric,
   timeline, on-prem deployment, rollback. *(MISSING — write it.)*
3. **A standalone verifier the auditor runs themselves.** *(MISSING — P1 build.)*
4. **A security one-pager**: model + honest gap list + pre-prod roadmap.
   *(Assemble from `01` §6 + `04`.)*
5. **A control-objective mapping** for their specific regime (SOX / EU AI Act).
   *(MISSING — write for the target.)*
6. **A DPA/exit position**: on-prem, hash-only, portable re-verifiable evidence.
   *(MISSING — one page.)*
7. **A named pilot owner + success criteria signed off** by their audit/risk
   function before any code is deployed.

Items 1 exists now; items 2–6 are short documents, not engineering; item 3 is
the one small build worth doing before outreach. None require new core
technology — exactly the point of this phase.
