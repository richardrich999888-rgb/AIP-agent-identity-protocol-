# 02 — Auditor Acceptance Checklist & Role Assessment

## Part A — The auditor's five questions

An auditor must be able to answer these about any AI agent action. For each:
how AIP answers it, the acceptance criterion, and the honest gap.

| # | Question | How AIP answers it | Acceptance criterion | Gap today |
|---|---|---|---|---|
| 1 | **Who performed the action?** | `agent.aip_id` + embedded public key; `AGENT_ID_BINDING` proves the ID derives from that key + provenance; each action is signed by that key | Verifier recomputes ID and checks the agent signature | Provenance is a *commitment* (hash), not a verified attestation of the actual model — see Q below |
| 2 | **Who authorized it?** | `root_authority.principal_id` (the human) + the delegation chain; `AUTHORITY_CHAIN` proves the chain connects principal → agent | Chain connects principal to acting agent; every hop signature verifies | Mapping AIP-IDs ↔ named employees is the deploying org's IAM/HR join (not in AIP) |
| 3 | **What authority existed?** | Root token scope + each hop's attenuated scope; `SCOPE_AUTHORITY` proves the decision/actions are within the most-attenuated scope | Action ∈ effective scope; child scope ⊆ parent (lattice MEET) | Scope vocabulary is generic (read/write/…/custom); domain scopes are a config exercise |
| 4 | **Was the evidence modified?** | `packet_hash` + `agent_sig`; `CANONICAL_HASH` + `AGENT_SIGNATURE` fail on any change, including a hash-recomputing attacker | Both checks pass for genuine, fail for tampered | None — demonstrated in `03_LOAN_DEMO.md` (tamper → `UNVERIFIED`) |
| 5 | **Can verification be performed independently?** | Verification is a pure function of (packet + trusted public keys); runs offline; format + rules are open (`AIP_SPEC.md`) | A third party verifies with no call to AIP | No standalone signed CLI verifier binary shipped yet (library + service only) — see gap list |

**Overall checklist (tick for pilot acceptance):**

- [x] Every action cryptographically attributable to one agent identity
- [x] Every action linked to a human-rooted, signed delegation chain
- [x] Authority attenuation enforced (no privilege escalation across hops)
- [x] Tamper detection on the whole packet, incl. embedded signatures
- [x] Offline / independent verification (no vendor call-home)
- [x] Open format + verification rules (no single-vendor lock-in to verify)
- [x] Append-only evidence store; tenant-isolated reads
- [ ] **Standalone signed verifier binary** for auditors (gap — P1)
- [ ] **Audit-export bundle** endpoint (gap — P1)
- [ ] **Independent security assessment** (e.g. CERT-In) (gap — pre-deployment)
- [ ] **Durable, backed-up storage** beyond a single JSONL file (gap — pre-deployment)

## Part B — Role-by-role assessment (Task 1)

### Bank Internal Auditor
1. **Trust:** offline, independent re-verification of any packet; tamper
   detection that catches a privileged insider, not just accidents.
2. **Missing:** a signed verifier they run themselves; an export bundle they
   can archive; mapping of AIP-IDs to named staff (their IAM join).
3. **Blocks adoption:** no third-party security assessment; single-node file
   storage with no documented backup/retention.
4. **Approves a pilot when:** they can take one real packet, alter it, and
   watch independent verification fail — on their own machine. (Reproducible
   today via the example; a packaged verifier closes the gap.)

### Big 4 Audit Partner
1. **Trust:** an open specification + conformance basis so the methodology
   isn't proprietary magic; deterministic, explainable per-rule results.
2. **Missing:** mapping to a control framework (SOX/ICFR, PCAOB) and a
   written control-objective narrative; SOC 2 of the service.
3. **Blocks adoption:** inability to opine without a recognised assessment;
   no evidence-retention/immutability attestation.
4. **Approves a pilot when:** AIP evidence demonstrably supports a specific
   control objective ("authorization of automated approvals") in a scoped
   walkthrough.

### Chief Risk Officer
1. **Trust:** reduction in unquantifiable autonomous-action risk; clear blast
   radius (revoke a token → cascade) and non-repudiation.
2. **Missing:** quantified coverage ("% of agent actions producing evidence"),
   incident playbook, DR/BCP for the vault.
3. **Blocks adoption:** operational fragility (single node), key-compromise
   story (no HSM/rotation yet), unclear liability boundary.
4. **Approves a pilot when:** scoped to one workflow, with a rollback path and
   no production dependency on AIP availability (AIP observes/records; it does
   not gate the transaction in the pilot).

### AI Governance Lead
1. **Trust:** provable human-in-the-authority-chain for autonomous decisions;
   model/build provenance commitment; alignment with EU AI Act / NIST AI RMF
   traceability expectations.
2. **Missing:** verified model attestation (vs. a self-declared commitment);
   policy mapping; coverage reporting across the agent fleet.
3. **Blocks adoption:** if AIP is mistaken for a decision/▲autonomy engine —
   it is **not**; it records authority and integrity only.
4. **Approves a pilot when:** one high-scrutiny agent workflow emits packets
   that a governance review can trace end-to-end without engineering help.

**Common thread:** every role approves a *scoped, non-gating pilot* once they
can independently verify a real packet and tamper-test it. Every role blocks a
*production* rollout until: independent security assessment, durable/backed-up
storage, key rotation/HSM, and a packaged verifier + export bundle. Those four
are the pre-deployment list in `04_PILOT_READINESS.md`.
