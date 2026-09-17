# BFSI pilot plan — Sniffer Dog + AIP, end-to-end

> **Status: PILOT PLAN for a scoped, non-gating, advisory deployment.**
> Not a production rollout. Every claim below maps to code in this repository
> or is named as a build item that does not exist yet. Where this plan and a
> code-backed report disagree, the report wins: `docs/PRODUCTION_READINESS.md`,
> `docs/design_partner/04_PILOT_READINESS.md`,
> `docs/architecture/SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md`,
> `docs/security/ADVERSARIAL_RESULTS.md`.

**BFSI is the sector, not one segment.** This plan targets Banking, Financial
Services **and Insurance** — banks, NBFCs, payment/fintech operators, capital
markets (brokers, AMCs, depositories), and insurers. Each segment has a
different primary regulator, a different cyber/IT framework, and different data
and criticality; §0.5 fixes that mapping and the rest of the plan is written
regulator-agnostic ("the institution", "the regulated entity"), with per-segment
specifics called out where they change the pilot.

This plan is deliberately written so the institution's security team and its
regulator can audit it. It states what the pilot proves, what it cannot prove,
and the exact line the system must not cross during the pilot.

---

## 0. What this pilot proves — and does not

The pilot is a falsifiable experiment, not a demonstration. It **passes** only
if the observer's honesty holds under the institution's real conditions, and it
**fails** (usefully) if it does not.

**In scope to prove (P):**

- **P1** — An independently keyed observer records execution-related facts
  (process exec, TCP connect/transition, TCP send by byte count, file write)
  on the institution's real agent hosts, and the reconciler classifies them against
  independently signed authorization.
- **P2** — When the observer was not watching, or was blinded, the system says
  `CANNOT_PROVE` / `ObserverIntegrityUnknown` — it never converts absence into
  an accusation. (This is the property most likely to be attacked; see §3.)
- **P3** — The collector's signing key is **off the observed host**, so a
  compromised agent host can lie to its own probe but cannot forge or suppress
  an attestation after collection.
- **P4** — Every artifact verifies **offline** against keys the institution supplies,
  with no call back to us.
- **P5** — Vanian's account can be cross-checked against **independent**
  open-source observers (auditd, Tetragon) that Vanian does not consume.

**Explicitly NOT proved by this pilot (N):**

- **N1** — Root-compromise resistance. A root or kernel-module attacker on the
  observed host defeats on-host detection (`ADVERSARIAL_RESULTS.md` OI-08).
  The off-host collector bounds tampering *after* collection; it does not make
  the host kernel trustworthy.
- **N2** — Autonomous containment. Containment stays **OFF**. No process is
  frozen, no packet dropped, no traffic filtered. The pilot is advisory only.
- **N3** — Any performance, throughput, latency, or TRL figure. None is
  measured here and none may be quoted (`COMPLETE_IMPLEMENTATION_REPORT.md`
  §9/§12).
- **N4** — Hardware attestation, TPM/TEE, or post-quantum properties. None are
  deployed.
- **N5** — That AIP sits in the transaction critical path. It does not. It
  records and proves; it does not authorize or block a banking transaction.

If the institution needs any of N1–N5, this pilot is the wrong instrument and
the pre-production blockers in §8 must close first.

---

## 0.5. BFSI segments, regulators, and what changes per segment

The evidence pipeline is identical across segments; the regulator, the data
sensitivity, and the "never gate this" boundary differ. India context assumed
(CERT-In / DPDP references); for another jurisdiction, substitute the
equivalent authority — the structure holds.

| Segment | Examples | Primary regulator | Cyber/IT framework (name-level; confirm current version with the entity) | What changes for the pilot |
|---|---|---|---|---|
| **Banking** | scheduled/commercial banks, co-op banks | **RBI** | RBI Master Direction on IT Governance/Risk/Controls; cyber-security framework | Core-banking hosts are the highest-criticality; non-gating is absolute |
| **NBFC / lending fintech** | NBFCs, digital lenders | **RBI** | RBI IT/cyber directions for NBFCs; Digital Lending guidelines | Loan-decisioning agents are a natural pilot subject; DPDP on borrower data |
| **Payments** | PA/PG, PSO, UPI apps | **RBI** (DPSS) | RBI payment-system security; PCI-DSS where cards are in scope | Transaction-critical path — the non-gating rule (§4) is load-bearing |
| **Capital markets** | brokers, AMCs, depositories, RIAs | **SEBI** | SEBI **CSCRF** (Cybersecurity & Cyber Resilience Framework) | Order-flow latency sensitivity; observer must add no path latency (it does not — passive) |
| **Insurance** | life/general/health insurers, InsurTech | **IRDAI** | IRDAI Information & Cyber Security Guidelines | **Health/actuarial PII** — the most sensitive DPDP category; §6 field review is stricter |
| **Pensions** | NPS intermediaries | **PFRDA** | PFRDA cyber guidance | Similar to capital markets; low pilot priority |

Cross-cutting, every segment:

- **CERT-In** — incident-reporting directions and empanelled-auditor requirement
  (the §8 B2 assessment). Applies sector-wide.
- **DPDP Act 2023** — data-protection obligations; the content-minimization
  design (§6) is what keeps the observer clear of most of them.
- **MeitY / ISO 27001 / SOC 2** — common contractual asks; map once (§8 B7).

Pick **one** segment and **one** low-criticality agent workload for the first
pilot. Do not pilot a transaction-critical or health-data workload first; prove
the honesty property on something recoverable, then widen.

---

## 1. Scope and sequencing (observer-first)

The pilot is the full chain — agent → decision point → observer → reconciler →
evidence API → offline verifier — but it is **built and validated in
dependency order**, never downstream-first. Each phase has an exit gate; a
phase does not start until the prior gate is met.

| Phase | Deliverable | Exit gate |
|---|---|---|
| **1** | Off-host collector + host-side probe daemon + authenticated probe→collector transport | A real agent process on an institution host is observed; its batch is signed by a collector on a **different** host holding a wrapped key; `aip-verify` accepts the batch offline. **The three components are built (§7); the exit gate is running them on the institution's own hardware.** |
| **2** | Decision point issues signed `ExpectedExecution` for the pilot's agent actions | An expectation and an observation join on `decision_id` + `ExecutionBinding`; reconciler emits `VerifiedExecution` (Attested) on the honest path. |
| **3** | Reconciler + evidence API wired: verdicts land in `aip-service` | `POST /v1/evidence/*` stores and returns a verdict; `GET /v1/authority/{id}` rebuilds the chain; tenant isolation holds. |
| **4** | Adversarial + honesty validation on the institution's hosts | The RED suite (§3) runs on pilot hardware: blinded observer → `ObserverIntegrityUnknown`; observer down → `CANNOT_PROVE`; no false `PhantomClaim`. |
| **5** | Independent cross-check + auditor handoff | Vanian's account reconciled against auditd/Tetragon (§5); signed audit-export bundle handed to the institution's auditor; offline verification reproduced by them. |

Do not skip a phase. A phase-4 pass on a phase-1 gate that was waved through is
not a pass.

---

## 2. Deployment topology (the trust boundary is the design)

```text
  INSTITUTION AGENT HOST (attacker-reachable)   SEPARATE COLLECTOR HOST
  ──────────────────────────────────────        ──────────────────────────────
  agent workload (the subject)                   aip-collector (Phase-1 daemon)
  aip-probe (Phase-1 daemon)                       · holds the ONLY signing key,
    · perf tracepoints (sched, sock)                 wrapped at rest
      + netlink connector + fanotify + AF_PACKET     (WrappedFileCustodian:
    · pidfd-anchored procfs reads                      argon2 + chacha20poly1305)
    · HOLDS NO KEY                                   · assigns sequence + prev_head
    │                                                · enforces continuity ledger
    │  ObservationBatch (unsigned)                   · signs → AttestedBatch
    └───── authenticated transport ─────────────────▶  · exposes signed health
                                                     │
  ── independent cross-checks (NOT Vanian inputs) ── ▼
  auditd (NETLINK_AUDIT)                          aip-reconcile  (ExpectedExecution
  Tetragon (kprobes, if kernel permits)             ⋈ ObservedExecution)
    · compared against Vanian's account, never      │
      fed into it (validation/external/)            ▼
                                                   aip-service  /v1/evidence/*
                                                     · TLS at ingress (institution proxy)
                                                     · service signing key in KMS/HSM
                                                     ▼
                                                   aip-verify  (auditor, offline)
```

Two boundaries carry the whole security argument and must be enforced in the
the institution's deployment, not assumed:

1. **Key custody boundary.** The collector's signing key is generated **on the
   collector host** and never leaves it. The probe on the agent host holds no
   key and has no signing method (`ProcfsProbe` has neither). This is what
   makes P3 true. Buildable today via `CollectorKey::production` /
   `WrappedFileCustodian`; the demo `ghost-demo-collector` writes a plaintext
   key and **must not** be used in the pilot.
2. **Evidence boundary.** The independent cross-check observers (auditd,
   Tetragon) live under `validation/external/` and are **compared against**
   Vanian, never consumed by it. Feeding them into a reconciliation would make
   the actor control its own evidence — the one thing this architecture exists
   to prevent (`validation/README.md`).

---

## 3. Threat model for the pilot (BFSI)

Attacker models, tested separately (from `.claude/skills/ghost-adversarial-tester`):

| Model | Capability | Pilot stance |
|---|---|---|
| **A1** confused agent | unintended actions, no evasion | baseline; the common real case |
| **A2** adversarial agent, unprivileged | evades, no root | in scope; expected to reach `CANNOT_PROVE`/`IdentityDivergence` |
| **A2+/A3** agent with `CAP_BPF`, or root | attaches a tracepoint gate; reads local state; alters clock | **detection bound**: a `CAP_BPF` gate is detected (→ `IntegrityUnknown`); full root defeats on-host detection (N1) — off-host collector bounds post-collection tampering only |
| **A4** compromised observer | controls the sensor | key custody + coverage predicate prevent a forged observation from minting `UNATTRIBUTED_EFFECT` against an innocent workload; confirm `SENSOR_INTEGRITY_FAILURE` never drives containment |

**The RED suite that must run on pilot hardware (Phase 4).** Each is an attack
whose *correct* outcome is honesty, not a verdict. Results recorded in
`docs/security/ADVERSARIAL_RESULTS.md`, one row per attack, with raw output.

- Foreign eBPF tracepoint gate on each perf sensor → observer signs
  `IntegrityUnknown`, reconciler `CANNOT_PROVE(ObserverIntegrityUnknown)`
  (already demonstrated in-repo; re-run on institution hardware).
- Observer killed / restarted / partitioned from collector →
  `OBSERVATION_UNAVAILABLE` → `CANNOT_PROVE`, never `PhantomClaim`.
- Collector state rollback → strict continuity refuses to sign, leaves a signed
  report.
- Forged/replayed observation → rejected by continuity + coverage predicate.
- Clock manipulation on the agent host → does not manufacture stronger
  evidence.

A pilot in which the RED suite was not run on the pilot's own hardware has not
established P2, whatever the happy path shows.

---

## 4. Safety posture (non-negotiable during the pilot)

- **Advisory only. Autonomous containment OFF.** Nothing freezes a process,
  drops a packet, changes a firewall, or touches an actuator. Enabling
  containment requires two separate operator decisions and `Proven` evidence,
  and **no production evidence path yields `Proven` for a workload today**
  (`COMPLETE_IMPLEMENTATION_REPORT.md` §8.2). It stays off.
- **Non-gating.** AIP is never in a banking transaction's critical path. If the
  observer degrades, the institution's workload is unaffected; only Vanian's coverage
  claim shrinks.
- **Fail closed for the verdict, fail open for availability.** Missing or
  ambiguous evidence → `CANNOT_PROVE`. An observer error never escalates into
  an accusation or an action.
- **Protected identities.** The institution names its own critical processes as
  protected; they are exempt from any autonomous action even if containment
  were later enabled.

---

## 5. Independent cross-check plan (open source, external only)

Per the answered scope: open source is added **only** as independent
cross-check instruments, never as workspace dependencies or evidence inputs.
They live under `validation/external/` with provenance, license, and a STATUS
file (existing convention). See `validation/external/CROSS_CHECK_BFSI.md`.

| Instrument | Mechanism | Independent of Vanian? | Pilot use |
|---|---|---|---|
| **auditd** | `NETLINK_AUDIT`, syscall boundary | Yes — different facility from the perf-tracepoint path | Primary independent witness of exec/connect; disagreement with Vanian is signal |
| **Tetragon** | eBPF on **kprobes** | Yes, if the kernel has `CONFIG_KPROBES` | Secondary witness; **blocked where kprobes are absent** (the repo's test kernel lacks them — verify on institution hardware) |
| **ftrace reader** | reads the same tracepoints | **No** — interface-independent, not mechanism-independent | Cross-check of Vanian's *reading*, not a second witness (`validation/linux/INDEPENDENCE.md`) |

Rule, enforced: an instrument Vanian *consumed* would become part of Vanian and
the comparison would stop being a comparison. Agreement corroborates; a
disagreement where two independent witnesses agree and Vanian differs isolates
a Vanian defect. Neither raises a verdict above its `EvidenceCeiling`.

---

## 6. Data handling and privacy (DPDP / data residency)

- **Content minimization by construction.** No payload is captured or hashed
  anywhere (invariant I23). A send is evidenced by the kernel's **byte count**,
  a file write by its **path**, an execution by the executable's **content
  hash** — never file contents, never message bodies.
- **On-prem / offline.** No foreign cloud in the trust path; fully
  offline-deployable (`PRODUCTION_READINESS.md`). Evidence and keys stay in the
  institution's environment.
- **PII.** Inputs are referenced by hash; content can stay out of the packet.
  The institution's DPO reviews the exact field set before Phase 1. The review
  is **stricter for insurance/health** workloads (actuarial and health data are
  DPDP's most sensitive category) and for **lending** (borrower financial data):
  confirm no path, filename, or byte-count the observer records can leak a
  sensitive attribute, and drop or coarsen any that could.

---

## 7. Build status (what now exists, and what remains)

**Built in Phase 1** (design record: `docs/pilot/PHASE1_DAEMONS.md`; all with
unit + integration tests, `clippy -D warnings` clean):

1. **Probe daemon** (`aip-probe`) — a long-running host-side process over
   `aip-observe`'s perf sensors (sched, sockstate, socksend). Holds a
   transport-auth key only; no evidence key.
2. **Authenticated probe→collector transport** (`aip-transport`) — std-only
   blocking TCP, length-prefixed frames bounded before allocation, an Ed25519
   challenge/response handshake against the collector's allow-list, and a
   per-frame signature over a domain-separated preimage (session nonce +
   strictly increasing sequence + `sha256(batch)`). Replay, reorder, tamper and
   oversize are refused; a clean disconnect is normal.
3. **Collector daemon** (`aip-collector`) — attests authenticated batches under
   the wrapped key via `CollectorRuntime::start_with_custodian` (a new
   custody-aware path so the runtime never sees a raw key), persists chain
   state, and keeps a fresh signed health record. Fail-closed: a continuity
   refusal writes a signed report and does not serve.

The end-to-end proof runs in CI (`aip-collector/tests/e2e.rs`): a probe client
ships a real `ObservationBatch` over TCP to a collector holding a wrapped key,
and the resulting `AttestedBatch` verifies **offline** against the collector's
public key; an unlisted transport key is refused with nothing attested.

**Remaining before the pilot runs end to end on institution hardware:**

4. **Mechanism-integrity across the split** (Phase 1.x) — convey the probe's
   per-sensor gate finding to the collector as a signed transport field so a
   blinded probe drives `IntegrityUnknown` (safety already holds via the
   coverage predicate; see `PHASE1_DAEMONS.md`).
5. **Gate-independent sensors in the probe** (connector, fanotify, AF_PACKET) —
   requested-but-unsupported today is a startup error, not a silent no-op.
6. **Decision-point coverage statements** for `UNATTRIBUTED_EFFECT` (Phase 2).
7. **aip-service hardening** for §8.
8. **RED suite harness on institution hardware** (extend
   `validation/observation_integrity/pipeline_under_gate.sh`).
9. **TLS/mTLS outer layer and durable batch buffering** on the transport
   (confidentiality and no-loss-on-transient-failure) — deployment concerns
   named in `PHASE1_DAEMONS.md`.

The `deploy/pilot/` kit provides the built daemons' units and config plus the
off-host key-custody procedure.

---

## 8. Pre-production blockers, mapped to BFSI oversight

Merges `PRODUCTION_READINESS.md` §"pre-production blocker list" and
`04_PILOT_READINESS.md` §4 with the observer-side gaps. A **pilot** may proceed
with these open (it is advisory and non-gating); a **regulated production
rollout** may not. The "regulator" column names the segment authority from §0.5;
substitute per segment (RBI for banking/NBFC/payments, SEBI for capital markets,
IRDAI for insurance) — CERT-In and DPDP apply sector-wide.

| # | Blocker | Regulator (per §0.5) / framework | Status |
|---|---|---|---|
| B1 | TLS + rate limiting at ingress | segment regulator's cyber framework; CERT-In | ⬜ (proxy config) |
| B2 | Independent security assessment (CERT-In empanelled) + remediation | CERT-In (all); segment regulator | ⬜ **hard gate, every segment** |
| B3 | Durable, backed-up storage + DR/BCP | segment regulator's BCP/resilience rules (RBI BCP, SEBI CSCRF, IRDAI) | 🟡 (Postgres backend exists; backup/DR not) |
| B4 | KMS/HSM for service **and** collector signing keys; API-key rotation | segment regulator's key-management expectations | 🟡 (wrapped-file custody exists; HSM not) |
| B5 | Signed audit-export bundle + standalone verifier for the auditor | audit / evidence (all) | 🟡 (`aip-verify` + bundle exist; auditor distribution not) |
| B6 | Metrics / monitoring / SIEM export + runbook | SOC integration (all) | ⬜ |
| B7 | Control-framework mapping (RBI / SEBI CSCRF / IRDAI / DPDP / ISO 27001) | compliance, **mapped per target segment** | ⬜ |
| B8 | Off-host collector daemon + authenticated transport (§7.1–7.3) | the P3 guarantee in production (all) | ⬜ **observer-side hard gate** |
| B9 | Client-side signing SDK + `/v1/evidence/ingest` (no agent key on the wire) | key custody (all) | ⬜ |

---

## 9. Roles and runbook

- **The institution's security team** (bank / NBFC / payments / broker / insurer)
  — owns host access, the protected-identity list, the DPO field review, and
  running the RED suite on their hardware.
- **Deploying engineer** — provisions the off-host collector key
  (`deploy/pilot/`), builds the Phase-1 daemons, wires the topology.
- **Auditor** — receives the signed export bundle and reproduces offline
  verification independently (P4).

Runbook: `deploy/pilot/README.md`. This plan is the authority on scope and
safety; the kit is the authority on procedure.
