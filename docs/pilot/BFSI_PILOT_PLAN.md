# BFSI pilot plan — Sniffer Dog + AIP, end-to-end

> **Status: PILOT PLAN for a scoped, non-gating, advisory deployment.**
> Not a production rollout. Every claim below maps to code in this repository
> or is named as a build item that does not exist yet. Where this plan and a
> code-backed report disagree, the report wins: `docs/PRODUCTION_READINESS.md`,
> `docs/design_partner/04_PILOT_READINESS.md`,
> `docs/architecture/SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md`,
> `docs/security/ADVERSARIAL_RESULTS.md`.

This plan is deliberately written so a bank's security team and a regulator can
audit it. It states what the pilot proves, what it cannot prove, and the exact
line the system must not cross during the pilot.

---

## 0. What this pilot proves — and does not

The pilot is a falsifiable experiment, not a demonstration. It **passes** only
if the observer's honesty holds under the bank's real conditions, and it
**fails** (usefully) if it does not.

**In scope to prove (P):**

- **P1** — An independently keyed observer records execution-related facts
  (process exec, TCP connect/transition, TCP send by byte count, file write)
  on the bank's real agent hosts, and the reconciler classifies them against
  independently signed authorization.
- **P2** — When the observer was not watching, or was blinded, the system says
  `CANNOT_PROVE` / `ObserverIntegrityUnknown` — it never converts absence into
  an accusation. (This is the property most likely to be attacked; see §3.)
- **P3** — The collector's signing key is **off the observed host**, so a
  compromised agent host can lie to its own probe but cannot forge or suppress
  an attestation after collection.
- **P4** — Every artifact verifies **offline** against keys the bank supplies,
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

If the bank needs any of N1–N5, this pilot is the wrong instrument and the
pre-production blockers in §8 must close first.

---

## 1. Scope and sequencing (observer-first)

The pilot is the full chain — agent → decision point → observer → reconciler →
evidence API → offline verifier — but it is **built and validated in
dependency order**, never downstream-first. Each phase has an exit gate; a
phase does not start until the prior gate is met.

| Phase | Deliverable | Exit gate |
|---|---|---|
| **1** | Off-host collector + host-side probe daemon + authenticated probe→collector transport | A real agent process on a bank host is observed; its batch is signed by a collector on a **different** host holding a wrapped key; `aip-verify` accepts the batch offline. **Transport does not exist yet — this is the first build item (§7).** |
| **2** | Decision point issues signed `ExpectedExecution` for the pilot's agent actions | An expectation and an observation join on `decision_id` + `ExecutionBinding`; reconciler emits `VerifiedExecution` (Attested) on the honest path. |
| **3** | Reconciler + evidence API wired: verdicts land in `aip-service` | `POST /v1/evidence/*` stores and returns a verdict; `GET /v1/authority/{id}` rebuilds the chain; tenant isolation holds. |
| **4** | Adversarial + honesty validation on the bank's hosts | The RED suite (§3) runs on pilot hardware: blinded observer → `ObserverIntegrityUnknown`; observer down → `CANNOT_PROVE`; no false `PhantomClaim`. |
| **5** | Independent cross-check + auditor handoff | Vanian's account reconciled against auditd/Tetragon (§5); signed audit-export bundle handed to the bank's auditor; offline verification reproduced by them. |

Do not skip a phase. A phase-4 pass on a phase-1 gate that was waved through is
not a pass.

---

## 2. Deployment topology (the trust boundary is the design)

```text
  BANK AGENT HOST (attacker-reachable)          SEPARATE COLLECTOR HOST
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
                                                     · TLS at ingress (bank proxy)
                                                     · service signing key in KMS/HSM
                                                     ▼
                                                   aip-verify  (auditor, offline)
```

Two boundaries carry the whole security argument and must be enforced in the
bank's deployment, not assumed:

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
  (already demonstrated in-repo; re-run on bank hardware).
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
  observer degrades, the bank's workload is unaffected; only Vanian's coverage
  claim shrinks.
- **Fail closed for the verdict, fail open for availability.** Missing or
  ambiguous evidence → `CANNOT_PROVE`. An observer error never escalates into
  an accusation or an action.
- **Protected identities.** The bank names its own critical processes as
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
| **Tetragon** | eBPF on **kprobes** | Yes, if the kernel has `CONFIG_KPROBES` | Secondary witness; **blocked where kprobes are absent** (the repo's test kernel lacks them — verify on bank hardware) |
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
  bank's environment.
- **PII.** Inputs are referenced by hash; content can stay out of the packet.
  The bank's DPO reviews the exact field set before Phase 1.

---

## 7. Build items that do not exist yet (honest gap list)

The pilot cannot run end-to-end until these are built. None are hidden behind
optimistic language elsewhere in this plan.

1. **Production probe daemon** (`aip-probe`) — a long-running host-side process
   over `aip-observe`'s live sensors. Today only `ghost-demo` and the exp01
   recorder drive them, both demonstrators.
2. **Authenticated probe→collector transport.** The reference transport is
   pipes + JSONL in a state dir (`LINUX_EDGE_REFERENCE.md` §8); a networked,
   authenticated carrier for two hosts does not exist. The `AttestedBatch`
   signature survives any carrier, so this is transport engineering, not new
   evidence semantics — but it needs its own security review (auth, TLS,
   backpressure) before a bank host.
3. **Production collector daemon** (`aip-collector`) — persists attested
   batches (today only snapshot/health/continuity persist —
   `COMPLETE_IMPLEMENTATION_REPORT.md` §8.6), holds the wrapped key, exposes
   signed health. `WrappedFileCustodian` supplies the key custody; the daemon
   around it is the build item.
4. **Decision-point coverage statements** for `UNATTRIBUTED_EFFECT` (Phase 2).
5. **aip-service hardening** for §8.
6. **RED suite harness on bank hardware** (extend
   `validation/observation_integrity/pipeline_under_gate.sh`).

The `deploy/pilot/` kit provides what **is** buildable now — the off-host key
custody procedure, config templates, and the target daemon shapes — and marks
each of the above as a Phase-1 deliverable.

---

## 8. Pre-production blockers, mapped to BFSI oversight

Merges `PRODUCTION_READINESS.md` §"pre-production blocker list" and
`04_PILOT_READINESS.md` §4 with the observer-side gaps. A **pilot** may proceed
with these open (it is advisory and non-gating); a **regulated production
rollout** may not.

| # | Blocker | Maps to | Status |
|---|---|---|---|
| B1 | TLS + rate limiting at ingress | RBI cyber-security framework; CERT-In | ⬜ (proxy config) |
| B2 | Independent security assessment (CERT-In empanelled) + remediation | CERT-In; RBI | ⬜ **hard gate** |
| B3 | Durable, backed-up storage + DR/BCP | RBI BCP guidelines | 🟡 (Postgres backend exists; backup/DR not) |
| B4 | KMS/HSM for service **and** collector signing keys; API-key rotation | RBI key-management | 🟡 (wrapped-file custody exists; HSM not) |
| B5 | Signed audit-export bundle + standalone verifier for the auditor | audit / evidence | 🟡 (`aip-verify` + bundle exist; auditor distribution not) |
| B6 | Metrics / monitoring / SIEM export + runbook | SOC integration | ⬜ |
| B7 | Control-framework mapping (RBI / DPDP / ISO 27001) | compliance | ⬜ |
| B8 | Off-host collector daemon + authenticated transport (§7.1–7.3) | the P3 guarantee in production | ⬜ **observer-side hard gate** |
| B9 | Client-side signing SDK + `/v1/evidence/ingest` (no agent key on the wire) | key custody | ⬜ |

---

## 9. Roles and runbook

- **Bank security team** — owns host access, the protected-identity list, the
  DPO field review, and running the RED suite on their hardware.
- **Deploying engineer** — provisions the off-host collector key
  (`deploy/pilot/`), builds the Phase-1 daemons, wires the topology.
- **Auditor** — receives the signed export bundle and reproduces offline
  verification independently (P4).

Runbook: `deploy/pilot/README.md`. This plan is the authority on scope and
safety; the kit is the authority on procedure.
