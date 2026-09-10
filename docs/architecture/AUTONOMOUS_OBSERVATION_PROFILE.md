# Autonomous Observation Profile

**Status** SPECIFICATION — written before implementation.
**Scope** Skill 20. Environment-neutral. No vertical profile here.

> **The question.** How can Vanian independently observe autonomous-system
> execution without allowing the autonomous system itself to manufacture,
> modify, suppress, or reinterpret the observation used to judge it?

---

## A. What already exists

The research phase found the independence boundary **already built and
mature**. Recording it precisely matters, because the largest risk to Skill 20
is duplicating it.

| Concern | Existing primitive | Where |
|---|---|---|
| Observer/subject split | `ProcfsProbe` (on host, **no key field, no signing method**) vs `CollectorSigner` (off-host, holds the key) | `aip-observe` |
| Observation mechanisms | `SourceMechanism` — 9 Linux mechanisms, each documented with what it establishes and does not, plus `is_kernel_pushed()` | `observed.rs` |
| Signed observation | `AttestedBatch` — collector-signed, chained (`sequence`, `prev_head`), collector clock `attested_at_ms` | `attest.rs` |
| Observer authority | `ObserverTrustAnchors`: `(observer_id, key_version) → key`, with rotation and revocation | `attest.rs` |
| Coverage declaration | `SignedSensorHealth.covered_by: Vec<SourceMechanism>` — **signed** | `health.rs` |
| Observer condition | `ObserverState` — Active / Degraded / Recovering / ContinuityUnverified / Quarantined | `health.rs` |
| Completeness | `ObservationAvailability` + `UnavailableReason` (NoObserver, ObserverDegraded, ObserverRecovering, ContinuityUnverified, ObserverQuarantined, window-outside) | `health.rs` |
| Continuity / anti-rollback | `ObserverLedger`, `ContinuityBreak`, probe-run and loss accounting | `continuity.rs` |
| Absence of a process | `ObservedEffect::ProcessNoLongerPresent`, documented as a fact about *sampling* | `observed.rs` |
| Host-boot anchoring | `ObservedBoot` — constructible only from a verified batch | `aip-platform` (Skill 19) |
| Evidence ceiling | `precondition_holds` — every content-dependent result class requires **exactly** `Attested` | `aip-reconcile` |
| Replay / duplication | R17 `ACTION_UNIQUENESS`, R18 `REPLAY_SCOPE`, `ObservedHistory` | `aip-protocol` (Skill 16) |
| Self-report boundary | `AiriEvent`, documented as authorship-and-integrity only | `aip-airi` |

**Nothing in that list is rebuilt here.**

## B. What Skill 20 actually adds

Four things, and the first is the reason the others are needed.

### B1 — `ObservationClass`: the environment-neutral layer above mechanism

`SourceMechanism` is a **closed enum of nine Linux mechanisms**. A UAS
altimeter, a UGV wheel encoder, an industrial flow meter and a spacecraft
attitude sensor have no `SourceMechanism` and cannot acquire one without
editing a core-protocol enum — which is precisely the "schema fork of the
accountability core" the architecture forbids, and precisely what would force
"the core protocol to be rewritten" for each future environment.

`ObservationClass` is the abstraction those profiles consume. Each existing
`SourceMechanism` maps into a class; new environments add *implementations*
of a class, not variants of a Linux enum.

### B2 — A declared evidentiary ceiling per class

The skill's acceptance gate: *every profile states its evidentiary ceiling.*
Today the ceiling is real but implicit — enforced per **result class** inside
`precondition_holds`. There is no statement of what an **observation class**
can ever contribute.

`EvidenceCeiling` is that statement. It is:

- **declared, not computed** — a static property of a class, like Skill 18's
  `EvidenceOrigin`;
- **an upper bound only** — it can lower what a class may contribute and can
  never raise it;
- **not a verdict** — this crate computes no `EvidenceStrength` and the
  reconciler remains the only thing that assigns one.

A test asserts no declared ceiling exceeds what the reconciler would permit,
so the declaration cannot drift above the enforcement.

### B3 — `ObservationProfile`: what a deployment is provisioned to observe

`SignedSensorHealth.covered_by` says what an observer **did** cover. Nothing
says what a deployment **can** cover — so a class nobody can observe is
silently absent rather than explicitly unobservable.

The profile makes that explicit, which is what lets a later UAS profile state
honestly: *physical-effect observation is not available on this airframe*, and
have that absence be a recorded fact rather than a gap.

### B4 — `ObservationCorrelation`: binding an observation to what it describes

An observation must be bound to the execution it claims to describe, or an
arbitrary observation becomes evidence for a different execution. This reuses
`ObservedBoot` (Skill 19) and `decision_id`; it introduces no identifier.

## C. What Skill 20 deliberately does NOT solve

- **Physical-effect observation.** The class is *representable* and its
  ceiling declared; no implementation exists. Skill 21.
- **Hardware attestation.** ADR-002 stays PROPOSED. An observer relaying a
  TPM quote is relaying an attestation — the trust-anchor question is
  unchanged by which process carries the bytes, and no class here accepts one.
- **Vertical profiles.** UAS, UGV, robotics, industrial, space, enterprise.
- **Any reconciler change.** None was needed; none was made.
- **Any new observer trust anchor.** Keys stay in `aip-observe`.

---

## Trust and provenance model

Five levels, not collapsed. The first three already exist in the codebase in
some form; Skill 20 names them together so a class can be placed on the ladder.

| Level | Meaning | Owner |
|---|---|---|
| `SelfReported` | Generated by the system being judged | `aip-airi` |
| `Expected` | Derived from authorized intent | `aip-authorize` |
| `Observed` | Independently measured by an observer | `aip-observe` |
| `Attested` | Authenticity anchored by a recognised key | `aip-observe` anchors |
| `Proven` | Satisfies the existing reconciliation requirement | `aip-reconcile` **only** |

`Observed ≠ Proven`. `Attested ≠ Proven`. Only `precondition_holds` decides
`Proven`, and Skill 20 does not touch it.

## Observation taxonomy

| Class | Existing mechanisms | Establishes | Cannot establish | Ceiling |
|---|---|---|---|---|
| `ProcessLifecycle` | `SchedTracepoint`, `ProcConnector`, `PidFdAnchored`, `ProcfsPoll` | that a process instance existed / forked / exec'd, and when in kernel time | what it did; what any effect was | `Attested` |
| `ProcessIdentity` | `PidFdAnchored`, `ProcfsPoll` | which executable content an instance was running | that the code behaved | `Attested` |
| `NetworkSocket` | `ProcNetTable`, `SockStateTracepoint` | that a socket existed / changed state, and its endpoints | that a remote system acted | `Attested` |
| `NetworkWire` | `WireTapAfPacket` | that a frame crossed a device, headers only | which process sent it; payload; remote effect | `Attested` |
| `DataTransfer` | `SockSendTracepoint` | that N bytes were accepted by the kernel for a socket | what the bytes were; that they arrived | `Attested` |
| `FilesystemEffect` | `Fanotify` | that a marked path was modified/closed-for-write by a kernel-bound instance | file contents; that the write was correct | `Attested` |
| `PlatformBinding` | (Skill 19, via `ObservedBoot`) | which host-boot an execution ran on | which physical platform, absent a registry | `Attested` |
| `ObserverIntegrity` | chain arithmetic over signed batches | that a signature or chain failed | anything about the workload | **`Proven`** |
| `PhysicalEffect` | **none** | — | — | `Attested` **(ceiling; unreachable today)** |

Two entries carry the whole argument:

- **`ObserverIntegrity` is the only class whose ceiling is `Proven`**, and
  that matches ADR-001 exactly: `Proven` is reserved for facts recomputable
  from held bytes, and a broken signature is one. It is also, per
  `contain()` gate 6, an accusation about the *sensor*, not the workload.
- **`PhysicalEffect` has no mechanism.** Its ceiling is declared `Attested`
  and is unreachable, because a physical sensor's reading is content read from
  a device — root-forgeable on the observed host, exactly like procfs. Its
  presence in the taxonomy is so a later profile can say "unobservable here"
  rather than leaving a silent hole.

## Observer boundary — candidate architectures

| Candidate | Status | Why |
|---|---|---|
| In-process observer | **PROHIBITED** | The subject would control the evidence used to judge it. `ProcfsProbe` has no key field and no signing method precisely to make this unbuildable |
| Privileged host observer (probe) | **IMPLEMENTED** | Reads procfs and kernel sources; holds no key |
| External collector | **IMPLEMENTED** | Holds the key, assigns chain position, off-host |
| Kernel-pushed sources | **IMPLEMENTED** | perf tracepoints, proc-connector, fanotify — no eBPF |
| Network observer (mirror/TAP) | **IMPLEMENTED** | `WireTapAfPacket`; same code off-host on a TAP |
| Sidecar / separate process | **REPRESENTABLE** | A probe id with declared mechanisms; no new type needed |
| Hardware-backed observer | **DEFERRED** | ADR-002, PROPOSED. No class accepts an attestation |
| Physical sensor observer | **REPRESENTABLE, DEFERRED** | Class declared, ceiling declared, no mechanism. Skill 21 |

## Completeness semantics

Eight states the brief requires, mapped to what exists — Skill 20 adds none of
these, it consumes them:

| State | Representation |
|---|---|
| Observed event | an `ObservedExecution` / `KernelLifecycleEvent` in an attested batch |
| Observed absence | `ObservedEffect::ProcessNoLongerPresent` — a fact about the observer's sampling |
| Incomplete observation | `ObserverState::Degraded`, probe loss counters |
| Observer unavailable | `UnavailableReason::NoObserver` |
| Observer compromised | `ObserverState::Quarantined` |
| Observation gap | `ContinuityStatus`, `ContinuityBreak` |
| Collector gap | `ObserverState::Recovering` / `ContinuityUnverified` |
| Suppressed data | loss counters + chain arithmetic; suppression before signing is **not detectable**, and is recorded as such |

**No observation is never "the event did not happen."** A class declared
unobservable yields `NotObservable`; an observable class with no evidence
yields `NotObserved`. Both are compatible with `CANNOT_PROVE` and neither
asserts non-occurrence.

## Temporal semantics

Reused wholesale; no new clock abstraction:
collector `attested_at_ms` (off-host, signed), kernel `CLOCK_BOOTTIME` stamps
on pushed events, `boot_id` for reboot boundaries, collector `sequence` +
`prev_head` for order and anti-rollback, probe-run id and loss counters for
gaps, R18 `REPLAY_SCOPE` for cross-packet replay.

## Invariant matrix

| ID | Invariant | Enforcement |
|---|---|---|
| S20-1 | A class's ceiling can never exceed what the reconciler permits | declared table + test against `precondition_holds` semantics |
| S20-2 | A profile can lower a ceiling, never raise it | `min` at the one construction point |
| S20-3 | Self-report cannot become an observation | no constructor accepts AIRI material |
| S20-4 | An observation record requires a verified attested batch | constructor takes batch + anchors |
| S20-5 | Only `ObserverIntegrity` may declare a `Proven` ceiling | table + test |
| S20-6 | `PhysicalEffect` has no mechanism | mapping is total and excludes it |
| S20-7 | Unobservable ≠ unobserved ≠ observed-absent | three distinct states |
| S20-8 | Absence never asserts non-occurrence | no API returns "did not happen" |
| S20-9 | An observation is bound to system, execution and platform | all inside the canonical preimage |
| S20-10 | Wrong system/execution/platform is refused | correlation check |
| S20-11 | No observer key leaves `aip-observe` | structural test |
| S20-12 | No `EvidenceStrength` is computed here | code scan |
| S20-13 | No TPM/attestation material is accepted | no field, structural test |
| S20-14 | Unknown versions refused | explicit check |
| S20-15 | Canonical encoding domain-separated and injective | prefix-free, presence bytes |

## NEXORA

Additive, via the existing leaf/component model: an observation record's
digest is a commitment, verified by the holder against its **own** anchors.
The verifier must not trust a package-supplied anchor — B-4's rule, one layer
out. No parallel proof tree; no NEXORA change in this skill.

## Reconciliation

**No change.** `precondition_holds` remains the only place `Proven` is
decided, and the ceiling table is asserted to be consistent with it rather
than to replace it. Skill 20 is additive: it produces inputs.
