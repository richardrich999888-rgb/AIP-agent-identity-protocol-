# Observation integrity — requirements

> Companion from a concurrent, independently built characterisation of the same finding: `OBSERVATION_INTEGRITY_THREAT_MODEL.md` (attack model, states, boundary) and `OBSERVATION_INTEGRITY_EXPERIMENT_PLAN.md` (three-phase design, results, AIRI implications). `validation/observation_integrity/README.md` compares the two.

**Status: specified, validated by experiment, and implemented in production**
(`OBSERVE_PROTOCOL_VERSION` 9; see `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md`
for what shipped). The states below were the design vocabulary; the one the
finding turns on, `OBSERVATION_INTEGRITY_UNKNOWN`, is now the real
`aip_observe::ObserverState::IntegrityUnknown`, carried inside the signed
`SensorHealth`. The other four names remain a reasoning vocabulary that the
existing `Active / Degraded / Recovering / ContinuityUnverified / Quarantined`
states and `ObservationAvailability` already realise; this document does not
rename those.

## The property

> **An observer MUST NOT report healthy coverage when the system has
> insufficient evidence that its observation mechanism remained capable of
> observing the event class under test, for the window in question.**

The emphasis is on *evidence that it remained capable*. An observer that
received no events has two explanations it cannot tell apart from its own
outputs — nothing happened, or it was prevented from seeing what happened —
and the requirement forbids it from resolving that ambiguity in its own favour.

## Why this is not ordinary loss

`aip-observe` already models loss: the kernel tells a `perf_event_open` reader,
via `PERF_RECORD_LOST`, how many records it dropped when a ring overran, and
the reader reports that count. That mechanism is sound and unaffected here.

The finding is a different failure. When a BPF program attached to a tracepoint
returns 0, the kernel never submits the sample to *any* perf consumer of that
tracepoint (`perf_trace_run_bpf_submit()` gates submission on the return
value). There is no dropped record to count, because no record was generated
for that consumer in the first place. Loss accounting sees nothing, because
from the ring's point of view nothing was ever lost.

Reproduced deterministically (`validation/observation_integrity/`, kernel
6.18.44):

| Arm | `sched_process_exec` observed | reported loss |
|---|---|---|
| Sniffer Dog alone | 8 of 8 | 0 |
| Sniffer Dog + no-op BPF gate | **0 of 8** | **0** |

Zero events, zero loss, `ACTIVE`. That triple is the vulnerability.

## The states

A vocabulary for what an observer knows about its own coverage. Design only.

- **`OBSERVATION_READY`** — the mechanism opened and attached; no events yet,
  and no positive evidence of capability yet either. The honest state at
  startup, distinct from `ACTIVE`.
- **`OBSERVATION_ACTIVE`** — the mechanism is attached **and** there is current
  positive evidence it can still deliver the event class (see below). Only in
  this state may observations be offered at their full strength.
- **`OBSERVATION_DEGRADED`** — a known, bounded impairment: reported loss, a
  ring overrun, a sensor restart with a defined gap. The affected windows are
  covered-with-loss, and the loss is quantified.
- **`OBSERVATION_UNAVAILABLE`** — the mechanism is known not to be delivering:
  it failed to attach, the reader stopped, the process exited. Absence during
  an `UNAVAILABLE` window is *expected* and carries no information about
  whether events occurred.
- **`OBSERVATION_INTEGRITY_UNKNOWN`** — the mechanism reports attached and
  reports no loss, but the system has **no positive evidence** it remained
  capable. This is the state the finding creates and the one today's model
  lacks: it currently collapses into `ACTIVE`, which is the bug.

The distinction that carries the security weight is `ACTIVE` vs
`INTEGRITY_UNKNOWN`. An observer that cannot produce evidence of continued
capability is in the second, not the first, and silence from it means
"cannot say", not "clean".

## What "positive evidence of capability" could mean

Not settled here — the options are in
`docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md`. It is named as a requirement,
not a design: something must periodically demonstrate that the mechanism still
delivers the event class — a liveness canary the observer must see, a second
mechanism that would disagree, an enumeration of BPF programs gating the
sampled tracepoints, or an off-host vantage point. Absent any such evidence,
the correct state is `INTEGRITY_UNKNOWN` and the correct downstream verdict is
`CANNOT_PROVE`.

## Relationship to the existing health model

`aip-observe` has `ACTIVE / DEGRADED / RECOVERING / CONTINUITY_UNVERIFIED /
QUARANTINED`. Those describe the observer's *own* lifecycle — did it restart,
did its sequence break, is its state file trustworthy. They do not describe
*interference with its mechanism by a third party*, which is what this finding
is. `INTEGRITY_UNKNOWN` is orthogonal to all five: an observer can be `ACTIVE`
and continuity-verified in the existing model and still be blind.

This document does not redefine the existing states and does not touch the code
that implements them. Whether `INTEGRITY_UNKNOWN` becomes a sixth production
state, or is expressed through the existing ones, is a decision recorded for
later, gated on the experiment in `OBSERVATION-INTEGRITY-001.md`.

## The inference this forbids

> no observed event  ⟹  no event occurred

is invalid whenever observer integrity is `UNKNOWN` or `UNAVAILABLE`. It is
valid only when the observer was `ACTIVE` — attached *and* evidenced-capable —
across the whole window in question. Vanian's existing `CANNOT_PROVE` default
already refuses this inference in the reconciler; this requirement is the
statement of *when the observer is entitled to assert the coverage* that would
let a verifier move off `CANNOT_PROVE` in the first place.

---

## The six situations that must stay distinct

An observation report has to keep these apart. Collapsing any pair is a
correctness failure; collapsing 1 with 3/4/5 is a *security* failure.

| # | Situation | What the observer sees | Correct reading |
|---|---|---|---|
| 1 | no event occurred | nothing | there was nothing to observe |
| 2 | event occurred, observed | the event | established (subject to strength) |
| 3 | event occurred, missed (loss) | a reported `PERF_RECORD_LOST` | covered-with-loss; window is `DEGRADED` |
| 4 | observer was unavailable | nothing, and it knows it is down | `UNAVAILABLE`; absence carries no information |
| 5 | observer was interfered with | nothing, and it does **not** know | `INTEGRITY_UNKNOWN`; absence carries no information |
| 6 | observer health cannot be established | nothing, and it cannot check | `INTEGRITY_UNKNOWN` |

Situations 1 and 2 are the only ones from which a positive statement about
occurrence may be made. Every other row means "cannot say" about the events in
that window.

The finding is that situation **5 currently presents identically to situation
1** — nothing observed, no loss, `ACTIVE` — and the observer's outputs give a
verifier no way to tell them apart. That is the exact confusion this
requirement exists to forbid.

The forbidden inference, once more, precisely:

> `observed_count == 0`  ∧  `reported_loss == 0`  ⟹  `no_event_occurred`

is sound only under `OBSERVATION_ACTIVE` for the whole window. Under
situations 4, 5 or 6 it is invalid, and the observer is not entitled to the
`ACTIVE` assertion that would license it.

---

## Attack model

Each row: the attacker capability; whether the interference is **detectable**
here; on what basis; whether it is **provable** (independently attestable, not
just noticeable); the **expected conservative fallback**; and the security
impact if the fallback is not taken. "Here" means kernel 6.18.44 with the
current single-mechanism Sniffer Dog; a different mechanism mix changes the
detectability column, which is the point of
`docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`.

### `CAP_BPF` subject — no-op BPF program on the sampled tracepoint

- **Attack.** Attach a program returning 0 to `sched:sched_process_exec`.
  Reproduced; this is the finding.
- **Detectable.** Not by Sniffer Dog today. Yes, by enumerating BPF programs
  attached to the tracepoint (`bpf_prog_query` / `PERF_EVENT_IOC_QUERY_BPF`),
  or by a liveness canary, or by a second mechanism.
- **Detectability basis.** The gating program is enumerable kernel state; a
  known exec that fails to appear is positive evidence of blindness.
- **Provable.** Partially. The presence of a foreign gating program is
  attestable; that it was *malicious* is not — a legitimate observer looks
  identical.
- **Expected fallback.** `INTEGRITY_UNKNOWN` → `CANNOT_PROVE` for the window.
- **Impact if not taken.** Silent, total blindness to exec on that tracepoint
  reported as full coverage. **This is the finding.**

### `CAP_PERFMON` subject

- **Attack.** Open perf events, sample or manipulate; cannot load the gating
  BPF program without `CAP_BPF`, but can contend for ring buffers and perf
  resources.
- **Detectable.** Resource pressure is visible as reported loss; the tracepoint
  gate specifically is not reachable with `CAP_PERFMON` alone.
- **Detectability basis.** `PERF_RECORD_LOST` accounting.
- **Provable.** Loss is kernel-reported and attestable.
- **Expected fallback.** `DEGRADED`, quantified.
- **Impact.** Bounded; the existing loss model covers it.

### root subject

- **Attack.** Everything below plus load kernel modules, detach observers,
  rewrite `/proc`, unload the sensor.
- **Detectable.** Some actions (killing the observer) yes; a root that
  rewrites kernel state to hide itself, no.
- **Detectability basis.** Only for interference that leaves host-visible
  traces a *different* trust domain can see.
- **Provable.** No, not from on-host evidence.
- **Expected fallback.** `INTEGRITY_UNKNOWN`; and no on-host observer may claim
  root-compromise resistance.
- **Impact.** Total if unacknowledged. Must be a stated limit, not a silent
  one.

### competing eBPF observer (benign)

- **Attack.** None intended — A3S is the real case. A second legitimate BPF
  tool attaches a gating program and incidentally blinds the perf reader.
- **Detectable.** Same basis as the `CAP_BPF` row; indistinguishable from the
  malicious case, which is why detection keys on *effect*, not *intent*.
- **Provable.** The program's presence, yes.
- **Expected fallback.** `INTEGRITY_UNKNOWN` for the affected tracepoint.
- **Impact.** Accidental blindness reported as coverage. Observed with A3S.

### malicious BPF program (targeted)

- **Attack.** A program that passes most events but drops the ones that matter
  (returns 0 selectively on a target pid/argv).
- **Detectable.** Much harder — a canary using different argv than the target
  would still pass. Requires the canary to be indistinguishable to the gating
  program from real events, or a second mechanism.
- **Detectability basis.** Cross-mechanism disagreement; a single-mechanism
  observer cannot see selective suppression of events it never generated.
- **Provable.** No, from one mechanism.
- **Expected fallback.** `INTEGRITY_UNKNOWN` whenever a foreign gating program
  is present, regardless of whether the canary passed.
- **Impact.** Targeted, deniable blindness. Worse than the total case because a
  naive canary gives false assurance.

### observer termination

- **Attack.** `kill` the observer.
- **Detectable.** Yes — the process is gone.
- **Detectability basis.** Process liveness; a supervisor sees the exit.
- **Provable.** Yes.
- **Expected fallback.** `UNAVAILABLE`; the gap is explicit.
- **Impact.** None if the gap is honoured; the existing continuity model
  handles restart.

### observer crash

- **Attack.** Induce a fault (resource exhaustion, a malformed event path).
- **Detectable.** Yes, as termination, plus possibly a truncated final batch.
- **Detectability basis.** Process liveness + sequence discontinuity.
- **Provable.** Yes.
- **Expected fallback.** `UNAVAILABLE`, then `CONTINUITY_UNVERIFIED` on
  restart until re-established.
- **Impact.** None if honoured.

### observer starvation

- **Attack.** Deny the observer CPU or ring memory so it drops events without
  dying.
- **Detectable.** Yes — this is exactly what `PERF_RECORD_LOST` reports.
- **Detectability basis.** Kernel loss accounting.
- **Provable.** Yes.
- **Expected fallback.** `DEGRADED`, quantified.
- **Impact.** Bounded.

### tracepoint interference (the finding)

Covered by the `CAP_BPF` row; named separately because it is the specific
mechanism reproduced.

### perf-event interference

- **Attack.** Manipulate perf configuration or contend for perf resources
  without the BPF gate.
- **Detectable.** As loss or as attach failure.
- **Detectability basis.** Loss accounting; attach return codes.
- **Provable.** Yes.
- **Expected fallback.** `DEGRADED` or `UNAVAILABLE`.
- **Impact.** Bounded.

### ring-buffer overflow

- **Attack.** Flood events faster than the reader drains.
- **Detectable.** Yes — the canonical loss case.
- **Detectability basis.** `PERF_RECORD_LOST`.
- **Provable.** Yes.
- **Expected fallback.** `DEGRADED`, quantified.
- **Impact.** Bounded; already modelled.

### namespace / container boundaries

- **Attack.** Run the subject in a namespace the observer does not correctly
  attribute, or where the observer's view differs.
- **Detectable.** Partially — depends on whether the observer resolves
  namespaces. A3S records `pid_namespace`; Sniffer Dog's binding carries
  `boot_id` but namespace attribution is a known gap.
- **Detectability basis.** Namespace metadata on events, where present.
- **Provable.** Only as far as the metadata is trustworthy, which on a
  compromised host it is not.
- **Expected fallback.** `INTEGRITY_UNKNOWN` for cross-namespace attribution
  that cannot be resolved.
- **Impact.** Misattribution rather than blindness; a distinct problem, flagged
  not solved here.

### kernel-module / root compromise

- **Attack.** Patch the kernel to lie to every on-host observer uniformly.
- **Detectable.** No, by any on-host observer, by construction.
- **Detectability basis.** None on-host. Only an off-host or hardware-rooted
  vantage could see it.
- **Provable.** No.
- **Expected fallback.** `INTEGRITY_UNKNOWN`; and the threat model must state
  that on-host observation assumes an uncompromised kernel.
- **Impact.** Total and undetectable on-host. This is the outer boundary of
  what any software observer on the observed host can promise, and it must be
  written down rather than implied.

### Summary of the model

Three tiers fall out:

1. **Loss-visible** (starvation, overflow, perf contention): the existing
   `PERF_RECORD_LOST` model already reports these as `DEGRADED`. No new work.
2. **Integrity-invisible-but-enumerable** (BPF tracepoint gating, competing BPF
   observers): undetectable by loss accounting, detectable by enumerating
   gating programs or by cross-mechanism/canary evidence. **This tier is the
   finding, and it is where a mitigation would live.**
3. **Beyond on-host reach** (root, kernel module compromise): undetectable by
   any on-host observer. Not fixable in software on the observed host; must be
   a declared limit, and only an independent off-host or hardware-rooted
   vantage changes it.

---

## AIRI impact

For each AIRI event kind and each downstream construct: what the finding
changes. The short version is that it changes nothing about what Vanian
*concludes* — because `CANNOT_PROVE` already refuses the dangerous inference —
and everything about what an observer is *entitled to assert* on the way there.

| AIRI event kind | Host-observable? | Effect of the finding |
|---|---|---|
| `AgentExecutionStarted` | no | none new — already `SELF_REPORTED` |
| `ModelInvocationRequested` | no | none new — already `SELF_REPORTED` |
| `ModelInvocationObserved` | no | none new — the name never implied independence |
| `ToolInvocationRequested` | yes (via exec/socket) | corroboration now requires the observer to have been `ACTIVE`, not merely attached |
| `ToolExecutionReported` | yes | same |
| `SubprocessExecution` | **yes — the exact class the finding suppresses** | an observer under `INTEGRITY_UNKNOWN` cannot corroborate or refute; must yield `CANNOT_PROVE` |
| `ExecutionCompleted` | no (needs exit evidence) | none new; exit evidence already unavailable here |
| `ExecutionFailed` | no | same |

Construct-level:

- **`ObservationRecord`.** The finding is an argument that a record needs to
  carry the *integrity state* of the mechanism over its window, not only its
  loss count. A record produced under `INTEGRITY_UNKNOWN` must not be
  presentable as clean coverage. **No change is made to the type here**; this
  is recorded as the requirement a future change would satisfy.
- **`EvidenceCeiling`.** Unchanged, and the finding argues it is load-bearing:
  a content-derived or single-mechanism observation is already ceilinged below
  `Proven`, so even a *successful* exec observation on one gated tracepoint was
  never eligible to be proof on its own. The ceiling is what keeps the finding
  from being catastrophic.
- **`Reconciliation`.** Unchanged and vindicated. `CANNOT_PROVE` is the default
  and the blinded observer produces exactly the silence that keeps it there.
  The reconciler never concludes non-execution from absence, so no false
  verdict arises. What the finding shows is upstream of reconciliation: the
  *coverage assertion* a `PHANTOM_CLAIM` would require — "an attested sensor
  covered the exact window and saw nothing" — must not be derivable from a
  blinded-but-`ACTIVE` observer.
- **`EffectAssessment`.** Unchanged. It already refuses to name an effect
  without corroborating findings; a blinded observer contributes no findings,
  so it cannot inflate an assessment.
- **`NEXORA`.** Unchanged. It commits verified history; it never manufactures
  it. A window that reconciled to `CANNOT_PROVE` commits as `CANNOT_PROVE`.

### The question the mandate poses

> Can absence of independent observation ever be treated as proof of
> non-execution?

**No — and specifically not when observer integrity is unknown.** The finding
makes the reason concrete rather than theoretical: absence from an observer
that is attached, reporting zero loss, and blind is indistinguishable from
absence from an observer that genuinely saw nothing happen. Since the two
cannot be told apart from the observer's outputs, absence can only ever mean
`CANNOT_PROVE` unless the observer can independently evidence that it was
`ACTIVE` — capable, not merely attached — across the whole window. Vanian's
current behaviour already refuses the inference; this requirement names the
precondition under which the refusal could ever be lifted.
