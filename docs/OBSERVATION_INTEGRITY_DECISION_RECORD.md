# Decision record — observer integrity boundary

> See also the mitigation-option analysis in `OBSERVATION_INTEGRITY_THREAT_MODEL.md` §6, from a concurrent independent characterisation.

**Decision: implemented — H + A + G + I, the fail-safe cross-mechanism core.**
The threat was reproduced and characterised, the options below were analysed,
and the operator directed implementation to production. What shipped is the
combination the analysis pointed at as lowest-risk and trust-model-preserving:
detect the gate (H), require an independent mechanism before coverage counts
(A), carry the honest state in the signed record (G), and fail the coverage
assertion closed (I). The heavier options (C canary, D/E remote/off-host, F
hardware) were **not** taken; they remain future work on the
OBSERVER_ATTESTATION roadmap. The original "no mitigation selected" posture is
superseded by this record; the earlier reasoning is retained below because it
is what justifies the selection.

## Status

- `THREAT_REPRODUCED` — `validation/observation_integrity/`, deterministic,
  kernel 6.18.44.
- `THREAT_CHARACTERIZED` — `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`,
  `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`.
- `MITIGATION_OPTIONS_DEFINED` — below.
- `MITIGATION_IMPLEMENTED` — **yes** (see "What shipped").
- One signed-wire change (`OBSERVE_PROTOCOL_VERSION` 8 → 9); no new runtime
  dependency; `CANNOT_PROVE`, `EvidenceCeiling`, and the single reconciler
  authority all preserved.

## What shipped

Fail-safe and strictly monotone: every part can only make the observer *more*
conservative — it can turn an `Active`/covered claim into `CannotProve`, never
the reverse, and it touches no verdict on the trusted-observation side.

1. **Detect (H).** `PerfTracepoints::foreign_bpf_program_count` queries the
   kernel's per-tracepoint eBPF program array through the observer's own perf
   fds (`PERF_EVENT_IOC_QUERY_BPF`); `ProcessTracer::mechanism_integrity` maps
   a foreign program to `ForeignTracepointGate`, fail-closed if the query is
   refused. This is the direct, synchronous detector for the reproduced gate.
2. **State + attestation (G).** `ObserverState::IntegrityUnknown` (new, code
   `0x06`, non-`Active`, fails `permits_attested_use`) is carried inside the
   signed `SensorHealth`. A blinded collector signs the truth, so a verifier
   consumes a coverage claim that is itself evidence — not an assumption. A
   forger holding the collector key can still lie, but that is the separate
   key-custody boundary, stated in `execution-binding` / `attestation-keys`.
3. **Cross-mechanism requirement (A).** `covered_by_kernel_pushed_source`
   now requires a mechanism that does **not** share the perf-tracepoint gate
   (`is_gate_independent_kernel_pushed`): the netlink connector, `fanotify`,
   or the `AF_PACKET` tap. A lone gate-able tracepoint no longer licenses a
   non-occurrence statement. This is always-on and needs no runtime signal, so
   it holds even where detection (H) cannot run.
4. **Fail closed (I).** `IntegrityUnknown` maps to
   `cannot_prove(ObserverIntegrityUnknown)` in every reconciler state gate; a
   blinded observer never reaches `PhantomClaim`.

Tests: `aip-observe` unit + `tests/observer_integrity.rs` (synthetic
adversarial, incl. the re-signing forger); `aip-reconcile` `t03d`/`t03e`
(a blinded observer cannot accuse); `validation/observation_integrity`
reproduces the gate and now asserts the observer reports `integrity_unknown`.

## What any mitigation must preserve

Non-negotiable, because the finding does not justify weakening them:

- The `CANNOT_PROVE` default and the refusal to read absence as non-execution.
  The finding is contained by these today; a mitigation improves *observer
  honesty*, it does not get to relax *reconciler conservatism*.
- `EvidenceCeiling`: no mechanism, however clever, raises a content-derived or
  single-mechanism observation to `Proven`.
- No second Reconciliation authority; no competing proof authority.
- Observer independence from the observed subject.

A mitigation that bought detection by weakening any of these would be a net
loss and is out of scope by construction.

## The options

Each: security benefit; limitations; attacker capabilities defeated and not
defeated; false-positive and false-negative risk; complexity; performance; new
trust anchors; architectural impact; whether it preserves the current Vanian
trust model.

### A. independent second observation mechanism (require agreement)
- **Benefit.** Two mechanisms on different kernel paths for the same event
  class; a gate on one is exposed by disagreement with the other.
- **Limitations.** Only as independent as the *paths* — two tracepoint
  consumers do not count (the whole finding). Must be genuinely different
  facilities.
- **Defeats.** `CAP_BPF` tracepoint gating, `CAP_PERFMON` contention,
  accidental interference.
- **Does not defeat.** Root; kernel-module compromise; an adversary who gates
  *both* paths.
- **FP risk.** Moderate — legitimate timing skew between mechanisms can look
  like disagreement; needs a tolerance window.
- **FN risk.** Low for single-path attacks; high for dual-path.
- **Complexity.** Moderate. **Two instances already exist in-tree.** Sniffer
  Dog reads the netlink proc connector (`linux.rs`), a non-tracepoint facility,
  for the exact fork/exec/exit class the finding suppresses. And the concurrent
  AIRI work established the **audit subsystem** (`NETLINK_AUDIT`) as
  mechanism-independent of the tracepoint path and verified it usable on this
  kernel (`validation/airi/OBSERVER_INDEPENDENCE.md`) — a syscall-boundary
  witness, stronger than the connector because it also catches events the
  `sched_*` tracepoints never fire for.
- **Performance.** Low — the connector is already consumed.
- **New trust anchors.** None.
- **Architectural impact.** Low; a cross-check within the existing observer.
- **Preserves trust model.** Yes.

### B. cross-mechanism observation (correlate, don't require)
- Like A but advisory: record which mechanisms agreed rather than gating on
  agreement.
- **Benefit.** Surfaces `INTEGRITY_UNKNOWN` without risking availability from
  false disagreement.
- **Limitations.** Does not itself force a conservative verdict — relies on the
  reconciler continuing to default to `CANNOT_PROVE`.
- **FP/FN.** Lower FP than A, higher FN (a disagreement is noted, not acted
  on).
- **Preserves trust model.** Yes; arguably the most conservative option.

### C. observer liveness heartbeat (canary)
- **Benefit.** A known event emitted at a known cadence that the observer must
  see; a missed canary is positive evidence of blindness — the thing the
  finding shows is otherwise absent.
- **Limitations.** A *targeted* gate that suppresses only the attacker's own
  events (not the canary's) passes. The canary must be indistinguishable to the
  gating program from real events, which is hard against a discriminating
  adversary.
- **Defeats.** Total blindness (the reproduced case).
- **Does not defeat.** Selective/targeted suppression; root.
- **FP risk.** Low if the canary is robust. **FN risk. Real and subtle** — a
  passing canary can give false assurance against a targeted gate, which is
  worse than no canary. This risk must be stated wherever a canary is used.
- **Complexity.** Low–moderate.
- **Performance.** Low.
- **New trust anchors.** None.
- **Preserves trust model.** Yes, if a passing canary is treated as *necessary
  not sufficient* for `ACTIVE`.

### D. remote observer
- **Benefit.** Signing/collection off the observed host; the host cannot forge
  or suppress what it never held.
- **Limitations.** Network partition becomes `OBSERVATION_UNAVAILABLE` (which
  is correct, not a failure); does not by itself detect on-host tracepoint
  gating unless combined with a mechanism that would notice.
- **Defeats.** Post-hoc tampering with collected evidence; host-local evidence
  deletion.
- **Does not defeat.** On-host blindness at the source — if the on-host sensor
  is gated, it ships nothing to forward.
- **FP/FN.** FP from partitions; FN for source-level gating.
- **Complexity.** High. **New trust anchor: the collector**, which the
  architecture already contemplates (OBSERVER_ATTESTATION).
- **Preserves trust model.** Yes — it is the direction the architecture already
  leans.

### E. off-host observation
- **Benefit.** Observes from entirely outside the host kernel — the only path
  independent of a root/kernel compromise of the observed host.
- **Limitations.** Coarse: sees network and physical effects, not in-process
  tool calls; expensive; not always available.
- **Defeats.** Root; kernel-module compromise — uniquely.
- **Does not defeat.** Nothing about in-process model calls, which leave no
  external trace.
- **Complexity.** High. **New trust anchor: the external vantage.**
- **Preserves trust model.** Yes.

### F. hardware-backed observer
- **Benefit.** Roots observer integrity in hardware the host software cannot
  forge (TPM-measured sensor, attested boot of the sensor).
- **Limitations.** Attests that the *right sensor* is running, not that its
  tracepoint was not gated afterward — necessary, not sufficient, against this
  finding.
- **Defeats.** Sensor substitution; boot-time tampering.
- **Does not defeat.** Runtime tracepoint gating of an attested sensor.
- **Complexity.** High; hardware dependency. **New trust anchor: the TPM/RoT.**
- **Preserves trust model.** Yes, but addresses a different part of the problem
  than the finding.

### G. observation-health attestation
- **Benefit.** The observer signs a statement of its own integrity state
  (`ACTIVE`/`DEGRADED`/`INTEGRITY_UNKNOWN`) alongside its observations, so a
  verifier consumes coverage claims that are themselves evidence rather than
  assumed.
- **Limitations.** Only as truthful as the observer's *self-knowledge* — if the
  observer cannot detect its own blinding (today's case), a signed `ACTIVE` is
  a signed falsehood. Must be paired with A/B/C so the observer can actually
  know.
- **Defeats.** Nothing on its own; it is the *carrier* for whatever detection
  A/B/C provide.
- **Complexity.** Moderate — this is the piece that would touch
  `ObservationRecord`.
- **Preserves trust model.** Yes, and it is where the `INTEGRITY_UNKNOWN` state
  from the requirements doc would become real.

### H. kernel-side integrity evidence
- **Benefit.** Enumerate BPF programs attached to the sampled tracepoints
  (`bpf_prog_query` / `PERF_EVENT_IOC_QUERY_BPF`); a foreign gating program is
  directly observable kernel state.
- **Limitations.** Needs `CAP_BPF`/`CAP_PERFMON` to query; a root adversary can
  hide programs by patching the kernel; detects presence, not intent (benign
  and malicious look identical — which is fine, since the fallback is the same).
- **Defeats.** Exactly the reproduced finding — it makes the gate visible.
- **Does not defeat.** Root/kernel compromise.
- **FP risk.** Low, but every legitimate co-resident eBPF tool (A3S itself)
  trips it, so the fallback must be `INTEGRITY_UNKNOWN`, not "attack".
- **Complexity.** Low–moderate; no new dependency, no new anchor.
- **Preserves trust model.** Yes. **The most directly targeted at the finding.**

### I. fail-closed coverage assertion
- **Benefit.** The default is that a window is *not* covered unless positively
  evidenced `ACTIVE`; silence never reads as coverage.
- **Limitations.** This is arguably already Vanian's posture at the reconciler
  (`CANNOT_PROVE` default). As an *observer* policy it means the observer
  refuses to assert `ACTIVE` without evidence — which needs A/B/C/H to supply
  that evidence, so it is a policy, not a mechanism.
- **Defeats.** The *consequence* of every blindness attack (false coverage),
  regardless of detection.
- **Does not defeat.** Availability — everything degrades to `CANNOT_PROVE`
  without a capability signal, which is safe but weak.
- **FP risk.** High availability cost if no capability evidence exists (all
  windows `CANNOT_PROVE`). **This is why it must be paired with a detector.**
- **Preserves trust model.** Yes — it is the strongest expression of it.

### J. privileged trusted observer
- **Benefit.** A single observer with privileges the subject lacks, so the
  subject cannot attach competing BPF programs.
- **Limitations.** Requires denying `CAP_BPF` to the subject — a deployment
  constraint, not a Vanian mechanism, and often impossible (the subject may
  legitimately need it). Concentrates trust.
- **Defeats.** `CAP_BPF` subjects *if* the subject can be denied that
  capability.
- **Does not defeat.** Root; any subject that must hold `CAP_BPF`.
- **Complexity.** Low technically, high operationally.
- **Preserves trust model.** Partially — concentrating observation trust in one
  privileged component is in tension with independence.

## Reading of the options (analysis, not a decision)

The finding lives in the "integrity-invisible-but-enumerable" tier (per the
requirements doc). Three options address that tier directly and cheaply,
without new trust anchors and while preserving the trust model:

- **H** (enumerate gating BPF programs) makes the specific attack *visible*.
- **A/B** via the already-consumed **netlink connector**, or via the
  **audit subsystem** the sibling work proved usable and mechanism-independent,
  make it visible through *disagreement*, with no new trust anchor.
- **G + I** are how visibility becomes a *verdict*: the observer signs
  `INTEGRITY_UNKNOWN` and the coverage assertion fails closed.

**C** (canary) is attractive and carries a specific trap — a passing canary
against a targeted gate is false assurance — so it is at most a supplement.
**D/E/F** raise the ceiling against root and kernel compromise but are heavier
and introduce trust anchors; they belong to the OBSERVER_ATTESTATION roadmap,
not to closing this finding.

None of this is selected. The discriminating evidence is which of H / A-B / G-I
the OBSERVATION-INTEGRITY-001 matrix shows to be *sufficient on its own* to move
condition E/F from a lucky `CANNOT_PROVE` to an *observer-reported*
`INTEGRITY_UNKNOWN`. Until that experiment runs, selecting one would be a guess
with the reasoning written afterwards, which is what this record exists to
avoid.

## If implementation is later found unavoidable

Per section 9 of the governing mandate, any production change stops before
implementation and reports: the exact defect (observer reports `ACTIVE`/no-loss
under `INTEGRITY_UNKNOWN`); the security property affected (the coverage
assertion, hence the precondition for lifting `CANNOT_PROVE`); the proposed
change (most likely a new integrity state carried on `ObservationRecord`, fed
by H or A/B); why validation-only instrumentation is insufficient (a verifier
consuming records cannot see interference the observer did not record); and the
compatibility impact (a new field/state on a signed record is a wire change and
would need the usual single deliberate version bump). That report is not
written yet, because the experiment that would justify a specific change has
not run.
