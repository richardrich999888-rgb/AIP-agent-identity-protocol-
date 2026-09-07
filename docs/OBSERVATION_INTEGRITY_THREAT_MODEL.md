# Observation-integrity threat model

Status: **THREAT_CHARACTERIZED.**

Not MITIGATION_DESIGNED beyond the option analysis in §6, not
MITIGATION_IMPLEMENTED, not "secure against privileged subjects". This
document defines a security property, reproduces one concrete violation of it,
and maps the boundary of what is currently detectable. It changes no
production code.

The organising rule is unchanged from the rest of the validation programme:

> The actor should not control the evidence used to judge the actor.

This document adds a corollary the AIRI experiment forced into view:

> A silent observer is not a healthy observer. Absence of events is not
> evidence of absence of activity unless observer integrity is independently
> established for the window.

---

## 1. The finding that motivates this

During AIRI-INDEPENDENT-AGENT-OBSERVATION-001 and the follow-up
OBSERVATION-INTEGRITY-001, a second eBPF observer (A3S) attached to
`sched:sched_process_exec` caused Sniffer Dog 2.0's `perf_event_open` sensor to
stop receiving exec events for that tracepoint — **while reporting zero loss.**

Reproduced deterministically here, in one observer lifetime with no restart
(`validation/observation_integrity/`, verdict `INTERFERENCE_REPRODUCED_SILENTLY`,
`PER_TRACEPOINT_CONFIRMED`, `TOTAL_SUPPRESSION` in the confirmed-attached
window). §7 of the experiment plan has the full evidence.

The security problem is not that events were lost. The security problem is that
**the observer could not tell that it had been blinded**, and every coverage
signal it exposes would have reported health.

## 2. The security property

Five states. **Defined here as documentation only — not as production types.**
Whether any of these becomes an `enum` in `aip-observe` is a later, explicit
decision, and §6 argues that some of them cannot be soundly computed on the
observed host at all.

### OBSERVATION_HEALTHY
The observation mechanism is attached, receiving, and its coverage for the
window is positively established by evidence the observed subject cannot forge
or suppress. This is the strong state, and the finding below shows the current
system cannot actually establish it — it can only establish the absence of the
*specific* faults it knows how to look for.

### OBSERVATION_AVAILABLE
The mechanism is attached and the collector holds a verified, contiguous,
clean-probe-stream link over the window. This is what `aip-observe` currently
computes as `ObserverState::Active` + `attested_coverage` covering the window.
**It is weaker than HEALTHY**, because it is satisfied by silence: a window
with zero events and zero reported loss is AVAILABLE under the present rules.

### OBSERVATION_UNAVAILABLE
The observer cannot vouch for the window, and says so. Already modelled:
`ObservationAvailability::Unavailable{reason}` with `UnavailableReason` covering
no-observer, degraded, recovering, continuity-unverified, quarantined,
window-not-covered, health-stale. This is the correct, conservative state and
the system reaches it well for the faults it can see.

### OBSERVATION_INTERFERED
A third party has suppressed, corrupted, or degraded the observation path
without the observer recording a fault. **This is the state the finding
occupies and the state the system currently cannot represent or reach.** It is
distinct from UNAVAILABLE: UNAVAILABLE is the observer admitting a gap;
INTERFERED is a gap the observer does not know it has.

### OBSERVATION_COVERAGE_UNKNOWN
The observer cannot establish whether its coverage over the window was intact.
This is the honest label for the finding: after the fact, a window during which
`perf` submission may have been gated is not provably covered, and — critically
— is also not provably uncovered. The correct behaviour is to **fail toward
this state**, not toward AVAILABLE.

### The three distinctions that matter

The mandate names them and they are the spine of this model:

| | meaning | who can assert it |
|---|---|---|
| **NO EVENT** | the thing did not happen | requires proof of intact observation |
| **NO EVIDENCE THAT EVENT OCCURRED** | we did not record it happening | any observer, always |
| **NO ABILITY TO OBSERVE EVENT** | our observation path was down or gated | requires observer self-knowledge the system lacks here |

The defect is that the current system collapses the third into the first: a
gated observer produces "no evidence", and a coverage model that keys on
reported loss reads "no evidence + no loss" as "nothing happened". The whole
point of this model is to keep those three apart, and to make the system say
the second or third rather than the first whenever integrity is not established.

## 3. Attack model

Seventeen attacker positions. For each: can it happen here; can Sniffer Dog
detect it; can it prove it; what the system should report if detection is
impossible.

"Detect" means the observer itself surfaces a fault for the window. "Prove"
means it can produce evidence a third party recomputes. The default correct
report for anything undetectable is **OBSERVATION_COVERAGE_UNKNOWN for the
affected window**, never OBSERVATION_AVAILABLE.

| # | Attacker position | Can happen here | Sniffer Dog detects | Can prove | Correct report if undetectable |
|---|---|---|---|---|---|
| 1 | Subject with `CAP_BPF` | **yes** — can load a BPF prog on the same tracepoint | **NO** (the finding) | no | COVERAGE_UNKNOWN |
| 2 | Subject with `CAP_PERFMON` | yes — can open perf events, contend | partial (may show loss) | no | COVERAGE_UNKNOWN |
| 3 | Privileged root subject | yes — can do 1, 2, and disable the tracepoint | NO for the silent paths | no | COVERAGE_UNKNOWN |
| 4 | Competing eBPF program | **yes — demonstrated** | **NO** | no | COVERAGE_UNKNOWN |
| 5 | Competing perf-event consumer | yes | usually (ring pressure → loss) | partial | UNAVAILABLE(Degraded) if loss seen, else COVERAGE_UNKNOWN |
| 6 | Tracepoint interference (BPF return-gate) | **yes — demonstrated, per-tracepoint** | **NO** | no | COVERAGE_UNKNOWN |
| 7 | Observer process termination | yes | yes — collector sees the stream stop | partial | UNAVAILABLE(NoObserver/Stale) |
| 8 | Observer crash | yes | yes — health goes stale | partial | UNAVAILABLE(HealthStale) |
| 9 | Observer restart | yes | **yes** — run-id change → Recovering | yes | UNAVAILABLE(Recovering) |
| 10 | Observer process starvation | yes | partial — may manifest as loss or stale health | no | COVERAGE_UNKNOWN |
| 11 | Ring-buffer pressure | yes | **yes** — `PERF_RECORD_LOST` → Degraded | yes | UNAVAILABLE(Degraded) |
| 12 | Timestamp manipulation | subject cannot touch kernel monotonic; root can skew wall clock | partial | no | COVERAGE_UNKNOWN for ordering |
| 13 | Namespace isolation | yes — pid/mount ns affect attribution | partial | no | COVERAGE_UNKNOWN for attribution |
| 14 | Container boundary | yes — observer in one container, subject in another | depends on host visibility | no | COVERAGE_UNKNOWN outside the observer's namespace |
| 15 | Kernel configuration limits | **yes — present** (`# CONFIG_KPROBES is not set`) | n/a — a build fact | yes (readable) | mechanism BLOCKED, stated |
| 16 | Observer self-monitoring | the observer watching itself | **cannot detect its own blinding** — the finding | no | COVERAGE_UNKNOWN; self-monitoring is not sufficient |
| 17 | Malicious kernel module / root-level attacker | yes | **NO** — defeats every host observer identically | no | COVERAGE_UNKNOWN; outside any host observer's boundary |

The pattern: the system detects **loss-shaped** and **lifecycle-shaped** faults
(rows 7–9, 11) well, and is blind to **suppression-shaped** interference (rows
1, 4, 6, 16) and to anything at or below its own trust boundary (rows 3, 17).

## 4. Observation-mechanism independence

The mandate's rule, restated: two consumers of the same kernel tracepoint are
not independent observers. The finding is the proof — A3S and Sniffer Dog both
touch `sched:sched_process_exec`, and one silenced the other.

| Mechanism | Kernel source | Independent of Sniffer Dog | Can interfere with it | Can detect interference | Liveness or corroboration |
|---|---|---|---|---|---|
| **Sniffer Dog 2.0** | `perf_event_open` on sched tracepoints | — (it is the subject) | — | no (self-blind) | — |
| **A3S Observer** | eBPF on **the same** sched tracepoints + syscall tracepoints | interface only | **YES — demonstrated** | no | corroboration only, and a hazard |
| **Tetragon** | eBPF on **kprobes** (kernel functions) | **mechanism** — different probe site | possibly (also BPF) | plausibly | corroboration of the *event*; blocked here |
| **ftrace** | ftrace ring on the **same** sched tracepoints | interface only | no (separate submission path) | partial — kept working when perf was gated | corroboration of *reading* |
| **perf_event** | the submission path itself | — | is the gated path | no | — |
| **eBPF (generic)** | wherever attached | depends on attach point | **yes if same tracepoint** | no | depends |
| **tracepoints** | the shared source | consumers are not independent | n/a | n/a | shared source |
| **procfs** | `/proc` snapshot | **mechanism** — pull, not push | no | can detect a live process, not a missed exec | liveness of *state*, not of *events* |
| **fanotify** | VFS-level file events | **mechanism** for file ops | no | no | corroboration for file effects only |
| **netlink (audit)** | `audit_syscall` hook, `kernel/auditsc.c` | **mechanism** — different subsystem, not on the perf path | no | **YES — kept full coverage throughout the attack** | second witness at the syscall boundary |
| **netlink (proc connector)** | `cn_proc` | mechanism vs tracepoints | no | plausibly | corroboration of fork/exec |

The load-bearing rows: **audit** stayed fully live through every interference
arm here (it is what established the executions really happened), and **ftrace**
kept working while the perf path was gated (that asymmetry is what makes the
mechanism diagnosis certain). Both are on different submission paths from the
gated one. **That, not their being "another observer", is why they survived.**

## 5. Where the observation boundary ends — no fabricated claim

Stated in the mandated vocabulary, and deliberately conservative.

- **PROVEN:** the interference reproduces; it is per-tracepoint; it is total for
  the gated tracepoint within the confirmed-attached window; and Sniffer Dog's
  reported loss counter is zero throughout. Established by
  OBSERVATION-INTEGRITY-001 with a negative control and an independent ground
  truth. This is a statement about the *effect*, on this host, with this
  mechanism.
- **CODE-PROVEN:** `ObserverState::Active` requires
  `ContinuityStatus::Verified` and an empty `probe_faults`, and `probe_faults`
  is populated only by a positive loss count, a probe-sequence discontinuity,
  or a probe restart (`aip-observe/src/attest.rs`, `track_probe_stream` and
  `state`). The attack produces none of the three, so the derived state is
  `Active` and `permits_attested_use()` returns true. This is read from the
  code, not run through the full attest pipeline under attack — see §8.
- **CORROBORATIVE:** the *mechanism* — the kernel gating perf submission on a
  BPF program's return value, per `trace_event_call`, host-wide across perf
  consumers of that tracepoint — is the explanation given by the concurrent
  experiment's reading of kernel source
  (`validation/external/a3s_observer/TRACEPOINT_INTERFERENCE.md`). It is
  corroborated here behaviourally: the per-tracepoint isolation (gating exec
  suppresses exec, gating fork does not) is exactly what that explanation
  predicts, and the ftrace path surviving is the predicted asymmetry. The
  kernel source itself was not read on this host (only `/proc/config.gz` is
  available), so the exact function name is corroborative, not proven-here.
- **UNKNOWN:** whether the same gate is reachable by an unprivileged subject.
  It required `CAP_BPF`-equivalent privilege here (root). Whether a constrained
  subject can achieve it is untested.
- **CANNOT_PROVE:** that Sniffer Dog is secure against a `CAP_BPF` subject. It
  is not — the opposite is demonstrated. And no claim is made that any host
  observer resists a root or kernel adversary (rows 3, 17); that is outside the
  boundary and stated as outside it.

**The system is NOT secure against a privileged subject's observation-path
interference, and this document does not claim otherwise.**

## 6. Mitigation options — evaluated, none selected

Per the mandate: analysis only. No option is implemented, and several are
recorded as unsound so they are not reached for later.

Legend for the last columns: **Indep?** = does it add a genuinely independent
observation, or only detect that the primary failed; **New anchor?** = does it
introduce a new trust root the current architecture does not have.

### A. Independent second observation mechanism (audit alongside perf)
- **Benefit:** a mechanism on a different submission path keeps coverage when
  the perf path is gated. Demonstrated: audit held full coverage through the
  attack.
- **Attacker cost to defeat:** must now suppress two subsystems, not one.
- **False positive risk:** low. **False negative:** the two can still be
  defeated together by a root/kernel adversary (row 17).
- **Complexity:** moderate — audit has a single-consumer constraint.
- **New anchor:** no. **Violates architecture:** no. **Independent:** **yes,
  genuinely.** **Merely detects failure:** no — it observes.
- **Verdict: strongest option. It adds observation, not just an alarm.**

### B. Observation health attestation (positive coverage proof)
- **Benefit:** require the observer to prove coverage rather than infer it from
  the absence of known faults. Would turn AVAILABLE-by-silence into
  COVERAGE_UNKNOWN.
- **Attacker cost:** must forge the proof, which is the point.
- **FP risk:** moderate — a genuinely quiet window looks the same as a gated
  one; this is inherent and argues for pairing with A.
- **Complexity:** high — "prove you saw everything" has no local kernel
  primitive.
- **New anchor:** no. **Violates architecture:** no — extends the existing
  `SensorHealth`. **Independent:** no. **Merely detects failure:** it detects
  the *inability to establish* coverage, which is the correct conservative move.
- **Verdict: correct direction for the health model; insufficient alone.**

### C. Heartbeat / liveness channel
- **Benefit:** detects observer death and starvation (rows 7, 10).
- **Against this attack:** **useless.** The observer was alive and heartbeating
  throughout; only its event submission was gated. A heartbeat proves the
  process runs, not that its sensor sees.
- **New anchor:** no. **Independent:** no. **Merely detects failure:** yes, and
  not even this failure.
- **Verdict: addresses a different threat. Do not mistake it for a fix.**

### D. Kernel-side integrity evidence (e.g. count events at the source)
- **Benefit:** a BPF program that counts execs and is compared against the
  perf stream would catch the gap.
- **Problem:** it is on the same attack surface — a subject with `CAP_BPF` can
  gate or unload it too. It moves the boundary, it does not close it.
- **New anchor:** no. **Independent:** partially. **Verdict: circular against
  the very capability in the attack model.**

### E. Cross-mechanism sampling
- **Benefit:** periodically confirm the perf stream against audit/procfs for
  known events.
- **This is A in a weaker, sampled form.** Prefer A.

### F. Hardware-backed observation
- **Benefit:** a root/kernel adversary (row 17) is otherwise undetectable; only
  something below the kernel can witness it.
- **Cost:** requires hardware not present; large trust and complexity.
- **New anchor:** **yes — a significant one.** **Verdict: out of scope now,
  and the only thing that addresses rows 3 and 17. Record and defer.**

### G. Privileged observer outside the subject trust domain
- **Benefit:** if the subject cannot load BPF or open perf (no `CAP_BPF`/
  `CAP_PERFMON`), the attack in rows 1–2 is prevented rather than detected.
- **This is a deployment constraint, not code.** It is the cheapest real
  mitigation for the demonstrated attack and belongs in an operator guide.
- **New anchor:** no. **Verdict: necessary regardless of what else is built.**

### H. External host observer
- **Benefit:** an observer on a different host (hypervisor, network tap) is
  outside the subject's kernel entirely.
- **Cost:** only sees what crosses the boundary it sits on (network, not local
  exec). **Verdict: complements, does not replace.**

### I. Watchdog / remote attestation
- **Benefit:** an off-host verifier that expects periodic positive coverage
  proofs (B) and alarms on their absence.
- **New anchor:** yes — the remote verifier. **Verdict: the delivery vehicle
  for B, evaluated with B.**

### J. Fail-closed coverage assertion
- **Benefit:** the cheapest correct change. When coverage cannot be positively
  established, report OBSERVATION_COVERAGE_UNKNOWN and refuse to let the window
  support a "did not happen" conclusion — instead of AVAILABLE.
- **Attacker cost:** none — this is not a detector, it is a refusal to
  over-claim. **FP risk:** raises UNKNOWN on genuinely quiet windows; that is
  the conservative and correct behaviour.
- **New anchor:** no. **Violates architecture:** no — it *is* the architecture's
  own stated principle ("silence must shrink coverage, not extend it")
  extended to cover suppression as well as staleness. **Independent:** no.
  **Merely detects failure:** no — it declines to assert, which is exactly the
  NO EVENT vs NO ABILITY distinction from §2.
- **Verdict: the right first change if any is authorised. It removes the
  dangerous interpretation without adding a trust anchor or a new mechanism,
  and it is honest about what it does not do.**

**Recommended shape, not implemented:** J (fail-closed on unestablished
coverage) + A (audit as a second, different-submission-path observer) + G
(deployment: keep `CAP_BPF`/`CAP_PERFMON` out of the subject domain). B/I for a
stronger later posture. F only if rows 3/17 must be addressed. **No code is
changed by this document.**

## 7. What this does not establish

- Nothing about whether an unprivileged subject can reach the gate (UNKNOWN).
- Nothing about a root or kernel adversary beyond naming it out of boundary.
- Nothing about mechanisms other than `perf_event_open` on a tracepoint.
- Nothing run through Vanian's reconciler or `EvidenceCeiling`; §8 reasons about
  them from the code, and marks that reasoning as such.
