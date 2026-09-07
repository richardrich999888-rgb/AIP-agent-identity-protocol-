# CONTAINMENT_MODEL

> **Completion mandate, final state.** Gates 1–11 are complete;
> `SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md` is the single record of
> what exists, what was measured, what may be claimed and what may not.
> Final status: **VALIDATED RUNTIME**, scoped there — the evidence
> machinery, not a shipped product.

## 1. Current state

> **Updated at Gate 9 (Skill 9, `272feac`).** The paragraph below described the
> repository before containment existed and is kept for traceability. What
> exists now is `aip-standalone/aip-containment`: a warrant-gated boundary whose
> only actuator is a Linux cgroup v2 freeze, advisory by default, with every
> attempt a signed record. See §9 and `CONTAINMENT_IMPLEMENTATION_REPORT.md`.

`CONTAINMENT = MISSING` from production, and this is **correct for now**.

Verified: no process termination, no cgroup control, no network blocking, no
firewall manipulation, no actuation of any kind in `aip-standalone/` or
`aip-service/`. The only `kill`-adjacent code anywhere in the repository is on
the unmerged PR #3 branch and is an unrelated child-process teardown.

AIP is an evidence system. It has no enforcement surface, and adding one before
the evidence pipeline exists would be the single most dangerous change
available.

## 2. The prohibited shape

```
anomaly  →  kill process
```

This is forbidden by the skill's §18 and by **I13**. A watchdog that
quarantines on statistical suspicion is a denial-of-service weapon aimed at its
own fleet — one false positive at scale takes down production, and the blast
radius is proportional to how much the operator trusted it.

## 3. Required decision path

```
Observation
    ↓  (attested by an observer the agent does not control)
Evidence
    ↓  (reconciled against ExpectedExecution on decision_id + ExecutionBinding)
Reconciliation Result
    ↓
Evidence Strength          Heuristic | Correlated | Attested | Proven
    ↓
Warrant                    policy predicate over (severity, strength)
    ↓
Containment Decision       explicit, logged, itself sealed as evidence
```

Every arrow is a gate. No arrow may be skipped, and the path may not be
short-circuited by a "high confidence" score, because confidence is Axis 1 and
the gate is on Axis 2 (**I12**).

## 4. Warrant standard

| Evidence strength | Definition | Maximum permitted response |
|---|---|---|
| `Heuristic` | statistical/behavioural inference | **Alert only** |
| `Correlated` | multiple unattested sources agree | **Alert only** |
| `Attested` | signed observer, continuity verified over the window | Alert; Constrain only with explicit operator opt-in |
| `Proven` | arithmetic on held data any third party can recompute — e.g. signature mismatch, hash-chain break, unsealed execution against attested coverage | Containment permitted, subject to policy |

**Non-negotiable:** containment requires `Proven`. Suspicion alone generates an
alert. This mirrors the principle already implemented (correctly) on the
unmerged PR #3 branch at `ot-sentinel/src/response.rs:112-129`, which is worth
reading as prior art even though **I17** bars citing it as capability.

## 5. Default posture

| Setting | Default | Rationale |
|---|---|---|
| Mode | **advisory** | a new deployment must not be able to disable its own fleet |
| Autonomous containment | **off** | requires explicit operator enablement |
| Uncited findings | capped at Alert | a finding with no evidence reference cannot warrant action |
| Degraded sensor | **never** escalates | **I9**; a sensor outage is not a ghost |
| `OBSERVATION_UNAVAILABLE` | **never** warrants containment | **I8** |
| Protected identities | exempt from autonomous action | prevents self-quarantine and control-plane lockout |

## 6. Fail-safe direction

Containment failures must fail **open** (do not contain) and be reported, not
fail closed. Inverting this makes the containment path itself an availability
attack: an adversary who can induce containment errors could otherwise take
down workloads.

Conversely, *detection* failures must fail **closed** in the epistemic sense —
an unverifiable observation yields `CANNOT_PROVE`, never `VERIFIED_EXECUTION`.

## 7. Containment must be accountable to itself

Any containment action is a privileged act and must produce evidence of the
same quality it demanded before acting:

- the action, its target, the warrant, and the reconciliation result that
  justified it are sealed into the evidence chain;
- the sealed record must be independently verifiable by the same
  `verify_packet` path used for agent evidence;
- **I20** applies to the containment feature itself: THREAT → ASSUMPTION →
  MECHANISM → IMPLEMENTATION → TEST → LIMITATION.

## 8. Sequencing

Containment is **step 13** of the skill's §23 order. Preconditions, all
currently unmet:

1. `ExpectedExecution` producer exists (decision point) — **library CLOSED (Skill 5)**; separate-process deployment design only
2. `ExecutionBinding` survives PID reuse — **CLOSED (Skill 4)**
3. Observer with an independent trust root — **CLOSED (Skills 6/6.5)**, collector off-host; deployment separation an operator obligation
4. Reconciliation with `CANNOT_PROVE` as default — **CLOSED (Skill 7)**
5. Warrant engine with orthogonal axes — **CLOSED (Skill 8, `aip-warrant`)**
6. Adversarial tests proving suspicion cannot reach containment — **CLOSED at the warrant boundary** (`aip-warrant/tests/warrant.rs` w12 sweeps every result × strength × severity × availability × policy)

The six preconditions hold at the library level, and Gate 8 added strict
continuity semantics for the collector whose health containment demands.
Containment itself (Skill 9) is now **implemented** — §9. PR #3's actuation
(authority revocation inside the detector loop) was reviewed and not harvested
(`OT_SENTINEL_HARVEST_AUDIT.md` §G, Phase 3); nothing in `aip-containment`
revokes authority, and nothing in it runs inside a detector loop.

Today no production evidence path yields a `Proven` workload violation: the
reconciler produces `Proven` only for `SENSOR_INTEGRITY_FAILURE`, which targets
the observer and which the boundary refuses. So `Contain` is reachable in tests
and unreachable from real inputs. That is a property of the evidence layer,
stated, not a defect of the gate.

## 9. What is implemented (Gate 9)

`aip-containment` accepts a signed `Warrant`, an `ExecutionBinding`, the cited
observer's current signed health and an explicit policy, and returns a signed
`ContainmentRecord`. Seventeen gates run in order before anything is touched:

| # | Gate | Refusal |
|---|---|---|
| 1 | warrant authenticated under the warrant trust root, and **not** under the containment key | `WarrantInvalid` |
| 2 | now inside `[issued_at, valid_until]` | `WarrantNotYetValid` / `WarrantExpired` |
| 3–4 | `response == Contain`, `target == Workload` | `ResponseNotContain` / `TargetNotWorkload` |
| 5 | `strength == Proven`, by explicit match over all four variants | `StrengthBelowProven` |
| 6 | result is a workload violation | `ResultNotWorkloadViolation` |
| 7–8 | observation was not unavailable; evidence references present | `ObservationUnavailable` / `NoEvidenceReference` |
| 9 | engine issued it autonomous and did not flag it protected | `WarrantNotAutonomous` / `WarrantMarkedProtected` |
| 10 | warrant subject bound and equal to the target agent | `SubjectUnbound` / `SubjectMismatch` |
| 11 | no protected agent, decision point or observer involved | `Protected` |
| 12 | mode permits (operator mode needs an acknowledgement naming *this* warrant) | `OperatorAcknowledgement*` |
| 13 | cited observer's health verifies, is `Active` and is fresh | `ObserverHealth*` / `ObserverNotActive` / `ObserverNotCited` |
| 14 | warrant id not consumed | `Replayed` |
| 15 | target attributed live through a held pidfd: pid, start ticks, boot id, executable contents | `Attribution(..)` |
| 16 | consume the warrant id, durably | `Outcome::Failed` if the ledger cannot be written |
| 17 | actuate; `Applied` only on a kernel-confirmed effect | `Outcome::Failed` |

**Action set.** Closed: `AdvisoryOnly` and `FreezeProcess`. No string, path or
command line is representable as an action, and the `Actuator` trait takes an
`Attributed` instance rather than a pid, so a caller holding a process number
cannot reach the kernel through this crate.

**The actuator.** `CgroupV2Freezer` creates a cgroup for the instance under the
detected cgroup2 mount, moves the process there, writes `1` to `cgroup.freeze`,
and reports `Applied` only once `cgroup.events` reports `frozen 1`. Every
failure reverts what was done and fails open. `release` thaws, returns members
to their original cgroup and removes the cgroup.

**Posture.** `ContainmentPolicy::default()` is `Advisory` + `AdvisoryOnly`:
every gate runs, the decision is signed, nothing is actuated, and the warrant is
not consumed. Autonomous actuation needs two independent enablements — the
warrant engine's `autonomous_containment` and the containment policy's
`AutonomousEnabled`.

**Limits worth stating here.** Freezing is not killing and not isolation: a
frozen process keeps its descriptors, sockets and memory, and work already
queued in the kernel may complete. Children the target forks after attachment
inherit the cgroup and freeze with it. Network isolation is deliberately not
implemented.

## 10. Is autonomous containment reachable? (directive §13)

**No, and that is the v1 position rather than an unfinished edge.**

`aip_warrant::evaluate` takes the minimum of three caps, so `Contain`
requires all three to reach it:

| cap | reaches `Contain` when |
|---|---|
| result | the result targets the **workload**: `UNATTRIBUTED_EFFECT`, `PHANTOM_CLAIM`, `IDENTITY_DIVERGENCE`, `LINEAGE_VIOLATION` |
| strength | the strength is **`Proven`** — nothing weaker |
| severity | the operator's table says **`Critical`** |

The severity cap belongs to the operator and may be raised. The other two
are not policy, and the reconciliation engine's own guard fixes which
`(result, strength)` pairs can leave `Draft::finish`:

```
VERIFIED_EXECUTION        Attested
PHANTOM_CLAIM             Attested
UNATTRIBUTED_EFFECT       Attested
IDENTITY_DIVERGENCE       Attested
LINEAGE_VIOLATION         Attested   ← procfs-bound instances, never Proven
CONTINUITY_FAILURE        Attested
SENSOR_INTEGRITY_FAILURE  Attested, Proven
CANNOT_PROVE              Heuristic
```

The only result the engine produces at `Proven` is
`SENSOR_INTEGRITY_FAILURE` — a finding a verifier can recompute from bytes
it already holds, which is what earns the word. That result's own cap is
`Constrain`, and its target is the **observer**, not the workload.

The two sets do not intersect. Everything containable is at most
`Attested`; the one `Proven` thing is not a workload finding. And the
observer target is deliberate: freezing a workload because a sensor failed
would be the wrong response to the wrong party.

**Why this is A and not B.** Reaching option B would mean either lowering
what `Proven` means — which would make the word describe evidence it does
not describe — or adding an evidence source whose output a verifier can
independently recompute for a workload action. The current sources cannot
support that: `/proc` content and socket-table reads are attested
observations of a host's own reporting, not recomputable facts. Manufacturing
a `Proven` label over them to make a later gate reachable is exactly the
substitution this architecture exists to prevent.

**What would change the answer.** An evidence source whose record a verifier
can recompute end to end from independently anchored material — a
kernel-resident sensor with its own attestation path, or hardware-anchored
observation. When such a source exists, nothing else stands in the way:
`reachability.rs::r02` shows that a workload finding at `Proven` warrants
containment immediately. The machinery is not missing; the evidence is.

**Consequences recorded honestly.**

- `aip-containment` is real, tested and unreachable from live evidence in
  v1. Its gates, actuator and signed records are exercised against a
  fixture, and `containment.rs` says so at the top of the file.
- The fixture is `PHANTOM_CLAIM · Proven`, a pair the engine cannot
  produce. It demonstrates the gates, never the capability.
- `tests/reachability.rs` proves the unreachability over the engine's whole
  producible set under the most permissive policy an operator could write,
  and fails if the engine ever gains a `Proven` workload finding — at which
  point this section must be written again.
- Containment is gated twice regardless: by the evidence, and by two
  independent operator enablements that are both off by default.

**The claim that must not be made:** that this system can autonomously
contain a misbehaving agent today. It cannot, by design, and no
configuration changes that.
