# Containment Implementation Report

Skill 9 / Gate 9 of the completion mandate. Crate: `aip-standalone/aip-containment`.

## Status

**PASS.** Every item of the skill's §30 final gate holds, each with a test
that fails if the property is removed. One capability is deliberately not
built and is listed under Deferred: network isolation.

## Preconditions

| Skill | Report | Status |
|---|---|---|
| 3 — AIP correctness | `AIP_CORRECTNESS_REPORT.md` | PASS |
| 4 — Execution binding | `EXECUTION_BINDING_IMPLEMENTATION_REPORT.md` | PASS |
| 5 — Decision point | `DECISION_POINT_IMPLEMENTATION_REPORT.md` | PASS (library; separate-process deployment is design) |
| 6 / 6.5 — Observer | `OBSERVER_IMPLEMENTATION_REPORT.md`, `SNIFFER_DOG_IMPLEMENTATION_REPORT.md` | PASS |
| 7 — Reconciliation | `RECONCILIATION_IMPLEMENTATION_REPORT.md` | PASS |
| 8 — Warrant | `WARRANT_IMPLEMENTATION_REPORT.md` | PASS |

Gate 8 (collector continuity runtime) is also PASS, which matters here:
containment demands *current* observer health, and the health it demands
is produced by a collector whose own restart semantics are now strict.

## Current State (before this work)

Established by search, not assumption (skill §4). At `17437b8` the
production tree contained no process termination, cgroup, freeze,
firewall, nftables, XDP, drop, isolate or quarantine code. The word
"quarantine" appeared only as `ObserverState::Quarantined`, a statement
about the observer's own integrity. The only `kill` calls were child
teardown in tests and in `ghost-demo`. `CONTAINMENT_MODEL.md` recorded
`CONTAINMENT = MISSING` and said that was correct for the time.

## Threat Model

**THREAT.** An attacker may forge or alter observations; manipulate
severity; induce false positives; replay evidence; manufacture or mutate
a warrant; present a stale or expired warrant; edit containment policy on
disk; induce actuation failures; aim the response at protected
infrastructure; substitute one process for another by exiting and letting
the pid be reused; or try to use the response path itself as a
denial-of-service weapon against the fleet.

**ASSUMPTIONS.**

| Question | Answer |
|---|---|
| Who holds warrant authority? | Skill 8's `WarrantAuthority`, a separate key holder |
| Who holds containment authority? | This crate's `ContainmentAuthority`, a third key; `verify_containment_record_distinct` refuses an anchor equal to another authority's key, and `contain` refuses a warrant signed under the containment key |
| Who actuates? | The `Actuator` implementation the operator wires in. In production that is `CgroupV2Freezer`, which requires the privilege to write the cgroup hierarchy |
| Containment TCB | The host kernel's cgroup v2 freezer, the process running `contain`, its policy, its replay ledger, and the three trust anchors it is given |
| If the warrant store is compromised | An attacker with the warrant *authority key* can issue Contain warrants. The boundary cannot detect that; it is the reason warrant and containment keys are distinct and the reason every action leaves a record naming the warrant. NOT MITIGATED HERE |
| If the control plane is unavailable | Nothing is contained. There is no fallback path to actuation |
| If the target disappears before actuation | `Refusal::Attribution(ProcessNotVisible)` before the cgroup exists, or `ActuationFailure::TargetGone` after; either way nothing is frozen and nothing about the workload is concluded |
| Rollback of the replay ledger file | Re-enables exactly the warrant ids the rollback drops. Durability beyond `fsync` on one file is a deployment matter — NOT DETERMINABLE FROM CURRENT CODEBASE |

**MECHANISM.** Seventeen gates in `contain::contain`, in this order, each
with its own refusal: warrant authenticity (distinct from the containment
key) → validity window → `response == Contain` → `target == Workload` →
`strength == Proven` by explicit match → result is a workload violation →
observation was not unavailable → evidence references present → engine
issued it autonomous → warrant not flagged protected → subject bound and
equal to the target agent → no protected identity involved → mode permits
(advisory records; operator mode needs an acknowledgement naming *this*
warrant) → cited observer's health verifies, is Active and is fresh →
warrant id not consumed → target attributed live → consume, then actuate.

## Implementation

| File | Contents |
|---|---|
| `src/record.rs` | `ContainmentMode` (`Advisory` default, `OperatorEnabled`, `AutonomousEnabled`), `ContainmentAction` (`AdvisoryOnly`, `FreezeProcess`), `ContainmentPolicy`, `OperatorAcknowledgement`, `Refusal` (24 causes, each with a code), `TargetIdentity`, `ContainmentDecision`, `Outcome`, `ContainmentRecord` + canonical bytes under `SYNTRIASS/GHOST/CONTAINMENT/v1`, `ContainmentAuthority`, `ContainmentTrustAnchors`, `verify_containment_record`, `verify_containment_record_distinct` |
| `src/attribution.rs` | `attribute()` and `Attributed` (holds the pidfd), `AttributionFailure` (`ProcessNotVisible`, `InstanceMismatch`, `BootMismatch`, `ExecutableMismatch`, `SelfTarget`, `InitTarget`, `Unavailable`) |
| `src/actuator.rs` | `Actuator` trait, `Mechanism`, `Applied`, `ActuationFailure`, `CgroupV2Freezer` (`detect`, `at`, `cgroup_path_for`, `apply`, `release`) |
| `src/replay.rs` | `ReplayLedger`, `MemoryReplayLedger`, `FileReplayLedger` |
| `src/contain.rs` | `ContainmentAnchors`, `ContainmentRequest`, `Hold`, `Containment`, `contain()`, `release()` |

## Warrant Gate

`contain` accepts `&Warrant` and nothing else that could stand in for one.
There is no constructor here for a warrant, no path from a `Finding`, a
`Severity`, an `EvidenceStrength` or a boolean to an actuator, and the
`Actuator` trait takes an `Attributed` target and a closed action, so a
caller holding a pid cannot reach the kernel through this crate. The
warrant is verified with `verify_warrant_distinct` against the warrant
trust anchors, excluding the containment authority's own key, so this
crate cannot sign the permission it then consumes. Every security-relevant
warrant field is inside the signature: c03 mutates twelve of them one at a
time after signing and every mutation is refused.

## Evidence Gate

`EvidenceStrength::Proven` is required by an explicit `match` with all
four variants written out — no ordering, no comparison, no arithmetic, so
a new variant is a compile error rather than a silent pass. `Heuristic`,
`Correlated` and `Attested` are refused (c01). `CANNOT_PROVE`,
`CONTINUITY_FAILURE`, `SENSOR_INTEGRITY_FAILURE`, `VERIFIED_EXECUTION`, a
record whose observation was unavailable, and a warrant with no evidence
reference are all refused (c02) — in most of those cases twice over,
because the warrant engine already capped the response below `Contain`.

## Target Binding

The target is an `ExecutionBinding`: agent id, `(pid, start ticks, boot
id)` and the SHA-256 of the executable's contents. `attribute()` opens a
pidfd first and holds it for the life of the `Attributed` value, so the
number cannot be recycled underneath the checks, then compares start
ticks, boot id and executable contents with what the binding names. PID
reuse is `InstanceMismatch`, a different boot is `BootMismatch`, a
replaced binary is `ExecutableMismatch` (c06). The warrant's subject must
equal the target's agent id, so a warrant for agent A cannot contain agent
B, and an unbound warrant contains nobody (c05). The containment process
itself and PID 1 are refused outright.

## Operator Controls

`ContainmentPolicy::default()` is `Advisory` + `AdvisoryOnly`. Under
advisory every gate still runs and the decision is signed, but the
actuator is never called and the warrant is *not* consumed, so enabling
the mode later does not require a fresh warrant (c07). `OperatorEnabled`
requires an `OperatorAcknowledgement` whose `warrant_id` equals this
warrant's; missing or mismatched is a refusal (c08). `AutonomousEnabled`
additionally requires that the warrant engine itself issued the warrant
under autonomous policy — a warrant with `autonomous: false` never
actuates (c10). Absence of configuration is never permission.

## Protected Identities

The warrant engine's `ProtectedIdentitySet` is reused rather than
duplicated. Containment refuses when the target agent is protected, when
any decision point or observer the evidence cites is protected, or when
the warrant itself carries `protected: true` (c09). Because the engine
already caps a protected finding at `Alert`, the third case can only arise
from a forged or mutated warrant, and is refused on the flag alone.

## Replay

The uniqueness key is the warrant id. It is consumed *before* actuation,
so a failed action is not retried destructively by default and a second
attempt with the same warrant is `Refusal::Replayed` (c12, and c14 for the
failure path). `FileReplayLedger` appends the id and `fsync`s before the
decision proceeds, so consumed state survives a process restart (c13). If
the ledger cannot be written the attempt becomes `Outcome::Failed` and
nothing is actuated.

## Accountability

Every attempt — refused, advisory, applied, failed, released — produces a
`SignedContainmentRecord`. The record answers the skill's §21 questions:
the warrant id and the digest of its signing preimage, the reconciliation
digest and result, the evidence strength verbatim, the evidence
references verbatim, the target's full execution identity, the action, the
mode, the policy version, whether the warrant was autonomous, the decision
time, the validity bound, and the outcome. It is canonically encoded under
its own domain and verifiable offline; three post-signature mutations are
refused, and the record's JSON contains none of "trusted", "confidence",
"score", "malicious" or "risk" (c15).

## Tests

`aip-containment/tests/containment.rs` — 18 passed.

| Test | Property | Skill §22 |
|---|---|---|
| c01 | Heuristic, Correlated, Attested cannot contain | 1, 2, 3 |
| c02 | CANNOT_PROVE, unavailable observation, observer-targeted results, uncited warrant cannot contain | 4, 5 |
| c03 | forged, unsigned and twelve field mutations refused | 9, 18 |
| c04 | expired and not-yet-valid warrants refused | 8 |
| c05 | wrong subject and unbound subject refused | 11 |
| c06 | wrong pid, reused pid, wrong boot, wrong executable, self, init | 17 |
| c07 | advisory default; advisory never actuates and consumes nothing | 13 |
| c08 | operator acknowledgement must name this warrant | 13 |
| c09 | protected agent, protected observer, protected flag | 12 |
| c10 | non-autonomous warrant never actuates | 13 |
| c11 | health missing, stale, not Active, untrusted, not cited | 25 |
| c12 | consumed warrant is not a second authorization | 14 |
| c13 | replay ledger durable across a restart | 14 |
| c14 | actuation failure fails open, is recorded, escalates nothing | 15 |
| c15 | every attempt a signed, domain-separated, tamper-refused record | 19, 21 |
| c16 | release thaws through the same hold and is recorded | 19 |
| c17 | closed action set, no command representable | 16 |
| c18 | policy and mode vocabulary; advisory by default | 10, 24 |

Severity and confidence bypass (skill tests 6 and 7) are covered
structurally rather than by a test that constructs them: neither type is
an input to `contain`, so there is nothing to pass. The warrant engine's
own `w12` sweep covers severity across every result and strength.

`aip-containment/tests/live_freeze.rs` — 4 passed on this host (Linux
6.18, root, cgroup2 mounted at `/sys/fs/cgroup/unified`).

| Test | What actually happened |
|---|---|
| f_p | A real child writing to a pipe every 20 ms was frozen through a Proven warrant: the kernel's `cgroup.events` reported `frozen 1`, the pipe produced nothing for 300 ms, `release` thawed it, output resumed and the cgroup was removed |
| f_a | A root that is not a cgroup2 hierarchy → `Outcome::Failed`, the target kept running |
| f_b | A pre-existing cgroup holding another process → `ActuationFailure::WrongCgroup`; neither the target nor the bystander was frozen |
| f_c | A target that exits before actuation → `TargetGone` from the actuator, and `Refusal::Attribution` through the full path with nothing consumed |

Workspace validation at the GREEN commit: `aip-standalone` 785 passed / 0
failed / 3 ignored; `aip-service` 39 passed / 0 failed; clippy
`-D warnings` and `cargo fmt --check` clean in both.

## Security Properties Proven

- No input short of a signed `Contain` warrant on a `Proven` workload
  violation reaches an actuator. Suspicion, severity, confidence, silence,
  degradation and missing citations cannot.
- A warrant is bound to one execution instance, and that instance must be
  the one alive now: pid reuse produces a refusal, not a containment.
- Autonomous containment is off by default and requires two independent
  enablements (the warrant engine's policy and the containment policy).
- Protected identities are not autonomously contained.
- A consumed warrant is not a second authorization, across restarts.
- Actuation failures fail open, are recorded, and change no evidence.
- `Applied` is written only after the kernel confirmed the freeze.
- Every attempt is independently verifiable against a trust anchor
  distinct from the warrant authority's.

## Limitations

1. **Freezing is not killing, and it is not isolation.** A frozen process
   holds its file descriptors, sockets and memory. In-flight kernel work
   already queued may complete. The action stops the process from running;
   it does not undo what it did.
2. **The cgroup contains the target's later children.** Processes the
   target forks after attachment inherit the cgroup and are frozen with
   it. That is the semantics of freezing a process instance, and it is why
   the actuator requires the target to be a member rather than the only
   member.
3. **Privilege.** The freezer needs write access to the cgroup hierarchy.
   A host that denies it yields `Outcome::Failed`, never a silent success.
4. **No production path yields a `Proven` workload violation today.** The
   reconciler produces `Proven` only for `SENSOR_INTEGRITY_FAILURE`, which
   targets the observer and is refused here. So containment is reachable
   in tests and unreachable from real evidence — a property of the evidence
   layer, stated, not a defect of the gate.
5. **A compromised warrant authority key defeats the gate.** Distinct keys
   and mandatory records limit the blast radius and make it visible; they
   do not prevent it.
6. **The policy and the replay ledger are ordinary files.** Their
   integrity is a deployment matter; the crate does not sign or anchor
   them.
7. **No transport, no daemon, no scheduler.** A caller must bring the
   warrant, the binding and the health.
8. **`ghost-demo` has no containment scenario.** The live evidence is the
   test suite, not the demonstrator.

## Deferred

Network isolation as a second action (the skill's §16 allows it; nothing
in the product requires it yet, and adding an unused actuation capability
is exactly what §16 forbids). Committing containment records to the NEXORA
log. Persisting or transporting records. Warrant revocation. Key lifecycle
for the containment authority.

## Files Changed

```
aip-standalone/Cargo.toml                          workspace member
aip-standalone/aip-containment/Cargo.toml
aip-standalone/aip-containment/src/lib.rs
aip-standalone/aip-containment/src/record.rs
aip-standalone/aip-containment/src/attribution.rs
aip-standalone/aip-containment/src/actuator.rs
aip-standalone/aip-containment/src/replay.rs
aip-standalone/aip-containment/src/contain.rs
aip-standalone/aip-containment/tests/containment.rs
aip-standalone/aip-containment/tests/live_freeze.rs
docs/architecture/CONTAINMENT_IMPLEMENTATION_REPORT.md
docs/architecture/CONTAINMENT_MODEL.md
docs/architecture/GAP_MATRIX.md
docs/architecture/SNIFFER_DOG_2_0_GAP_MATRIX.md
docs/architecture/SNIFFER_DOG_2_0_IMPLEMENTATION_REPORT.md
docs/architecture/SNIFFER_DOG_PLAIN_ENGLISH.md
docs/architecture/CURRENT_SYSTEM.md
docs/architecture/WARRANT_IMPLEMENTATION_REPORT.md
```

Commits: `c06e10b` (RED), `272feac` (GREEN), and the commit carrying this
report.

## Final Gate

**PASS.**
