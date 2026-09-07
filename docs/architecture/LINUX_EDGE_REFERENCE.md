# Linux Autonomous Edge Reference (Skill 22)

**Status** REFERENCE — NOT_PRODUCTION_CAPABILITY
**Date** 2026-09-07
**Branch** `claude/codebase-production-readiness-wm6idp`
**Baseline** `607f7fd`
**Related** ADR-002 (hardware attestation, **PROPOSED** — unchanged), ADR-003
(observation class boundary, ACCEPTED — unchanged), ADR-004 (effect binding
granularity, ACCEPTED — unchanged), `OBSERVER_ATTESTATION.md`,
`AUTONOMOUS_OBSERVATION_PROFILE.md`

---

## 1. What this is, and the gap it closes

At baseline the workspace held two towers that had never met.

| | Tower A — live | Tower B — Skills 17-21 |
|---|---|---|
| subject | a real Linux process | `SystemExecution` |
| evidence | `aip-observe` mechanisms | `ObservationProfile` / `ObservationRecord` |
| custody | `CollectorSigner` → `AttestedBatch` | — |
| location | — | `PlatformBinding` |
| effect | — | `EffectAssessment` |
| verdict | `reconcile_expectation` | none, by design |

Tower A ran. Tower B did not, and could not: at `607f7fd`,
`PlatformBinding::resolve`, `EffectAssessment::assess` and `ExecutionProfile`
had **zero call sites anywhere outside their own crates**, and nothing in the
workspace depended on `aip-platform` or `aip-effect` at all. Its invariants
were proven against fixtures. Its inputs were imaginary.

This reference is the adapter, and only the adapter. It adds no model, no
engine, no identifier, no ceiling and no trust anchor.

## 2. Process topology

```
┌───────────────────────┐   pipe    ┌──────────────────────┐
│  aip-edge-workload    │◀─────────▶│                      │
│  process A · subject  │           │      aip-edge        │
│  holds an agent key   │           │  process C · verifier│
│  NO aip-observe       │           │  anchors + registry  │
└───────────┬───────────┘           │  measures nothing    │
            │ real TCP              │  signs nothing       │
            ▼                       │                      │
      the Linux kernel              └──────────┬───────────┘
            ▲                                  │ pipe
            │ procfs, pidfd, socket tables     │
┌───────────┴───────────┐   JSONL              │
│  aip-edge-observer    │─────────────────────▶│
│  process B · witness  │  AttestedBatch       │
│  holds collector key  │                      │
│  NO aip-airi          │◀─────────────────────┘
└───────────────────────┘
```

The two absences are the deliverable. They are enforced by the **dependency
graph**, not by review:

- `aip-edge-workload/Cargo.toml` does not name `aip-observe`, so no expression
  in that crate can reach `CollectorSigner`, `ObserverTrustAnchors` or
  `verify_attested_batch`. "The workload attempts to access the observer key"
  is not a runtime event that could succeed or fail; it is a compile error
  against a crate that is not linked.
- `aip-edge-observer/Cargo.toml` does not name `aip-airi` or `aip-authorize`,
  so it cannot author the subject's account of itself or decide what the
  subject was permitted to do.

`aip-edge-contract` exists so those exclusions survive: the three processes
need a shared protocol, and a shared crate that depended on everything would
restore both capabilities transitively. It depends on `aip-types` alone.

`aip-edge/tests/dependency_isolation.rs` asserts all of this over the manifests
(including `[dev-dependencies]`) and over comment-stripped source.

## 3. Threat model

### 3.1 Two compromises, kept apart

| | Application compromise | Host compromise |
|---|---|---|
| the attacker holds | the workload process and its agent key | root on the machine |
| can forge | AIRI events, self-reported bindings, transport statuses | all of the above, plus procfs content, socket tables, and the observer process's memory |
| the reference detects | yes — every claim is compared with an independent measurement | **no** |
| resulting ceiling | `Attested` | none: evidence from a root-compromised host is not evidence |

Running the collector as a second process establishes a **process** boundary.
It does not establish the **host** boundary that production requires
(`OBSERVER_ATTESTATION.md` §3 places the collector off-host). This is why every
positive finding is ceilinged at `Attested` and never `Proven`, and why the
reference says so in its own output.

### 3.2 What the workload is assumed to attempt

Each is exercised. "Where" names the layer that refuses.

| assumed behaviour | where it is refused |
|---|---|
| false self-report of success | the effect boundary: `Inconclusive`, and `CANNOT_PROVE` from the engine |
| incorrect execution claim | correlation: `ObservedProcess::matches_process_of` against the DP-signed binding |
| identifier substitution | the same check; equal pids alone never satisfy it |
| forged observation | `verify_attested_batch` — an unanchored observer yields no record |
| replayed evidence | the engine's `replay_detected`, plus `(sequence, index)` deduplication so a duplicate cannot inflate `supporting` |
| execution on the wrong process | `IDENTITY_DIVERGENCE` from the engine; zero correlated records in Tower B |
| execution in the wrong container | **not detectable.** See §6 |
| execution on the wrong platform | `PlatformDisposition::Mismatch` |
| bypassing the observer | nothing to bypass: the observer is told a pid by the verifier and measures it directly |
| terminating before observation | an attested **empty window**, then `CANNOT_PROVE / WindowNotCovered` |
| restarting after observation | a new process instance and a new execution id; no evidence carries across |
| migrating between containers | not detectable; see §6 |
| network loss | the transport is a pipe and a file; loss is a missing batch, which reduces coverage |
| observer loss | `NoObserverConsulted`, `NotEvaluated` platform, `CANNOT_PROVE` |

### 3.3 What is explicitly out of scope

Physical effect. Hardware identity. Container identity. A host-boundary
collector. Each is stated in §5, §6 and §8 with the reason.

## 4. Linux mechanisms used

The reference provisions two mechanisms. Both are polling; neither needs
`tracefs` or `perf_event_open`, so the reference runs on a bare host and in CI
without provisioning. `aip-observe` implements seven more, and the reference
declines them deliberately — see §8.

### `PidFdAnchored`

| | |
|---|---|
| **observes** | `/proc/<pid>/{stat,exe}`, bracketed by a `pidfd` the kernel bound to the process *instance* |
| **establishes** | that one instance, identified by `(pid, start ticks, boot id)` and by the SHA-256 of its executable's contents, was alive across the reads |
| **does not establish** | what the process did, or any effect it had |
| **trust source** | the kernel, for liveness and instance binding; the observed host's procfs, for content |
| **failure mode** | `InstanceEnded` if it exits mid-read — the reads are discarded, never returned as a weaker measurement; `ProcessNotVisible` if there is nothing at the pid |
| **evidence ceiling** | `Attested` (class `ProcessIdentity`). Content read from the observed host, forgeable by root there |

### `ProcNetTable`

| | |
|---|---|
| **observes** | rows of `/proc/net/{tcp,tcp6,udp,udp6}` whose inode is open in `/proc/<pid>/fd`, taken under the same pidfd anchor |
| **establishes** | that the instance held a socket to a named endpoint in a named kernel state at the moment of the sample |
| **does not establish** | that a remote system acted on anything; nothing about payload; nothing between samples |
| **trust source** | the observed host's kernel tables |
| **failure mode** | malformed rows are skipped and counted, never guessed; a connection opened and closed between samples is simply absent |
| **evidence ceiling** | `Attested` (class `NetworkSocket`) |

### The observer's declaration is the profile

The provisioned set is declared **once**, to the probe, and published as wire
codes in `observer.json`. The verifier's `ObservationProfile` is projected from
exactly that list. There is no second place that says what the deployment can
see, and an unknown mechanism code is refused rather than mapped to a
neighbour — an unknown mechanism is an unknown class, and an unknown class has
no defensible ceiling.

## 5. The actuation ladder

The reference's action is an authorized TCP connection to a specific endpoint,
held open. It is deterministic, OS-visible, and emphatically not physical.

| rung | stage | established by |
|---|---|---|
| REQUEST | `ToolInvocation` | a signed AIRI event. Self-reported |
| AUTHORIZED | `ExpectedExecution` | a decision point's signature over an execution binding |
| EXECUTION | `RuntimeExecution` | the workload's report that its call returned. Self-reported; the reference's equivalent of a 200 |
| INDEPENDENT OBSERVATION | `IndependentObservation` | correlated records from an anchored observer |
| OBSERVED ACTUATION | `ExternalEffect` | a corroborating finding **and** an `Exact` binding (ADR-004) |
| PHYSICAL EFFECT | **no stage** | nothing. See below |

The physical rung has no stage on Skill 18's twelve-rung ladder, because none
of the twelve is a physical measurement and adding one would be a claim in the
type system.

**`PhysicalEffect` = `CANNOT_PROVE`, permanently, in this build.** It is
computed rather than asserted: `ObservationClass::PhysicalEffect::is_implemented()`
is `false`, no mechanism maps to the class, and a profile declaring *every*
mechanism this build has still reports the class `NotObservable`. A file write,
a socket send, a process event or a driver return value does not become
physical-effect proof, and there is no code path here through which one could.

## 6. Five identities, and what survives what

| kind | independently established | derived from | workload restart | namespace change | host reboot |
|---|---|---|---|---|---|
| Process | yes | probe measurement of `(pid, start ticks, boot id)` under a pidfd anchor | Changes | Changes | Changes |
| Container | **no** | nothing — no mechanism measures one | NotEstablished | NotEstablished | NotEstablished |
| Platform | yes | probe measurement of `boot_id`, inside a signed batch | Survives | Survives | Changes |
| Hardware | **no** | nothing — ADR-002 is PROPOSED | NotEstablished | NotEstablished | NotEstablished |
| System | no (declared) | the deployment's declaration plus the AIRI execution id | Survives | Survives | Survives |

`NotEstablished` is a third state, not a synonym for "no". "This build cannot
tell" and "this build can tell and the answer is no" are different facts, and
summing them is how a blind spot becomes a clean bill of health.

**Container identity is deliberately not derived.** A container id is an
orchestrator's label; a namespace inode number is reused after the namespace is
freed. Neither is measured by any mechanism in `aip-observe`, and turning
either into an identity would import a self-reported name into a signed record.

The sharpest demonstration is in `tests/lifecycle.rs`: a workload in a fresh
PID namespace honestly reports pid 1, which on the host is `init`. A verifier
correlating on a self-reported pid would be measuring `init`. The reference
correlates on the instance the decision point *bound* and the observer
*measured*, and never on a reported number.

The namespace work uses `unshare(2)` via util-linux. This is a **Linux
namespace reference, not a mandatory product architecture**, and Docker is a
dependency of nothing here.

## 7. The correlation seam

`ObservationRecord::from_attested` remains the only constructor in the
workspace and this reference adds no second one. What it adds is the check
`from_attested` structurally cannot make.

An `ObservedExecution` carries no execution id, because the observer is never
told one — it measures a process instance and nothing more. So the join has to
be made somewhere, and where it is made decides whether the model means
anything. Made from the agent's self-report it means nothing: the subject would
be nominating its own evidence.

```
   a decision point signed an ExpectedExecution
   containing an ExecutionBinding                   ← authorization side
                       │
                       │  ObservedProcess::matches_process_of
                       │  (pid, start ticks, boot id, exe content digest)
                       ▼
   an anchored observer measured a process instance ← observation side
```

Two independently signed statements about the same process instance. The
execution id follows from the authorization side, where it was signed; the
observation side never has to be trusted to name it.

A record failing the comparison is **excluded, never downgraded**. Downgrading
would let anyone raise the count of "related" observations by supplying
unrelated ones.

## 8. Transport

**REFERENCE TRANSPORT ≠ PRODUCTION TRANSPORT.**

A one-line request/reply protocol over pipes, plus JSON Lines in a state
directory. Chosen for three properties a demonstration needs and a deployment
does not care about: synchronous replies (so the driver can place kernel
activity exactly between two batch boundaries, and the reference contains no
sleep and no retry), ordered append-only files, and no daemon or network.

Nothing in `aip-observe`, `aip-observation`, `aip-platform` or `aip-effect`
knows these bytes exist. The security property of an `AttestedBatch` is the
collector's signature over its canonical preimage, and that survives any
carrier. **No new network protocol is introduced by Skill 22.**

## 9. Known integration gaps

These are real and are recorded rather than worked around.

1. **Kernel-pushed evidence is unreachable to Skill 20.**
   `ObservationRecord::from_attested` indexes `batch.batch.observations` only.
   Every kernel-pushed mechanism — `Fanotify`, `SchedTracepoint`,
   `SockStateTracepoint`, `SockSendTracepoint`, `WireTapAfPacket`,
   `ProcConnector` — lands in `batch.batch.kernel_events`, which
   `from_attested` cannot address. In practice an `ObservationRecord` can carry
   only `ProcessIdentity` and `NetworkSocket`. Reaching the rest needs a
   constructor over `KernelLifecycleEvent`, which is an `aip-observation`
   change and outside Skill 22's scope. The reference therefore uses a class
   that *is* reachable, and does not pretend the others are.

2. **`NotObservedReason::NoneCorrelated` is unreachable from an honest
   adapter.** A record that does not correlate cannot be built at all, so
   `assess` is handed an empty slice both when nobody looked and when someone
   looked at another execution, and correctly answers `NoObserverConsulted` in
   both. Rather than manufacture a finding, the reference reports
   `observations_offered` beside `records.len()`: zero offered is "nobody
   looked"; non-zero offered with zero correlated is "someone looked at
   something that is not this execution".

3. **`ObservedStance::Opposes` is not derived from live evidence.** This
   reference has no observation that contradicts "a connection to X was held":
   a socket to Y does not contradict it, and the absence of a socket to X in
   one sample is a statement about sampling. So the live path reaches
   `Corroborated` and `Inconclusive` and cannot reach `Contradicted` or
   `Conflicting`. Both are exercised in tests over **real** attested records
   with the stance supplied explicitly — which is the caller's documented job —
   and the reference does not claim to have observed a contradiction.

4. **The collector is on the observed host.** A process boundary, not a host
   boundary. Production places it off-host; this reference does not, and every
   ceiling reflects that.

## 10. What was not changed

`aip-reconcile` and `aip-nexora` required **no code change**. The reference
drives `reconcile_expectation` and commits to a `CommitmentLog` using leaf
kinds that already existed; `LeafKind::ALL` still stands at nine.

The `EdgeReference` report has canonical bytes and a digest, and is
deliberately **not** committed to NEXORA: doing so would require a tenth leaf
kind for a projection of artifacts that are already committed individually. A
verifier holding the batches, the health record, the expectation and the
reconciliation can recompute everything the report says.

ADR-002 stays PROPOSED. ADR-003 and ADR-004 are unchanged. `EvidenceStrength`
is untouched, and `aip-edge` names neither `ReconciliationResult` nor
`EvidenceStrength` anywhere in its code — asserted over its own source, with
comments stripped, in `tests/no_second_engine.rs`.
