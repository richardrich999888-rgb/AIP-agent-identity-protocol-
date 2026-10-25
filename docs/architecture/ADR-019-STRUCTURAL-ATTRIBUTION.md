# ADR-019 — Structural Attribution: Bind Execution to a Decision by Kernel Placement, Not by Racing It

**Status** ACCEPTED (design) — implementation not started; milestones M2–M4 of
`docs/loops/LOOP_ATTRIBUTION.md`
**Date** 2026-10-25
**Branch** `claude/skill-25-implementation-xbz0t3` · **Baseline** `9ae741f`
**Governing skills** `ghost-architecture-orchestrator`,
`execution-binding-engineer`, `aip-protocol-change-guard`
**Related** XI-H2 (`docs/security/ADVERSARIAL_RESULTS.md`), B11
(`docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`), ADR-002 (hardware attestation,
PROPOSED/STOPPED), `aip-observe/src/{perf,sched,fanotify}.rs`

---

## 1. Context — the measured failure

On the sealed Phase-1 run, **84 of 105 `execve` events could not be bound to
a measured process instance** (XI-H2). The workload was a shell spawning
short-lived children. The mechanism is a race: an exec is observed from the
`sched:sched_process_exec` tracepoint, then the probe opens a pidfd and reads
`/proc/<pid>/exe`; a child that exits first is gone before the pidfd exists.
The system reported those execs as unmeasured — `CANNOT_PROVE`, correctly —
so nothing was falsely attributed. But a control that binds a fifth of execs
on one workload shape is one whose coverage nobody can rely on.

Two separate things are lost in that race, and they need different fixes:

| lost | what it answers | fix in this ADR |
|---|---|---|
| **attribution** | which authorised decision does this exec belong to? | kernel placement: the exec happens inside a cgroup created for that decision; the cgroup id travels **in the event** (§3, §4) |
| **measurement** | what binary content did it execute? | hold the exec at open-for-exec until the probe has hashed the file (§5) |

Neither fix wins the race. Both remove it.

## 2. Environment facts this design rests on (measured, this host)

| fact | evidence |
|---|---|
| kernel `6.18.44` | `uname -r` |
| cgroup v2 hierarchy mounted (hybrid: `/sys/fs/cgroup/unified`); `mkdir`, task move into it and `rmdir` all work as root | probed: `0::/aip-probe` after writing `cgroup.procs` |
| `CONFIG_CGROUP_PERF=y`, `CONFIG_PERF_EVENTS=y`, `CONFIG_TRACEPOINTS=y` | `/proc/config.gz` |
| tracepoints `cgroup:cgroup_mkdir`, `cgroup:cgroup_rmdir`, `cgroup:cgroup_attach_task`, `sched:sched_process_exec` (id 365) present | tracefs (mounted by hand this session; not mounted by default here) |
| `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` | `/proc/config.gz` |
| `CONFIG_IMA` **not set** | `/proc/config.gz` — IMA is not available as the alternative on this host |
| effective capabilities include `CAP_SYS_ADMIN` | `/proc/self/status` |
| root filesystem reports a zero fsid (`FAN_REPORT_FID` refused) | `aip-observe/src/fanotify.rs` module docs |

A deployment that lacks any of these lacks the property that depends on it,
and must say so (§9); nothing below is simulated where the kernel refuses.

## 3. Decision 1 — one cgroup v2 per authorised decision, created by a placement supervisor

DECISION:
cgroup v2 is a **hard requirement** for structural attribution. Each
authorised decision that runs work on the host runs it in its **own cgroup**,
`<placement-root>/<decision_id as 32 lowercase hex>`, created for that
decision and never reused. The work is started **into** the cgroup with
`clone3(CLONE_INTO_CGROUP)` (Linux ≥ 5.7), so the first instruction of the
first process already runs inside it and every descendant inherits it at
fork.

THREAT:
An exec by a short-lived child cannot be attributed to the decision that
caused it (XI-H2). Secondarily: a process outside the decision borrowing its
attribution.

MECHANISM — who creates the cgroup:
**Not the decision point.** The decision point is a signing authority that
may be remote and must stay outside the host's trust domain (I1, I19); it
cannot and should not `mkdir` on the host. A host-local **placement
supervisor** does it, and only on a **verified** `ExpectedExecution`
(`verify_expected_execution` under the supervisor's own decision-point
anchors). The supervisor:

- runs outside the agent's authority boundary (a different uid, or root with
  the agent unprivileged);
- owns `<placement-root>`; the agent has **no write access** to it or to any
  decision cgroup's `cgroup.procs` (no delegation to the agent);
- creates exactly one cgroup per `decision_id`, and refuses a second;
- removes the cgroup after `valid_until` once it is empty, and never
  recreates it.

The supervisor holds **no key** and signs nothing. Its authority is
established by the kernel, not by a credential: the observer records which
process instance created each decision cgroup (§4), and the reconciler
accepts a placement only if that creator is a measured instance of the
supervisor binary the **verifier** names (a context anchor, never a value in
the evidence).

ASSUMPTION:
The agent cannot obtain the supervisor's privileges. A root-compromised host
defeats this, as it defeats everything below the hardware line (§8).

LIMITATION — the one that matters most:
Attribution is **per process**. Work the agent does **in its own long-lived
process** — an in-process HTTP call, a library call — happens in the agent's
own cgroup and cannot be split between concurrent decisions by this
mechanism. Structural attribution covers decisions whose work runs in
processes the supervisor starts. In-process tool calls remain the gateway
receipt's job (`aip-airi`), not this ADR's.

## 4. Decision 2 — attribution travels in the event: `PERF_SAMPLE_CGROUP`, no eBPF

DECISION:
Add `PERF_SAMPLE_CGROUP` (bit 21) to the `sample_type` the existing perf
tracepoint sampler already uses (`aip-observe/src/perf.rs`, today
`TID | TIME | CPU | RAW`). The kernel writes the cgroup v2 id of the task in
whose context the event fired **into the sample itself**. No eBPF program is
loaded.

Sample, with the cgroup id, three tracepoint families:

| tracepoint | why |
|---|---|
| `sched:sched_process_fork`, `sched:sched_process_exec` | the events being attributed; already sampled |
| `cgroup:cgroup_mkdir`, `cgroup:cgroup_rmdir` | the decision cgroup's birth and death, its kernel id, level and path; the sample's TID is the **creating task** |
| `cgroup:cgroup_attach_task` | every migration (§6) |

MECHANISM — why this removes the race:
The cgroup id is captured by the kernel at the instant of the event, in the
task's own context. A child that exits 1 µs later has already left a sample
naming its cgroup. Attribution no longer requires the process to be alive
when the probe looks.

IDENTITY (I2, I4):
The binding key is **`(boot_id, cgroup_id)`**, never the cgroup's name or
path. A name is a label someone chose; the id is the kernel's. The path in
`cgroup_mkdir` is used only to recover the `decision_id` the supervisor
encoded in it, and is accepted only for a cgroup whose creator passed §3's
check. The kernfs-backed cgroup id is assumed **not reused within a boot**
(64-bit id space); M2 carries a test that churns cgroups and asserts no
repetition, and the assumption is cited to kernel source in the
implementation, not left implicit. Across boots, `boot_id` separates.

## 5. Decision 3 — measure the executed content while the exec is held: fanotify `FAN_OPEN_EXEC_PERM`

DECISION:
The probe adds a fanotify group of class `FAN_CLASS_CONTENT` with a
`FAN_OPEN_EXEC_PERM` mark (mount mark; a filesystem mark is not assumed on a
zero-fsid root). When a file is opened for execution the kernel **blocks the
exec** and hands the probe an open descriptor to the exact file being
executed plus the task's pid. While the task is blocked:

1. the probe reads the task's cgroup (race-free: the task cannot exit while
   it waits on the permission answer);
2. if the cgroup is not a decision cgroup, it answers `FAN_ALLOW` at once —
   no hashing, no added latency beyond the round trip;
3. if it is, it hashes the content **through the descriptor the kernel
   gave it** — the opened inode, not a path — and only then answers
   `FAN_ALLOW`.

The measurement is recorded with a new `SourceMechanism::ExecPermission`,
distinct from `PidFdAnchored` and from `ProcfsPoll`, so a reader can always
tell how a hash was taken.

The probe **never answers `FAN_DENY`.** It measures; it does not decide.
Refusing executions is enforcement, it belongs to the decision point and the
gateway (I19, ADR-015), and an observer that can deny is an observer whose
bugs are an outage.

LATENCY:
Every exec on the marked mount pays one user-space round trip; every exec in
a decision cgroup also pays one full-file SHA-256. Bounded by a named
configuration constant (`EXEC_MEASUREMENT_DEADLINE`, value set in M3 from
measurement, not chosen here). Past the deadline the probe answers
`FAN_ALLOW` and records the exec as **unmeasured**. Published in M7.

FAILURE MODE — stated explicitly:
**Execution fails open; evidence fails closed.** If the probe dies, the
kernel resolves its pending permission events as allowed when the group's
descriptor is released, and later execs are no longer held. Execs therefore
continue; what stops is the evidence. The gap shows as a break in the
probe's sequence and health stream, and every exec in the gap is
`CANNOT_PROVE`. The alternative — fail closed, blocking every exec on the
host when one process dies — would make the measurer a host-wide
availability kill switch, which the containment model forbids (failure must
not become an availability attack).

TOCTOU:
Hashing via the kernel's descriptor removes path substitution. Whether the
*content* of that inode can still change between the hash and the mapping —
writes to a file open for exec — is a kernel property M3 tests directly
(adversary: replace or rewrite the binary between open and exec) rather than
assumes. Until that test exists the hash is recorded as "content of the
inode opened for exec, at hold time", and no stronger.

ALTERNATIVE — IMA:
Load-time measurement by the kernel is stronger (no user-space round trip,
no hold). **Not available on this host** (`CONFIG_IMA` unset), so it is not
the M3 implementation; a deployment with IMA should prefer IMA's measurement
list as the source and record it as a distinct mechanism.

## 6. Decision 4 — migration detection, and what it produces

DECISION:
Every `cgroup:cgroup_attach_task` sample is recorded with the moved pid, the
destination cgroup (id, level, path) and the **writer** (the sample's TID —
the task that wrote `cgroup.procs`). Initial placement by
`CLONE_INTO_CGROUP` goes through the fork path, not the migration path, and
so is expected to produce **no** attach event — an expectation from kernel
source that M2 must confirm on this kernel by test before §6 relies on it.
If it holds, any attach that touches a decision cgroup is anomalous.

| event | precondition | result |
|---|---|---|
| a task **leaves** a decision cgroup for one outside its subtree | attach observed; observer coverage attested over the window | **`IDENTITY_DIVERGENCE`**, at `Attested` — the authorised instance moved out of the placement its authorisation ran in |
| a task **enters** a decision cgroup by attach (not by fork inheritance) | as above | the task is **never** attributed to that decision, and the attach is reported as `IDENTITY_DIVERGENCE`. This is the false-attribution direction — a process borrowing a decision's authority — and it is refused, not resolved |
| either, with an observer coverage gap over the window | — | `CANNOT_PROVE` for attribution in that window; the gap is named |

Signed how: the attach events are kernel-lifecycle events inside an
`AttestedBatch` — signed by the remote collector under its existing key, as
every observation already is. No new signing authority. The verdict is the
reconciler's, as every verdict already is.

Never `Proven`: this is kernel-pushed event content read on the host, the
same class as every other probe observation (I12; ADR-018 does not change
it).

## 7. Decision 5 — edges

| edge | decision |
|---|---|
| **nested cgroups / containers** inside a decision cgroup | descendants are attributed to the decision by **ancestry recorded from `cgroup_mkdir` events** observed after the decision cgroup's own creation. A descendant whose creation was not observed (coverage gap) is not attributed |
| **the agent already inside an orchestrator's cgroup** (Kubernetes pod, systemd unit) | the supervisor needs a delegated subtree (`Delegate=yes`, or the runtime's equivalent) under which `<placement-root>` lives. Packaging is M8/K8s work; without delegation the property is not established and the deployment says so |
| **cgroup reuse after expiry** | names never reused (`decision_id` is 128-bit random and the supervisor refuses a second creation); ids not reused within a boot (§4); `cgroup_rmdir` recorded |
| **work still running after `valid_until`** | its events fall outside the expectation's window: no `VERIFIED_EXECUTION`; with attested coverage, an effect after expiry is evidence of execution without live authority. The supervisor does **not** kill it — that is containment, gated on `Proven` (M5) |
| **boot id** | part of the key; a reboot ends every placement |
| **clock** | unchanged: kernel timestamps are `CLOCK_MONOTONIC` and reach the wall clock only through the batch's attested clock anchor (protocol 12) |
| **two cgroups claiming one `decision_id`** | the supervisor refuses it; if observed anyway, attribution for that decision is ambiguous → `CANNOT_PROVE`, never "pick one" |

## 8. Threats

### Closed (each needs the M2/M3 test named)

| threat | closed by | test (milestone) |
|---|---|---|
| short-lived child exits before measurement — exec unattributed (XI-H2) | in-event cgroup id | child exiting within 1 ms is bound (M2) |
| PID reuse transfers a decision to an unrelated process | binding is `(boot_id, cgroup_id)` + process instance, never pid | reused pid in another cgroup is not bound (M2) |
| same binary run outside the decision borrows its attribution | attribution by placement, not by binary | decoy with identical binary, outside the cgroup, not bound (M2) |
| process migrates **out** to shed attribution | `cgroup_attach_task` | escape → `IDENTITY_DIVERGENCE` (M3) |
| process migrates **in** to borrow authority | attach-entered tasks never attributed | join → not bound + divergence (M3) |
| exec path swapped for different content | hash through the kernel's exec descriptor | replace between open and exec lands in its documented class (M3) |
| measurer killed to blind the system | fail open for exec, closed for evidence; sequence/health gap | supervisor/probe killed mid-run → `CANNOT_PROVE`, never a verdict (M3) |
| permission-event backlog | deadline → allow + unmeasured | queue pressure → unmeasured, counted (M3) |
| a non-supervisor process creates a cgroup named for a real decision | creator must be a measured supervisor instance named by the verifier | forged placement → not attributed (M2) |

### Not closed

| threat | why | stays |
|---|---|---|
| **root on the observed host** | can write `cgroup.procs`, kill or ptrace the supervisor and probe, forge events before the ring. Below the hardware line; ADR-002 remains PROPOSED/STOPPED | out of scope; the collector's continuity and cross-sensor divergence detect some of it, not all |
| **in-process work of a multi-decision agent** | one process, one cgroup | gateway receipts; otherwise `CANNOT_PROVE` per decision |
| **what an interpreter ran** | `python script.py` opens the script for read, not exec: the interpreter is measured, the script is not | `CANNOT_PROVE` for script content (a later `FAN_OPEN_PERM` mark on declared script paths is a possible extension, not decided here) |
| **arguments, environment, payloads** | not in any of these events | `CANNOT_PROVE` |
| **effects off the host** | N-2 | `CANNOT_PROVE` |
| **a cgroup v1-only host** | no v2 id | property **not established**, reported |
| **a host without `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`** | no hold | measurement falls back to the pidfd race; reported per exec |

## 9. What remains `CANNOT_PROVE` after the change

Every exec whose cgroup sample is missing; every exec in a probe coverage
gap; every exec past the measurement deadline (attributed but unmeasured —
two separate facts, reported separately); everything in §8 "not closed".
The XI-H2 metric is reported as **two** ratios from M4 on — *attributed* and
*measured* — because collapsing them would let a high attribution figure
stand in for a measurement figure it is not.

## 10. Wire and protocol consequences (`aip-protocol-change-guard`)

One consolidated observe-protocol bump, **12 → 13**, carrying all of:

| change | signed by | read by |
|---|---|---|
| `KernelLifecycleEvent.cgroup: CgroupSample` — `NotSampled` \| `Sampled { cgroup_id: u64 }`; `NotSampled` for connector-sourced events and never defaulted to a value | collector, inside `AttestedBatch` (existing domain `KERNEL_EVENT/v1` content; batch version 13) | reconciler attribution |
| `KernelLifecycleKind::{CgroupCreated, CgroupRemoved, CgroupAttach}` with ids, level, path and the writer/creator task | as above | reconciler placement + migration checks |
| `SourceMechanism::ExecPermission` | as above | every reader of a measurement |

Encoding uses the existing length-prefixed helpers (`aip_types::canonical`);
each new enum variant gets its own code byte; `Option`-shaped fields carry
presence tags.

**Old evidence stays verifiable.** Sealed v12 archives exist and are read by
tests (`validation/external/corroborate/results/sealed/`,
`validation/external/spiffe/results/sealed-joint/`, consumed by
`aip-sentinel-feed/tests/sentinel_feed.rs`). The current policy — "earlier
versions are refused" — was harmless while no earlier version had been
sealed; it is not harmless now. v13 therefore **keeps a v12 verification
path**: a v12 batch verifies under v12 encoding, and every v12 event reads as
`cgroup: NotSampled`. Refusing sealed evidence because the format moved on
would destroy the property evidence exists to have.

**Unchanged:** `ExpectedExecution`, `ExecutionBinding`, the decision point's
preimage, `ReconciliationResult` (migration reuses `IDENTITY_DIVERGENCE`;
new `ReasonCode`s name the cases). No verifier reads a field its signer does
not cover: the cgroup id is inside the collector-signed batch.

`docs/architecture/AIRI_LIMITATIONS.md` is **not edited by this ADR**. If M4
moves a recorded limitation, that commit says so.

## 11. Alternatives rejected

**eBPF (`bpf_get_current_cgroup_id` in a program on the same tracepoints).**
Gives the same id. Rejected for this step: `PERF_SAMPLE_CGROUP` gives it
without loading code into the kernel, which keeps the "no eBPF" deployment
claim true and the probe's attack surface unchanged.

**Earlier pidfd acquisition (the roadmap item B11 names).** Narrows the race;
does not remove it. A child can still exit before any user-space reaction.

**The decision point creates the cgroup.** Rejected (§3): it would put a
host-mutating capability in the signing authority and the signing authority
on the host.

**Attribute by binary hash or by process name.** Rejected: identical
binaries run under different decisions, and a name is a label (I2).

**Deny unmeasured execs.** Rejected (§5): observation must not enforce, and a
measurer that blocks on failure is an availability attack.

## 12. Gate (M1)

This record lists every threat it closes (§8, each with its test) and every
one it does not (§8, §9). It is committed before any implementation. M2 may
begin: cgroup-per-decision placement and `PERF_SAMPLE_CGROUP`, tests first.
