# SNIFFER DOG — COMPLETE IMPLEMENTATION REPORT

**Scope.** The eleven-gate completion mandate, executed against this
repository on branch `claude/codebase-production-readiness-wm6idp`.
Every statement below is backed by code in `HEAD`, by a named test, or by a
measurement taken on the host that ran the tests. Where something is not
implemented, this report says so in the same voice as where something is.

**Method.** Each gate ran RED → IMPLEMENT → ADVERSARIAL → LIVE → DOC →
COMMIT, with `cargo test --workspace`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings` and `cargo fmt --all --
--check` after every gate. Gates 10 and 11 are evaluations rather than
implementations and say so.

**Final status: `VALIDATED RUNTIME`** — scoped in §14.

---

## 1. Original specification capability

The Sniffer Dog 2.0 specification names thirteen capabilities (SD-01 to
SD-13). This is where each one stands now, replacing the status column of
`SNIFFER_DOG_2_0_SPECIFICATION.md` §4.

| # | Capability | Status now | Where |
|---|---|---|---|
| SD-01 | Agent identity | **PRODUCTION** for derivation and validation; issuer and lifecycle **MISSING** | `aip-crypto`, `aip-core` |
| SD-02 | Agent profile | **PARTIAL** — the data model and its dimension separation exist; no API | `aip-agent::profile` |
| SD-03 | Execution identity | **PRODUCTION** — `(pid, start ticks, boot id)` plus executable contents, signed into the expectation and measured independently | `aip-types`, `aip-core::execution_binding`, `aip-observe::probe` |
| SD-04 | Lineage | **PRODUCTION** for the graph and for `LINEAGE_VIOLATION` on two-sided kernel evidence; agent-creation authority **MISSING** | `aip-agent::lineage`, `aip-reconcile::reconcile_lineage` (Gate 1) |
| SD-05 | Passport / authority | **PRODUCTION** in `aip-core`; the duplicate in `aip-service` remains (P1) | `aip-core::capability`, `::delegation` |
| SD-06 | Delegation graph | **PRODUCTION** — derived over verified token chains | `aip-agent::graph` |
| SD-07 | Observation | **PRODUCTION** for five kernel-mediated sources and two polled ones; coverage, loss and continuity explicit | `aip-observe` (Gates 2–4, 8) |
| SD-08 | Action evidence | **PRODUCTION** for four action classes: connect, exec, send, file write | `aip-authorize::actions`, `aip-reconcile::action` (Gates 2–4) |
| SD-09 | Reconciliation | **PRODUCTION** for the result classes and their preconditions; records are **not signed** | `aip-reconcile` |
| SD-10 | Ledger | **PARTIAL** — a commitment log exists and accepts records; nothing feeds it automatically and nothing persists it | `aip-nexora::commitment` (Gate 7) |
| SD-11 | History / commitment | **PRODUCTION** as a layer — RFC 6962 tree, signed chained heads, inclusion and consistency proofs, offline verifier, anchoring interface | `aip-nexora` (Gates 6–7) |
| SD-12 | Evidence graph | **PARTIAL** — every record carries `EvidenceRef`s; there is no index or query surface | `aip-reconcile::EvidenceRef` |
| SD-13 | API | **MISSING** — `aip-service` still runs the pre-Ghost model | `aip-service` |

Two capabilities the specification did not name are now implemented and
belong in this list: the **warrant engine** (`aip-warrant`, Skill 8) and
the **containment boundary** (`aip-containment`, Skill 9 / Gate 9).

## 2. Implementation status

| Gate | Subject | Status | Commits |
|---|---|---|---|
| 1 | `LINEAGE_VIOLATION` reachable through `reconcile_lineage` | **PASS** | `8c263fe`, `6dcec84`, `a153d75` |
| 2 | Wire observation: `AF_PACKET` device-layer tap, `WireCorroboration`, protocol v6 | **PASS** | `36b026c`, `57849bd`, `275c4e3`, `66f9679` |
| 3 | Action-level network evidence: `ghost.net.send.v1` from `sock:sock_send_length` | **PASS** | `c830a8d`, `4e4bd6a`, `8484ef2` |
| 4 | Filesystem observation: `ghost.fs.write.v1` from fanotify with kernel-bound pidfds | **PASS** | `4a5f716`, `2f1ba9b`, `b495177`, `bfbf34d` |
| 5 | Application / database / proxy sensors | **DECIDED, FENCED** — such records are writer statements, admissible only as a labelled supporting tier that can never move a verdict; no tier built | `6c51007`, `b412075` |
| 6 | Merkle commitment layer | **PASS** | `e8e42db`, `c9f21cc`, `f767e3e` |
| 7 | NEXORA proof layer: signed heads, proof objects, offline verifier, anchoring interface | **PASS** | `b6868de`, `e405d96`, `311431b` |
| 8 | Strict continuity runtime: amnesia, rollback, fork, truncation, with process restarts | **PASS** | `48b53b0`, `8a4b759`, `17437b8` |
| 9 | Containment boundary | **PASS** | `c06e10b`, `272feac`, `95b4cdb` |
| 10 | XDP | **EVALUATED, NOT ADOPTED** | `e662bf1` |
| 11 | Hardware validation | **NOT PERFORMED** — no hardware | `e662bf1` |

No gate was skipped and none was entered before its predecessor passed.

## 3. Exact implementation files

**Observation — `aip-standalone/aip-observe/src/`**

```
observed.rs    the signed event vocabulary: SourceMechanism (9 codes),
               KernelLifecycleKind, ObservationBatch, BootClockAnchor,
               OBSERVE_PROTOCOL_VERSION = 8
probe.rs       ProcfsProbe — holds no key; pidfd-anchored measurement,
               per-instance image cache, ingest of every kernel source
linux.rs       PidFd, ProcConnector, procfs and /proc/net parsers
perf.rs        perf ring reader (64 data pages), tracepoint format parsing
sockstate.rs   sock:inet_sock_set_state, boot clock anchor
sched.rs       sched_process_fork / sched_process_exec
socksend.rs    sock:sock_send_length            (Gate 3)
wiretap.rs     AF_PACKET tap, SO_TIMESTAMPNS, PACKET_STATISTICS  (Gate 2)
fanotify.rs    FAN_REPORT_PIDFD mount watch     (Gate 4)
attest.rs      CollectorSigner — holds the key; chain, probe registry,
               resume/snapshot, verify_continuity
continuity.rs  ObserverLedger, ContinuityBreak, Admission
health.rs      ObserverState, coverage, availability, SignedSensorHealth
store.rs       CollectorStore — durable snapshot, health archive, reports (Gate 8)
runtime.rs     CollectorRuntime, ContinuityPolicy, SignedContinuityReport (Gate 8)
```

**Authority and expectation** — `aip-core/src/{capability,delegation,execution_binding}.rs`,
`aip-authorize/src/{decision,actions}.rs` (four action classes, `PARAM_PATH`,
`net_send_action`, `fs_write_action`).

**Reconciliation** — `aip-reconcile/src/{result,reconcile,action,lineage}.rs`
(`RECONCILIATION_VERSION = 5`, `WireCorroboration`, `LineageComparison`,
`TransitionEvidence::{Socket, Exec, Send, File}`, `ActionOutcome`).

**Agent record** — `aip-agent/src/{profile,lineage,graph}.rs`.

**Warrant** — `aip-warrant/src/{policy,warrant}.rs`.

**Containment** — `aip-containment/src/{record,attribution,actuator,replay,contain}.rs`.

**Commitment** — `aip-nexora/src/{merkle,commitment}.rs`.

**Demonstrator (`NOT_PRODUCTION_CAPABILITY`)** — `ghost-demo/src/lib.rs`
and `src/bin/{ghost-demo,ghost-demo-agent,ghost-demo-collector}.rs`.

## 4. Tests

`aip-standalone`: **787 passed, 0 failed, 3 ignored**. `aip-service`: **39
passed, 0 failed**. `clippy -D warnings` and `cargo fmt --check` clean in
both workspaces.

| Crate | Target | Passed |
|---|---|---:|
| `aip-observe` | lib, `adversarial`, `blind_spots`, `sniffer_dog`, `pr3_coverage`, `restart_continuity` | 40, 26, 9, 22, 6, 8 |
| `aip-observe` | `wiretap` (Gate 2), `socksend` (3), `fanotify` (4), `gate5_no_log_sensor` (5), `continuity_runtime` (8), `gate10_xdp_evaluation` (10) | 10, 7, 7, 3, 10, 2 |
| `aip-reconcile` | lib, `adversarial`, `transition_evidence`, `action_evidence`, `exec_evidence`, `corrective` | 9, 30, 22, 19, 16, 9 |
| `aip-reconcile` | `lineage_edges`, `lineage_violation` (Gate 1), `wire_corroboration` (2), `send_evidence` (3), `file_evidence` (4) | 7, 16, 15, 13, 15 |
| `aip-nexora` | lib, `merkle` (Gate 6), `nexora` (Gate 7) | 2, 16, 15 |
| `aip-warrant` | `warrant`, `gate5_ceiling` | 19, 1 |
| `aip-containment` | `containment` (Gate 9) | 18 |
| `aip-authorize` | lib, `adversarial` | 7, 32 |
| `aip-agent` | `profile`, `graph`, `lineage`, `characterization` | 16, 11, 9, 3 |
| `aip-core` / `aip-crypto` / `aip-protocol` / `aip-types` | lib and packet suites | 141, 9, 46, 5 |
| `aip-real-tests` / `aip-test` | end-to-end | 67 (2 ignored), 16 |

The three ignored tests are pre-existing: one packet-bundle fixture and
two long-running end-to-end cases.

## 5. Live tests

Every "live" test below ran against the real kernel on the host described
in §9 — real processes, real sockets, real files, real cgroups. None of
them simulates kernel evidence.

| Suite | Passed | What actually happened |
|---|---:|---|
| `ghost-demo/tests/live.rs` | 8 | A controlled agent process connects; the probe reads the real socket table through a pidfd; the reconciler is run over the result, including the negative scenarios |
| `live_transition.rs` | 5 | `inet_sock_set_state` transitions read from a perf ring place a real connection in time against the anchored kernel clock |
| `live_exec.rs` | 8 | `sched_process_fork` / `sched_process_exec` observed for a real spawn, both ends bound |
| `live_wire.rs` | 2 | The `AF_PACKET` tap copied the headers of a real TCP handshake and corroborated the socket-layer transition (Gate 2) |
| `live_send.rs` | 2 | A real `send()` observed through `sock:sock_send_length`; the endpoint digest matches, the byte count is signed context, no payload is hashed (Gate 3) |
| `live_file.rs` | 3 | A real file write observed through fanotify, the writer identified through the kernel's own pidfd (Gate 4) |
| `live_collector_restart.rs` | 1 | The `ghost-demo-collector` **process** ran, exited, ran again over the same directory and continued one chain (sequence 2 → 4); an operator restored the old state file and the strict policy refused to sign (exit 3) leaving one signed report; advisory then resumed from the archived head to sequence 6 (Gate 8) |
| `aip-containment/tests/live_freeze.rs` | 4 | A real child process writing to a pipe was **frozen** through cgroup v2 behind a Proven warrant: the kernel reported `frozen 1`, the pipe went silent for 300 ms, release thawed it, output resumed, the cgroup was removed. A non-cgroup2 root, a pre-populated cgroup and a vanished target all failed open with nothing frozen (Gate 9) |
| `aip-observe/tests/gate10_xdp_evaluation.rs` | 2 | The kernel verifier accepted a 27-instruction XDP parser, executed it 1 000 times through `BPF_PROG_TEST_RUN`, counted only the TCP SYN, and refused the same program with its bounds check removed. Nothing was attached to any interface (Gate 10) |

**Demonstrator limitation.** The live scenarios run on whatever host
executes the tests. This host runs unrelated processes that stream TCP
continuously and fork often, and every host-wide source sees them. Sources
are opened per scenario, the perf rings and tap queue were enlarged, and
the live scenarios are serialised. One residual flake was observed once in
a full-workspace run at Gate 7 and not reproduced in four reruns; it
surfaced as `ObserverDegraded`, which is the observer's loss accounting
working, not a wrong verdict.

## 6. Trust root

Five distinct key holders. No two may be the same key, and each boundary
is enforced by a verifier, not by convention.

| Authority | Signs | Verifier | Refuses |
|---|---|---|---|
| Issuer / delegator (AIP) | `ScopedToken`, `DelegationToken` — expiry inside the signature | `aip-core::verify_delegation_chain` | mutated expiry, scope, grantee, depth |
| Decision point | `ExpectedExecution` — what was authorised, bound to an execution identity | `aip-authorize` | agent-signed expectations |
| Observer / collector | `AttestedBatch`, `SignedSensorHealth`, `SignedContinuityReport` — what was seen, at what chain position | `aip-observe::verify_*` (+ `verify_attested_batch_independent_of_agent`) | an anchor equal to the agent's key |
| Warrant authority | `Warrant` — what response the evidence permits | `aip-warrant::verify_warrant_distinct` | an anchor equal to another authority's key |
| Containment authority | `ContainmentRecord` — what was attempted and what happened | `aip-containment::verify_containment_record_distinct` | an anchor equal to another authority's key; a warrant signed under its own key |

NEXORA holds a sixth key for `SignedHead`, and commits records without
being able to authorise, observe or reconcile anything.

Every positive verdict names the trust root it rests on through its
`EvidenceRef`s (invariant 19). The probe on the observed host holds **no
key at all**: `ProcfsProbe` has no key field and no signing method, and
`ObservationBatch` has no signature field.

## 7. Security assumptions

Stated as assumptions, because that is what they are.

1. **The collector runs off the observed host.** The code makes this
   possible — the probe holds no key — but nothing in the repository
   enforces it. In the demonstrator both run in one process, and
   `ghost-demo-collector` writes its key in plaintext beside its state and
   is labelled `NOT_PRODUCTION_CAPABILITY`.
2. **The probe → collector transport is authenticated.** Not built. Under
   `ProbePolicy::RegisteredOnly` the collector refuses unregistered probes
   and unprovisioned mechanisms, but proving a batch really came from the
   registered probe is a deployment obligation.
3. **The kernel is honest.** Every strong claim rests on kernel-pushed
   events. A root-compromised host can suppress them, and a
   kernel-compromised host can fabricate them. Suppression appears as loss
   or a gap, never as silence that proves nothing happened.
4. **Clocks.** The collector's wall clock bounds when it *held* a batch.
   Kernel event ordering comes from the kernel. There is no trusted time
   source and none is claimed.
5. **Key custody and lifecycle.** Keys carry versions and can be revoked
   by removing an anchor. There is no provisioning, no rotation schedule,
   no expiry, no HSM, and no recovery beyond re-provisioning an identity.
6. **The containment host's privilege.** The freezer needs write access to
   the cgroup hierarchy. Denied, it fails open and records the failure.
7. **Policy and ledger files are ordinary files.** Their integrity is a
   deployment matter; nothing signs or anchors them.
8. **A compromised warrant authority key defeats the containment gate.**
   Distinct keys and mandatory records bound and expose the damage; they
   do not prevent it.

## 8. Known limitations

1. **`aip-service` integrates none of this.** The shipped HTTP service
   still carries its own weaker authority model and the
   `POST /v1/evidence/generate` signing oracle described in
   `CURRENT_SYSTEM.md` §5–§6. Nothing in Gates 1–11 touched it.
2. **No production path yields `Proven` for a workload.** The reconciler
   emits `Proven` only for `SENSOR_INTEGRITY_FAILURE`, which targets the
   observer and which containment refuses. Containment is therefore
   reachable in tests and unreachable from real evidence today.
3. **Reconciliation records are now signable (SD-09 closed).** A fourth
   authority signs the verdict: `aip_reconcile::ReconcilerSigner` produces a
   `SignedReconciliation`, verified offline against `ReconcilerTrustAnchors`
   the verifier supplies (`aip-reconcile/src/attest.rs`, adversarial tests +
   a real-engine end-to-end test in `ghost-demo/tests/signed_verdict.rs`).
   Signing attributes the verdict; it never strengthens it. **Wiring the
   signed verdict into the NEXORA commitment (SD-10) is the next step** — the
   capability exists; automatic commit does not yet.
4. **Nothing feeds NEXORA automatically, and nothing persists it.**
5. **`UNATTRIBUTED_EFFECT` is unreachable** until the decision point emits
   signed coverage statements.
6. **Attested batches are not persisted.** Gate 8 persists the snapshot,
   the health archive and the continuity reports — not the batches.
7. **Observation is TCP-only on the wire**, IPv4 without extension
   headers, and the send source counts bytes rather than seeing them. No
   payload is captured or hashed anywhere (invariant I23).
8. **Filesystem observation is one action** — a completed write on a
   marked mount. `FAN_REPORT_FID` is refused on this host, so creates,
   deletes and renames are not observed, and file identity is a path plus
   `(dev, ino)` context.
9. **Freezing is not killing and not isolation.** A frozen process keeps
   its descriptors, sockets and memory; work already queued in the kernel
   may complete; children forked after attachment are frozen with it.
10. **Agent attribution is a claim.** The observer cannot bind a process
    to an AIP-ID; it measures what a process is and lets the reconciler
    compare.
11. **No transport, no daemon, no scheduler, no API** for any of the new
    capability.
12. **The demonstrator flake in §5.**

## 9. Hardware evidence

**None. Gate 11 was not performed, because the hardware is not present.**

Everything in this report was produced on a virtual machine:

| Fact | Value |
|---|---|
| Kernel | Linux 6.18.44 |
| CPU | Intel Xeon @ 2.80 GHz, 4 vCPU, `hypervisor` flag set |
| Memory | 16 GB |
| DMI identity | masked — `/sys/class/dmi/id/*` unreadable |
| Network | `eth0`, `virtio_net`, PCI `1af4:1041` (`virtio-pci`), MTU 1400 |
| cgroups | v2 at `/sys/fs/cgroup/unified`, plus v1 controllers |
| BPF | `CONFIG_BPF_SYSCALL=y`, `BPF_JIT_ALWAYS_ON=y`, `XDP_SOCKETS=y`, BTF present |

There is no Dell R630, no Intel X710 and no physical NIC of any kind.
Consequently **no throughput, line-rate, latency, overhead, packet-loss,
concurrency or TRL figure exists in this repository**, and none may be
quoted from it. The single timing number recorded anywhere — ~10 ns per
run for one 27-instruction XDP program under `BPF_PROG_TEST_RUN` on an
idle virtual host (Gate 10) — is a property of that program in that
harness and is not a performance claim about anything else.

## 10. Claims safe for investor material

Each of these is backed by code and a named test in this repository.

1. An independent observer records execution facts from **kernel-pushed
   sources** — socket state transitions, process fork and exec, socket
   sends, filesystem writes, and a device-layer packet tap — and the
   component that does the observing **holds no signing key**, so a
   compromised host can lie to its own probe but cannot forge an
   attestation.
2. Authorisation and observation are **separate signatures under separate
   keys**, and the system refuses to treat one as the other. Five distinct
   authorities exist and each verifier refuses a key belonging to another.
3. The default answer is **`CANNOT_PROVE`**. Missing, ambiguous or
   degraded evidence never becomes proof, and silence is never evidence
   that something did not happen.
4. Four action classes are verified end to end against real kernel
   evidence on a live host: **network connect, process exec, network send,
   file write**.
5. The observer states its own coverage, loss and continuity, and
   **refuses to sign after amnesia, rollback or a fork of its own record**
   under the default strict policy — demonstrated by restarting a real
   collector process and restoring an old state file.
6. Verified history can be committed to a **Merkle log with signed,
   chained heads and offline inclusion and consistency proofs**, so a
   third party can check a record's presence without trusting the holder.
7. Response is **gated on proof, not suspicion**: severity and evidence
   strength are separate types, containment requires `Proven` by an
   explicit match, autonomous action is off by default, and a real process
   has been frozen through that gate and released.
8. The whole pipeline is **adversarially tested**: forged keys, mutated
   fields, replay, PID reuse, rollback, fork, truncation, protected
   targets, degraded observers and expired authority each have a test that
   fails if the property is removed.

## 11. Claims safe for customer documentation

1. Ghost answers one question: *what execution-related fact did an
   independently keyed observer actually record, and over what interval
   can it vouch for its own coverage?*
2. It runs on Linux and uses documented kernel interfaces:
   `perf_event_open` over static tracepoints, the netlink process
   connector, `pidfd_open`, `AF_PACKET`, fanotify and procfs. **It does
   not load eBPF programs, does not use XDP, and does not intercept,
   filter or block traffic.**
3. It never reads message content: no payload is captured or hashed. A
   send is evidenced by the kernel's byte count; a file write by its path;
   an execution by the executable's contents.
4. Application, database and proxy logs are **not** treated as
   observation. They are statements by the programs that write them, and
   the decision record explains why they can never move a verdict.
5. An outage of the observer produces "we cannot say", never an
   accusation. Degraded sensors cannot escalate anything.
6. Nothing is contained without a signed warrant resting on proven
   evidence, and containment is off by default. When enabled, the only
   action is to freeze one identified process, and every attempt —
   including every refusal — is a signed record.
7. Protected identities can be named and are exempt from autonomous
   action.
8. Every artefact is verifiable offline against trust anchors the verifier
   supplies, never anchors carried inside the artefact.

## 12. Claims still prohibited

Do not state any of the following. Each is either false today or
unmeasured.

1. **eBPF.** No eBPF program is loaded by any library or production path.
   The Gate 10 evaluation is a test that loads and test-runs a program and
   attaches nothing.
2. **XDP**, packet filtering, packet dropping, network isolation, traffic
   interception, or `cgroup/connect4` hooks. Evaluated and deliberately
   not adopted.
3. **Payload visibility** of any kind, or a hash of a raw payload.
4. **Zero loss**, complete capture, or full coverage. Loss is accounted
   and reported; polled sources cannot even claim "no loss".
5. **Root-compromise resistance.** A root-compromised host can lie to its
   own probe. The architecture bounds that; it does not defeat it.
6. **Post-quantum cryptography.** Ed25519 and SHA-256 only. An algorithm
   identifier is not a capability.
7. **Any performance figure** — throughput, line rate, overhead, latency,
   packets per second, agents per host — and **any TRL number**. Nothing
   in this repository measures them, and the test host is virtual (§9).
8. **Hardware attestation, TPM, TEE, secure enclave.** None exist.
9. **"Zero false outages"**, or any statistical claim about false
   positives. No such measurement exists.
10. **Autonomous threat response**, "instant isolation", or
    `anomaly → kill` in any form. The forbidden architecture is
    structurally absent.
11. **A deployed, integrated product.** `aip-service` runs the pre-Ghost
    model; the Ghost pipeline is a set of libraries and a demonstrator.
12. **That the observer's key is off-host in any running deployment.** The
    code permits it; no deployment enforces it.
13. **That NEXORA's anchor is external.** The interface exists; its
    independence is a deployment property.

## 13. Remaining research work

Ordered by what unblocks the most.

1. **Signed reconciliation records (SD-09) — DONE.** A fourth signer over the
   verdict (`aip_reconcile::attest`), so a committed record's origin is
   checkable. The remaining work it unblocks is **SD-10**: feed the
   `SignedReconciliation` into the NEXORA commitment automatically (nothing
   commits it yet), then SD-11/SD-12.
2. **Decision-point coverage statements** — the signed "no expectation
   exists for this window" that `UNATTRIBUTED_EFFECT` requires.
3. **A collector deployment** — an authenticated probe → collector
   transport, key custody off the observed host, and persistence of
   attested batches. This is what turns assumption 1 and 2 of §7 into
   properties.
4. **A `Proven` path for workload violations** — today `Proven` is
   reachable only for observer integrity. What kernel evidence would make
   a workload violation independently recomputable is an open research
   question, and until it is answered containment stays unreachable from
   real inputs.
5. **`aip-service` integration** — retire the duplicate authority model
   and the signing oracle, and expose the Ghost pipeline behind SD-13.
6. **NEXORA anchoring in practice** — an external anchor and a durable
   log, with the truncation argument made concrete.
7. **Broader filesystem and network observation** — creates, deletes and
   renames (needs `FAN_REPORT_FID`, refused on this host); IPv6; UDP.
8. **Hardware validation** on a physical NIC, at which point performance
   questions become askable for the first time.
9. **Key lifecycle** — provisioning, rotation, expiry, recovery.
10. **Whether network isolation should exist at all** as a containment
    action, and under what warrant, if the answer to (4) ever makes it
    reachable.

---

## 14. Final status

```
VALIDATED RUNTIME
```

**What that means here.** Every stage of the evidence pipeline —
authorisation, execution binding, kernel-mediated observation, continuity,
reconciliation, evidence strength, warrant, containment and commitment —
is implemented in `aip-standalone`, adversarially tested, and exercised at
runtime against a real Linux kernel on this host: real processes, real
sockets, real files, a real collector process restarted across a rolled-back
state file, and a real process frozen and released through the warrant gate.

**What it does not mean.**

- It is **not** `PRODUCTION HARDENING` or `PRODUCTION READY`. `aip-service`
  integrates none of this and still carries the signing oracle; there is no
  transport, no daemon, no key custody, no persistence of attested batches,
  and no deployment in which the observer's key is demonstrably off-host.
- The runtime that was validated is a **demonstrator**, not a deployment.
  Its collector runs beside its probe and writes its key in plaintext,
  which is exactly what a production deployment must not do.
- No hardware was validated and no performance was measured.

The status describes the evidence machinery, not a shipped product. Read
§8, §9 and §12 before quoting anything from this report.
