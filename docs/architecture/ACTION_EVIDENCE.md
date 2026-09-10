# ACTION_EVIDENCE

Stage 7 (action-level evidence) — the layer that lets one authorized action be
independently observed and cryptographically matched against its
`ExpectedExecution`, so that `VERIFIED_EXECUTION` becomes reachable for that
action and for nothing else.

> **Status: PARTIALLY_IMPLEMENTED — four action classes.**
> Implemented and live-demonstrated for `ghost.net.connect.v1` (an
> established TCP connection to a remote endpoint), as **presence** (a polled
> table row: the connection existed at the sample) and, since Stage 7b, as
> **transition** (the kernel reported the connection being made — §14);
> since Stage 7c, for `ghost.process.exec.v1` (the bound instance forked a
> child that executed an image of the authorized **content** — §15), as
> transition only; and, since Gate 3 of the completion mandate, for
> `ghost.net.send.v1` (the bound instance handed bytes to the kernel for
> send on a connection to the authorized endpoint — §16; the count, never
> the bytes), as transition only; and, since Gate 4, for `ghost.fs.write.v1`
> (the bound instance completed a write to the authorized path, bound by
> the kernel's own pidfd — §17; the path, never the content), as transition
> only. Every other action kind remains
> unobservable and reconciles to `CANNOT_PROVE`. Strength is `Attested`,
> never `Proven`. See `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md` for the
> evidence trail.

## 1. What "action evidence" is here

An `ExpectedExecution` authorizes an `action_kind` with a `parameter_digest`.
For the reconciler to *match* it, the parameters must name something an
independent observer can measure. Today the observer measures exactly one
thing that is also an action: rows of the kernel socket tables
(`/proc/net/tcp`, `/proc/net/tcp6`) joined to a process instance's open
descriptors under a pidfd anchor (`SNIFFER_DOG.md` §9). So the one observable
action class is:

```
ghost.net.connect.v1
    parameters: protocol ∈ {tcp, tcp6}, remote_addr (4 | 16 raw bytes),
                remote_port (u16, big-endian)
    observed as: an ESTABLISHED (0x01) TCP/TCP6 row whose inode is open in
                 /proc/<pid>/fd of the pidfd-anchored instance
```

Nothing about bytes, payload, TLS, DNS names, timing, or the `connect()` call
itself is part of the class, because no source in this repository sees them.

## 2. No new signed object

Deliberately. The evidence *is* the existing `ObservedExecution` with a
`SocketObserved` effect, already collector-signed inside an `AttestedBatch`
whose canonical bytes cover the process instance, executable hash, effect
(protocol, local, remote, state, inode), mechanism, attribution claim,
claimed decision id, probe clock and probe sequence. Introducing a second
"action evidence" record signed by the observer would have required the
observer to state what an observation *means* — which is authorization
vocabulary and therefore forbidden to it (I19). Instead:

- **Vocabulary** lives in `aip-authorize::actions`: `NET_CONNECT_ACTION`,
  `NetProtocol`, `net_connect_parameters(protocol, remote_addr, remote_port)
  → ActionParameters`. The decision point's caller uses it to build the
  request; its digest is what the `ExpectedExecution` carries. No dependency
  on any observation type.
- **Interpretation** lives in `aip-reconcile::action::derive_action`: a
  deterministic mapping from one observation to `(kind, parameter_digest,
  mechanism)` or `None`, computed through the *same* `net_connect_parameters`
  call. The digest is recomputed, never carried.

The cryptographic join is therefore: DP-signed `parameter_digest` ==
SHA-256(`GHOST/ActionParameters/v1` ‖ canonical pairs) recomputed from
collector-signed bytes. Two signers, one deterministic encoding, no third
authority.

## 3. Canonical encoding and domain separation

- Parameters: `ActionParameters::canonical_bytes` — domain
  `GHOST/ActionParameters/v1`, count, key-sorted `(put_str key, put_bytes
  value)`. Values are raw bytes (ASCII family, 4/16-byte address, 2-byte
  big-endian port) so each endpoint has exactly one encoding.
- Observation: `SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1` inside
  `OBSERVATION_BATCH/v1` inside `OBSERVER_HEAD/v1` (unchanged, Skill 6/6.5).
- Result: `SYNTRIASS/GHOST/RECONCILIATION/v1`, version 2. `ActionComparison`
  now encodes the mechanism that carried the evidence alongside the variant
  code.
- No new domain tag. The workspace domain audit is unchanged at 18 tags.

## 4. Provenance boundary

| Source | Kind | Who authors the content | May contribute to `VERIFIED_EXECUTION` |
|---|---|---|---|
| `ProcNetTable` socket row | kernel-authored table, **polled** through procfs, pidfd-anchored | kernel (forgeable by host root) | **yes** — the only source that does |
| `PidFdAnchored` process facts | procfs, pidfd-anchored | kernel (forgeable by host root) | identity only |
| `ProcConnector` fork/exec/exit | kernel-pushed netlink | kernel | identity/lifecycle only; carries no action content |
| `ProcfsPoll` | procfs, unanchored | kernel (forgeable by host root) | no |
| `AgentAttribution::Claimed`, `claimed_decision_id` | agent / host claim | the party under scrutiny | **never as evidence**; used only to tie an observation to *this* decision (a positive verdict requires the claim to be present and consistent — the claim can only restrict, never produce) |

The mechanism label is a probe claim bounded by the collector's registry
(`RegisteredOnly`): a probe not provisioned for `ProcNetTable` cannot label a
row as table evidence (`n12`). Under `Open` policy no label is verified and
action-shaped evidence yields `ProvenanceUnverifiedOpenPolicy`.

## 5. The `VERIFIED_EXECUTION` predicate, as implemented

All of the following, checked by the engine in this order; any failure is the
specific `CANNOT_PROVE` reason shown, or the earlier class already defined in
`RECONCILIATION_MODEL.md`:

1. `ExpectedExecution` verifies against the anchored decision point; with the
   agent's public key supplied, the decision key is not the agent's.
2. Observer health and every batch verify; one observer; contiguous chain
   ending at the signed health head; health neither stale nor future-dated;
   with the agent's public key supplied, the observer key is not the agent's.
3. Observer state `Active` (else `CONTINUITY_FAILURE` / `SENSOR_INTEGRITY_FAILURE` /
   `ObserverDegraded`).
4. Identity: at least one in-window observation whose measured instance
   matches the binding structurally (pid + start ticks + boot id +
   executable hash), and none diverges (else `IDENTITY_DIVERGENCE` or
   `AmbiguousObservations`).
5. Among those observations, one that `derive_action` maps to the expected
   `action_kind` — else `ActionEvidenceUnavailable`.
6. Its recomputed `parameter_digest` equals the expectation's — else
   `ActionEvidenceDoesNotMatch` (action `Mismatch`).
7. Its claim pair names this decision **and** this agent — else
   `ActionEvidenceUnclaimed`.
8. The batch carrying it has `claimed_from_ms ≥ issued_at − tol`,
   `claimed_to_ms ≤ valid_until + tol`, and the observation's own wall-clock
   stamp inside the same range — else `ActionEvidenceOutsideWindow`.
9. That batch lies inside the collector's signed `attested_coverage` epoch —
   else `ActionEvidenceNotCovered`.
10. `probe_policy == RegisteredOnly` — else `ProvenanceUnverifiedOpenPolicy`.
11. The central guard (`Draft::precondition_holds`) re-checks: sealed
    `ActionComparison::Match`, identity `Match`, the
    `action_continuity_verified` flag that only step 8–9 sets, and strength
    exactly `Attested`.

Then, and only then: `VERIFIED_EXECUTION`, `Attested`, reason
`ActionEvidenceMatches`.

**Whole-window coverage is not required for a positive verdict.** The
observation itself is the evidence; coverage of the rest of the window would
add nothing to it. The record still reports `availability` for the whole
window, so a `VERIFIED_EXECUTION` may carry `availability: Unavailable {
WindowNotCovered }` — read as "the action was observed inside the window; the
window as a whole was not covered". Whole-window, kernel-pushed, recomputed
coverage remains mandatory for `PHANTOM_CLAIM`, which asserts the opposite.

## 6. Why the positive result is hard to fake

- No caller-settable field: `Reconciliation` has no `verified`, `trusted`,
  `observed`, `kernel_verified`, score or severity.
- `ActionComparison::Match` needs an `ActionEvidenceSeal`; its constructors
  are `pub(crate)` and called from one place, after every check above.
- The central guard is the only exit; a positive class proposed without its
  visible precondition is downgraded to `CANNOT_PROVE / InvariantNotSatisfied`.
- Every field that matters is under the collector's signature; mutating any
  of them is `SENSOR_INTEGRITY_FAILURE` at `Proven` (`n15`, live `G`).
- The parameter digest is domain-tagged; the same pairs under any other
  domain do not reproduce it (`n16`).

## 7. Temporal semantics

Three clocks, never equated: the probe's wall clock and claimed batch
interval (host claims — used only to *restrict*), the collector's health
emission time (signed — anchors the batch to a moment the collector vouched
for), the verifier's time (bounds health freshness). The socket table shows
that a connection **existed at the sample**, not when it was created; on its
own, presence evidence of a connection that pre-dates the authorization
window and is still open inside it would verify. **Stage 7b closes this**
where the kernel-pushed socket-state source is live: the connection's
creation is a kernel event with a kernel timestamp, placed in time by the
collector's signed clock and the probe's boot-clock anchor, and a connection
shown to predate the decision disqualifies presence evidence of the same
connection (§14).

## 8. Replay protection

A batch offered twice is collapsed and flagged (`replay_detected`). An
observation claimed under decision A does not verify decision B
(`ActionEvidenceUnclaimed`, live `F`). What is **not** protected: two
genuine, overlapping authorizations of the same instance for the same
endpoint may both be verified by one long-lived connection observed twice
under each claim — the table cannot tell one connection from a reconnect
except by inode, and cross-decision reuse is not tracked (§10).

## 9. What the live demonstrator shows (`ghost-demo`, Linux)

`cargo run -p ghost-demo --bin ghost-demo` / `cargo test -p ghost-demo`. A real
child process (`ghost-demo-agent`) makes a real TCP connection to a real
listener; the binding is collected from procfs; a real decision point signs
the expectation; the probe reads the real socket table under a real pidfd
anchor; a real collector attests; the real engine reconciles. **In one
process** — which is exactly the trust separation production must not skip;
this is a demonstrator, labelled `NOT_PRODUCTION_CAPABILITY`.

| Scenario | Result |
|---|---|
| authorized connection made | `VERIFIED_EXECUTION` · `Attested` · action `Match(ProcNetTable)` |
| A. expected, not executed | `CANNOT_PROVE` · `ActionEvidenceUnavailable` (instance seen, no connection; polled — never `PHANTOM_CLAIM`) |
| B. executed, not expected | `CANNOT_PROVE` · `ExpectedSideCompletenessUnknown` (never `UNATTRIBUTED_EFFECT`) |
| C. different parameters | `CANNOT_PROVE` · `ActionEvidenceDoesNotMatch` · action `Mismatch` |
| D. wrong instance, same binary | `IDENTITY_DIVERGENCE` · `Attested` |
| E. counted loss | `CANNOT_PROVE` · `ObserverDegraded` |
| F. replayed for another decision | `CANNOT_PROVE` · `ActionEvidenceUnclaimed` · `replay_detected` |
| G. tampered batch | `SENSOR_INTEGRITY_FAILURE` · `Proven` |

## 10. CANNOT_PROVE — stated

- Any `Standard(Action)` verb (Read/Write/Delete/Admin/Execute/Delegate) and
  any custom action other than `ghost.net.connect.v1`.
- Application payload, bytes, request content, parameter digests that name
  application data.
- With presence evidence alone: when a connection was created and whether it
  pre-dates the window. With transition evidence (§14): pre-existence is
  provable by the collector's clock; placement *inside* the window rests on
  the host's clock anchor.
- Truth of the socket table on a host whose root feeds the probe a
  fabricated procfs — hence `Attested`, never `Proven`.
- Non-execution from the absence of a connection in a polled table (A).
- UDP "connections", non-ESTABLISHED TCP states, IPv4-mapped-IPv6 forms not
  literally present in the table row.
- Anything under `ProbePolicy::Open`.
- Independence (I1/I10) when the verifier does not supply the agent key.

## 11. Deployment assumptions

Those of `SNIFFER_DOG.md` §8 and `RECONCILIATION_IMPLEMENTATION_REPORT.md`
"Deployment assumptions", plus: the party constructing the
`AuthorizationRequest` uses `net_connect_parameters` (any other encoding of
the same endpoint will never match); the collector provisions `ProcNetTable`
for the probe; the probe reads sockets under a pidfd anchor (the
`observe_sockets` path), not by pid alone.

## 12. The kernel primitive (closed in Stage 7b)

Stage 7 recorded that stronger evidence than a polled table needs a
**kernel-pushed socket-state event** bound to the process instance. Stage 7b
implements exactly that: the `sock:inet_sock_set_state` tracepoint read
through `perf_event_open` — no eBPF, no XDP — with the `connect()`
initiation pidfd-anchored to the calling instance (§14). What it does *not*
add: payload, bytes, any second action class, or `Proven` strength.

## 13. NOT_IMPLEMENTED / NOT_PROVEN

eBPF, XDP, any tracepoint other than `sock:inet_sock_set_state`,
`sched:sched_process_fork`, `sched:sched_process_exec` and
`sock:sock_send_length`, payload capture or payload digests (the Gate 2
`AF_PACKET` tap keeps TCP/IP headers only; the Gate 3 send class keeps a
byte count only), syscall observation, file events other than a completed write on a marked
mount (create / delete / rename need `FAN_REPORT_FID`, refused on this
host), file content or content digests, exec-argument capture,
UDP actions, receive-side actions, any fifth action class, zero loss,
root-compromise resistance, containment logic, TRL, latency, throughput,
hardware validation. (This list was "any second action class" until Stage
7c and "any third" until Gate 3; §12 above records Stage 7b's own view.)

## 14. Stage 7b — transition evidence (kernel-pushed)

Everything above describes **presence** evidence: a socket row read from the
polled table. §7 stated its limit — existence at the sample, not creation —
and the live tests T-A/T-C reproduced both failure modes (a pre-existing
connection verified; a connect-and-close was unprovable). Stage 7b adds a
second, stronger kind for the same action class, and makes the two
distinguishable in the record:

```
ActionEvidenceSeal { mechanism, kind }
    kind = Presence    ProcNetTable        "a connection to R existed at the sample"
    kind = Transition  SockStateTracepoint "the kernel reported a connection to R being made"
```

### 14.1 Source

`sock:inet_sock_set_state`, read through `perf_event_open` (no eBPF) —
`SNIFFER_DOG.md` §4, §6b. Two events make one connection:

| Event | Context | What it carries | Instance binding |
|---|---|---|---|
| `CLOSE → SYN_SENT` | the `connect()` caller's task | remote endpoint, protocol, `sk`; local port not yet assigned | the probe pidfd-anchors `current_pid` and binds **only if** the instance's start tick ≤ the event's kernel time (same boot clock) |
| `SYN_SENT → ESTABLISHED` | softirq | full 4-tuple, `sk` | none — `current_pid` is whoever was running |

The reconciler pairs them by `sk`, same protocol, same remote, completion
not earlier than initiation in kernel time (`aip-reconcile::action::
derive_transitions`). An initiation without a completion is an **attempt**,
not a connection (`ActionTransitionIncomplete`).

### 14.2 The transition predicate

`VERIFIED_EXECUTION` with `kind = Transition` requires, in addition to steps
1–4, 10–11 of §5:

5′. a `SocketTransition` whose bound instance matches the binding and whose
   derived `kind`/`parameter_digest` equal the expectation's;
6′. a completion of the same socket (else `ActionTransitionIncomplete`);
7′. the initiating event's claim pair names this decision and this agent
   (else `ActionEvidenceUnclaimed`);
8′. temporal placement **inside the window** by the rules of §14.3 (else
   `ActionPrecedesAuthorization`, `ActionEvidenceOutsideWindow`, or
   `KernelTimeUnanchored`);
9′. both carrying batches inside the collector's signed coverage epoch (else
   `ActionEvidenceNotCovered`).

Strength is `Attested`, exactly as for presence. Not `Proven`: the events are
kernel-authored and cannot be injected from user space, but they travel
through a host-side probe that a root host can stop, filter or starve, and
the instance binding is procfs. What changed is the *fact*, not the
epistemic class: a transition says the connection was **made**.

### 14.3 Temporal semantics — five cases

Kernel timestamps are `CLOCK_MONOTONIC` (this sentence said `CLOCK_BOOTTIME`
until Stage 7c; §15.4 records why it was wrong); the window is decision-point
Unix ms. Placement uses the most trustworthy clock first and never compares
the two domains directly:

| Case | How it is decided | Result |
|---|---|---|
| 1. connection existed before authorization | the batch carrying the initiation has `attested_at_ms` (collector clock, signed) `< issued_at` — two off-host clocks, no host input; **or** the probe's `clock_anchor` places the initiation before `issued_at` | `CANNOT_PROVE / ActionPrecedesAuthorization`, `temporal = BeforeWindow`; also overrides presence evidence of the same connection (same protocol, remote, and local port where known) |
| 2. connection transitioned during authorization | anchor places initiation and completion inside `[issued_at, valid_until]` ± tol; collector clock does not contradict | eligible for `VERIFIED_EXECUTION · Transition` |
| 3. connection transitioned after authorization | anchor places initiation or completion after `valid_until` + tol | `CANNOT_PROVE / ActionEvidenceOutsideWindow`, `temporal = AfterWindow` |
| 4. event timestamp unavailable/untrusted | no `clock_anchor` in the carrying batch | `CANNOT_PROVE / KernelTimeUnanchored`, `temporal = Unanchored` |
| 5. clock domains cannot be compared | as 4; the reconciler never converts without an anchor and never uses the verifier's clock for placement | `Unanchored` |

The collector clock can only ever *deny* a placement (prove pre-existence);
it cannot place an event inside the window, because an event may be reported
long after it happened. The anchor can place, but it is the host's clock —
a probe claim, hence the `Attested` cap.

### 14.4 Replay, duplication, transplantation

A duplicated batch is collapsed and flagged. The initiating event carries the
claim it was captured under; offered against another decision or agent it is
`ActionEvidenceUnclaimed` / `ClaimInconsistent`. Two decisions cannot both be
verified by one transition: one event, one claim. Cross-instance: the
initiation is bound at capture; an event bound to another instance (other
start tick, boot id, or executable) is not a match (`tp10`).

### 14.5 What Stage 7b proves that Stage 7 could not

- That the connection was **made** inside the window, not merely open during
  it (T-C live: verified with an empty table).
- That a connection open during the window was made **before** the decision
  (T-A live: `ActionPrecedesAuthorization` by the collector's clock).
- Which instance made it, by a kernel-time-ordered pidfd anchor rather than a
  table join.

### 14.6 Still CANNOT_PROVE after Stage 7b

- Wall-clock placement beyond what the collector clock decides (the anchor
  is the host's clock).
- PID reuse inside one `CLK_TCK` tick of the initiation.
- Which process performed any transition other than the initiation.
- Anything on a host whose root disables or starves the ring — the
  mechanism is then absent or `Degraded`; it never becomes silent coverage.
- Bytes, payload, UDP, any other action class, non-execution from absence.

### 14.7 Live results (`ghost-demo`, this host)

| Scenario | Result |
|---|---|
| T-P authorized connection, tracer live | `VERIFIED_EXECUTION · Attested · Match(SockStateTracepoint, Transition)` |
| T-A established and attested before the decision, still open in the window | `CANNOT_PROVE · ActionPrecedesAuthorization · BeforeWindow` |
| T-C made and closed before any poll (0 rows in the table) | `VERIFIED_EXECUTION · Attested · Transition` |
| positive (polling-only observer, unchanged) | `VERIFIED_EXECUTION · Attested · Match(ProcNetTable, Presence)` |

The polling-only observer and its results are unchanged; presence evidence
was not weakened, only labelled, and overridden solely where the kernel
shows the same connection predates the decision.

## 15. Stage 7c — process execution (second action class)

Decided in `NEXT_ACTION_EVIDENCE_DECISION.md`. An AI agent that does anything
on a host runs tools; every tool run is a fork followed by an exec. This class
makes *what an agent ran* independently observable and matchable to *what it
was authorized to run*.

```
ghost.process.exec.v1
    parameters: exe_sha256 (32 raw bytes) — the image's CONTENT hash, never a path
    observed as: sched:sched_process_fork  (parent = the actor, anchored; child_pid)
                 sched:sched_process_exec  (child = the new image, anchored; kernel filename)
    kind:        Transition · mechanism SchedTracepoint · Attested
```

### 15.1 Source and attribution

Both tracepoints are sampled through the shared perf plumbing
(`aip-observe/src/perf.rs`, `sched.rs`), no eBPF. Measured live before
implementation: `sched_process_fork` fires in the **parent's** task context,
so the actor is attributable at the event; `sched_process_exec` fires in the
**new image's** context with the kernel-resolved `filename`. The probe
pidfd-anchors the parent at the fork and the child at the exec, each under
the start-tick rule, and hashes `/proc/<child>/exe`. The kernel's `filename`
is recorded as context and **never enters the digest** (`xe02`: same hash,
other path → verifies; same path, other content → mismatch).

### 15.2 Pairing (`aip-reconcile::action::derive_executions`)

A spawn pairs with an exec when the exec's `pid` equals the fork's
`child_pid`, the exec is not earlier than the fork in kernel time, and the
anchored child's start tick lies within `[fork − one tick, exec]` converted
through the batch's clock anchor — a recycled pid does not pair (`xe04`).
Without an anchor the pairing is recorded as unverified and the evidence is
`KernelTimeUnanchored` (`xe09`). A spawn with no paired exec is an attempt,
`ActionTransitionIncomplete` (`xe03`); an exec whose child could not be
anchored (it exited first) is not an execution (`xe05`).

### 15.3 The predicate

Identical in shape to §14.2, with the actor being the fork's bound parent,
the digest recomputed from the child's content hash through
`process_exec_parameters`, and the claim taken from the fork event (the
actor's registered pid). Placement, claim, coverage, provenance, loss,
restart and the central guard are the same code path for both classes
(`TransitionEvidence`). Strength is `Attested`; the executed image hash is
procfs-read under a pidfd anchor, like every content fact.

### 15.4 Clocks — a defect found by this class

The tick-level child-start check exposed that Stage 7b's perf samples were
**not** on `CLOCK_BOOTTIME` as documented: the `use_clockid` flag had been set
at the wrong bit and the kernel had silently used its default `sched_clock`
(a ~237 ms disagreement with process start ticks on this host). Measured on
this kernel, the tracepoint PMU accepts `use_clockid` only with
`CLOCK_MONOTONIC`/`MONOTONIC_RAW` and rejects `BOOTTIME`/`REALTIME`/`TAI`
with `EINVAL`. Event stamps are now explicit **`CLOCK_MONOTONIC`**; the
anchor samples realtime, boottime and monotonic together plus `CLK_TCK`, and
converts boot-clock start ticks into the event clock. §14.3's rules are
unchanged in form; "boot clock" there now reads "the event clock through the
anchor". Boot and monotonic coincide on a host that has not suspended; a
suspend between anchor and event shifts the relation, which is why probes
re-anchor per batch. Both documents (§14 above) should be read with this
correction.

### 15.5 Live results (`ghost-demo`, this host)

| Scenario | Result |
|---|---|
| X-P agent spawns a child executing the authorized image | `VERIFIED_EXECUTION · Attested · Match(SchedTracepoint, Transition)` |
| X-A child executes a different image (authorized `/bin/true`, ran `sleep`) | `CANNOT_PROVE · ActionEvidenceDoesNotMatch`, action `Mismatch` |
| X-B another instance of the same binary spawns the image under the bound instance's claim | `CANNOT_PROVE · AmbiguousObservations` — the bound (idle) agent's own exec event is a genuine match, the actor's spawn is divergent; ambiguity is never a verdict |
| X-C spawn observed and attested before the decision | `CANNOT_PROVE · ActionPrecedesAuthorization · BeforeWindow` |

### 15.6 Still CANNOT_PROVE

Arguments and environment (the kernel exposes `filename` only); what the
child did afterwards; an exec chain faster than the probe's anchoring (the
hash is of the image present at the anchor, as with Skill 6.5 `t10`); the
truth of the hashed image under a root host that swaps `/proc/<pid>/exe`;
PID reuse inside one `CLK_TCK` tick; any placement inside the window beyond
what the collector clock decides (the anchor is the host's clock); anything
on a host whose root disables or starves the ring; non-execution from the
absence of a fork/exec (the sched stream is not accepted as lifecycle
coverage for `PHANTOM_CLAIM` — it carries no exit; `xe15`).

## 16. Gate 3 — socket send (third action class)

The mandate asked for the smallest action-level network class beyond
`connect()`, with explicit hash semantics and no payload-hash claim unless a
payload is captured. Chosen from the Gate 2 evaluation
(`OBSERVATION_MODEL.md` §5.2): the `sock:sock_send_length` tracepoint.
RED `c830a8d`, GREEN `4e4bd6a`.

```
ghost.net.send.v1
    parameters:  protocol, remote_addr, remote_port — the ENDPOINT only,
                 the same keys, encoding and validation as ghost.net.connect.v1
    observed as: sock:sock_send_length in the SENDER's task context (anchored),
                 the socket's endpoint resolved from the attested
                 sock:inet_sock_set_state transitions of the same `sk`
    evidence:    the byte count the kernel accepted (`bytes`), signed as context
    kind:        Transition · mechanism SockSendTracepoint · Attested
```

### 16.1 Hash semantics, stated once

The parameter digest of a send names the endpoint, and is **equal by
construction** to the digest of a connect to the same endpoint
(`net_send_parameters` delegates to `net_connect_parameters`); the action
*kind* is what tells them apart (`ss02`, `ss11`). The byte count is inside
the signed event and never inside the digest: any positive count verifies
against the same expectation (`ss02`). No digest of the bytes themselves
exists anywhere in this class, in the observer, or in the vocabulary — the
kernel path sees a count, not content (I23). A payload digest could only be
introduced by a party that holds the plaintext (the agent, or an in-path
proxy that terminates TLS), which is a Gate 5 decision about self-reported
evidence, not an observation.

### 16.2 Source and attribution

Measured on this host before implementation: the tracepoint fires in
`sock_sendmsg` in the sending task's context (a 19-byte loopback send
produced one record under the sender's pid with `length = 19`). The record
carries the socket's kernel identity `sk`, family, protocol, the value
`sendmsg` returns and the flags; `ret ≤ 0` accepted nothing and is not a
send (`sk02`, `ss12`). The probe pidfd-anchors `current_pid` under the same
start-tick rule as a `connect()` initiation (`sk05`); the endpoint is not in
the record.

### 16.3 Endpoint resolution (`aip-reconcile::action::derive_sends`)

A send's endpoint is the one named by the **latest** attested transition of
the same `sk` that is not later than the send and is not itself a close.
If a transition of that `sk` to `CLOSE` lies between that transition and
the send, the kernel may have reused the socket's address: the send is
**unresolved** (`SendSocketUnresolved`, `ss04`–`ss06`), and a later
`ESTABLISHED` for the reused `sk` names the new endpoint (`ss05`). An
unresolved send is not a mismatch and not a verdict.

### 16.4 The predicate

As §14.2 with the send event as both initiation and completion (the kernel
accepted the bytes: one event), the actor being the bound sender, the
digest recomputed from the resolved endpoint through `net_send_parameters`,
the claim taken from the send event. Placement, claim, coverage,
provenance, loss, restart and the central guard are the shared
`TransitionEvidence` path (`ss03`, `ss07`–`ss10`, `ss13`). The wire
question (Gate 2) is not asked of a send verdict: a send is not a
handshake (`ss01`).

### 16.5 A defect found by this class — host-wide sources and anchoring cost

The send tracepoint fires for every process on the host, and the probe
hashed each sender's executable for each event. On this host two daemons
(a 215 MB and a 31 MB binary) send continuously; with eight live observers
in parallel the drains never finished. The probe now keeps one image hash
per pid and reuses it only while the start tick (same instance) and the
inode, size, modification time and path of the file `/proc/<pid>/exe`
resolves to (same image) all agree; a recycled pid, an exec of another
file, a rewritten file or another path re-hash, and a poisoned entry for
another inode is re-hashed rather than trusted (unit tests in `probe.rs`).
The pidfd anchor around every measurement is unchanged. Residual: a root
attacker who rewrites an image in place while preserving inode, size and
mtime defeats the revalidation — the same attacker who can already present
any procfs content, which is why every content fact is `Attested`, never
`Proven`. The demonstrator additionally bounds each drain by a hard
deadline; events left in a ring are carried by a later batch and placed by
their kernel stamps.

### 16.6 Live results (`ghost-demo`, this host)

| Scenario | Result |
|---|---|
| S-P the agent's hello on its connection, send authorized to that endpoint | `VERIFIED_EXECUTION · Attested · Match(SockSendTracepoint, Transition)`, 1 send event |
| S-A send authorized to another port | `CANNOT_PROVE · ActionEvidenceDoesNotMatch`, action `Mismatch` |

### 16.7 Still CANNOT_PROVE

What the bytes were; that they left the host or reached the peer (the
count is what the kernel accepted from the caller); sends on a socket whose
transitions were not observed (`SendSocketUnresolved`); receive-side
actions (`sock_recv_length` is not read); UDP and every non-TCP send;
anything on a host whose root disables or starves the ring.

## 17. Gate 4 — file write (fourth action class; the five observation states)

The mandate asked for one filesystem or syscall action with its
observation states stated explicitly. Mechanism evaluation:
`OBSERVATION_MODEL.md` §6. RED `4a5f716`, GREEN `2f1ba9b`.

```
ghost.fs.write.v1
    parameters:  path — the absolute path bytes, exactly as authorized
    observed as: a fanotify FAN_CLOSE_WRITE on a marked mount, with the pidfd
                 the kernel created for the acting process (FAN_REPORT_PIDFD),
                 the object resolved to the kernel's current path and (dev, ino)
    evidence:    that a write to that path was completed by that instance
    kind:        Transition · mechanism Fanotify · Attested
```

### 17.1 The five states

| State | Meaning here | Record | Test |
|---|---|---|---|
| OBSERVED | a bound `FAN_CLOSE_WRITE` on the authorized path, claimed, in window, covered | `VERIFIED_EXECUTION · Attested · Match(Fanotify, Transition)` | fw01, F-P |
| NOT OBSERVED | the instance was seen in the window; no completed write to the path was | `CANNOT_PROVE · ActionEvidenceUnavailable` — never `PHANTOM_CLAIM` (fanotify is not lifecycle coverage) | fw03, F-N |
| AMBIGUOUS | two instances completed writes to the path under one claim | `CANNOT_PROVE · AmbiguousObservations` | fw04 |
| LOSS | the queue overflowed (`FAN_Q_OVERFLOW`) in the window | `CANNOT_PROVE · ObserverDegraded` — a matching event does not survive loss | fw05 |
| UNAVAILABLE | no observer; a probe not provisioned for `Fanotify` (its batch is refused); `Open` policy | `NoObserverEvidence` / refused / `ProvenanceUnverifiedOpenPolicy` | fw06 |

### 17.2 Source and attribution — the kernel binds the writer

`fanotify` queues, per event, an open descriptor to the object and a pidfd
it creates **from the event's own `struct pid`** when the event is read:
the binding to the acting process instance is the kernel's, not a pid
number the probe opens later (Stage 7b/7c/Gate 3 anchoring). If the
process has exited by the read the kernel reports `FAN_NOPIDFD` and the
event is unbound (`fa06`). The probe measures the instance *through* that
pidfd (alive before and after the procfs reads) and still applies the
start-tick rule against its read stamp (`fa05`). The content of the
measurement — start tick, image hash — is still procfs, so `Attested`.

### 17.3 Path semantics

The digest is over the path bytes, unnormalised (`fw02`): `/a/b` and
`/a/b/` are different names, as they are to the kernel. The observed path
is the kernel's resolution of the object's dentry in the probe's mount
namespace **when the event is read**: a rename between write and read
shows the new name; an unlink shows ` (deleted)`, which the probe turns
into a flag and the reconciler refuses to place on any authorized path
(`FilePathUnresolved`, `fw09`). `(dev, ino)` is signed context: a replaced
file at the same path still verifies (`fw02`), because the class names the
path. File-handle identity (`FAN_REPORT_FID`) would name the object
independently of any path; it is refused with `ENODEV` on this host (zero
fsid on the root filesystem) and is not claimed.

### 17.4 The predicate

As §14.2 with the event as both initiation and completion, the actor
being the kernel-bound writer, the digest recomputed from the resolved
path through `fs_write_parameters`, the claim taken from the event.
Placement, claim, coverage, provenance, loss, restart and the central
guard are the shared `TransitionEvidence` path (`fw07`–`fw15`). A
`FAN_MODIFY` without `FAN_CLOSE_WRITE` is a write in progress, not this
class (`fw08`).

### 17.5 Time — a weaker stamp than the tracepoints

fanotify events carry no kernel timestamp. The probe stamps each event
when it reads it: an upper bound on when the write completed, bounded
below only by the previous drain. Placement inside the window therefore
rests on the probe's read cadence as well as its clock anchor; a write
completed before the window and read inside it would be placed inside.
The demonstrator drains every 50 ms of quiet; a production probe must
state its cadence. This is recorded, not hidden: `TemporalComparison` for
this class is `Attested` on a probe stamp, as for every class, with this
additional caveat.

### 17.6 Live results (`ghost-demo`, this host)

| Scenario | Result |
|---|---|
| F-P the agent writes the authorized path | `VERIFIED_EXECUTION · Attested · Match(Fanotify, Transition)`, 1 file event |
| F-A write authorized for another path | `CANNOT_PROVE · ActionEvidenceDoesNotMatch`, action `Mismatch` |
| F-N write authorized, never done | `CANNOT_PROVE · ActionEvidenceUnavailable`, identity `Match`, 0 file events |

### 17.7 Still CANNOT_PROVE

What was written (no content is read, hashed or claimed); writes on
mounts that are not marked; creates, deletes and renames (need
`FAN_REPORT_FID`); writes whose writer exited before the read; when
exactly the write completed beyond the read stamp; anything on a host
whose root disables the mark or starves the queue.
