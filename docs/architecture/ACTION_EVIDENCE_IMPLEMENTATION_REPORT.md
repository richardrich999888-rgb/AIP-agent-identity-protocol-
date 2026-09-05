# ACTION EVIDENCE IMPLEMENTATION REPORT

Stage 7 — action-level evidence. Commits `44ed9b5` (RED), `63c5e0a` (GREEN),
`ghost-demo` (live demonstrator). Predecessor: Skill 7 + corrective pass at
`2c58771`.

## Status

**PASS, for one action class.** `VERIFIED_EXECUTION` is reachable for an
established TCP connection to an authorized `(protocol, remote_addr,
remote_port)`, at `Attested`, derived by the engine from collector-signed
socket-table observations of the pidfd-anchored instance. It is unreachable
for every other action kind. The live demonstrator produced the positive
class and the seven negative classes on this host from real processes, real
connections and the real kernel table. Skill 8 was **not** started.

What this stage does **not** claim: kernel-pushed connection events, payload
or byte visibility, eBPF/XDP/packet capture, connect() timing, zero loss,
resistance to a root host that fabricates procfs, any TRL or performance
figure.

## Step 1 — audit of the gap (recorded before coding)

| Question | Answer |
|---|---|
| A. `ExpectedExecution` fields | `decision_id`, `decision_point_id`, `agent_id`, `authority` jtis, `action_kind: ScopeAction` (`Standard(Action)` \| `Custom(≤64 B)`), `parameter_digest = SHA-256(GHOST/ActionParameters/v1 ‖ pairs)`, `execution_binding`, `issued_at`, `valid_until`, DP signature |
| B. Observation fields | `ObservedExecution { observed: {pid, start ticks, boot id, exe sha256}, attribution (Claimed/NotEstablished), effect: ProcessPresent \| ProcessNoLongerPresent \| SocketObserved{protocol, local, remote, state, inode}, mechanism, claimed_decision_id, host_wall_clock_ms, probe_seq }`; `KernelLifecycleEvent { fork/exec/exit, kernel_timestamp_ns, bound }`. Collector-signed inside `AttestedBatch`. |
| C. Can an observation identify… | process instance **yes** (pidfd-anchored); executable **yes** (content hash via procfs); syscall/event **fork/exec/exit only**, no arguments; network connection **yes, socket-level metadata**, polled; network *operation* (connect(), bytes, payload) **no**; payload/parameter digest **only when the parameters are the socket tuple**; action kind **no** — the observer never assigns meaning (I19) |
| D. Cryptographic join | `decision_id` + structural binding already; parameters join iff the authorized parameters are exactly the kernel-visible tuple under one canonical encoding |
| E. Agent forgery | cannot sign batches; can only claim. A claim never produces evidence; it can only tie evidence to a decision |
| F. Host fabrication | a root host can feed the probe a fabricated table. Accepted at `Attested`, never `Proven` — the cap already applied to identity (Skill 6 A4) |
| G. Probe claiming a mechanism | bounded by the collector registry; refused under `RegisteredOnly` if not provisioned (`n12`); unverified under `Open` |
| H. Required for a legitimate `VERIFIED_EXECUTION` | see `ACTION_EVIDENCE.md` §5 (eleven predicates) |
| I. Impossible after this stage | connection creation time; payload; any `Standard(Action)` verb; procfs truth under root; non-execution from polled absence; two decisions served by one connection |

Missing kernel primitive for stronger evidence: a kernel-pushed socket-state
event bound to the instance (tracepoint `inet_sock_set_state` or
`sock_diag` destroy events), which needs an eBPF/tracing loader this
repository does not have. Not implemented, not claimed.

## Design decisions

1. **No new signed object.** The evidence is the existing collector-signed
   `ObservedExecution`. A second "action evidence" record signed by the
   observer would require the observer to state authorization meaning. The
   vocabulary (`aip-authorize::actions`) and the interpretation
   (`aip-reconcile::action`) are separate, and the digest is recomputed by
   the reconciler through the same function the decision point's caller
   used. Two signers, one deterministic encoding, no third authority.
2. **One class, exactly.** `ghost.net.connect.v1` ↔ ESTABLISHED TCP/TCP6 row
   labelled `ProcNetTable`, address family consistent with protocol, port ≠ 0.
   UDP, LISTEN, SYN_SENT, TIME_WAIT, family mismatch, mislabelled mechanism →
   not evidence.
3. **The claim is a join key, never evidence.** A positive verdict requires
   the observation's claim pair to name this decision and this agent
   (`ActionEvidenceUnclaimed` otherwise). This only restricts; it also
   blocks cross-decision transplantation of one observation.
4. **Positive verdicts do not require whole-window coverage.** The
   observation is the evidence; the carrying batch must be inside the window
   and inside the collector's attested coverage epoch. Whole-window,
   kernel-pushed, recomputed coverage stays mandatory for `PHANTOM_CLAIM`.
   `RECONCILIATION_MODEL.md` §4 now states this reading of "continuity
   attested over the window" for each class.
5. **Strength is exactly `Attested`.** The guard refuses `Proven` for this
   class.

## Files changed

| Commit | File | Change |
|---|---|---|
| `44ed9b5` | `aip-reconcile/tests/action_evidence.rs` | 19 adversarial tests; p1/p2 red on verdict, n10 red on reason, 16 negatives pinned |
| `63c5e0a` | `aip-authorize/src/actions.rs`, `lib.rs` | vocabulary: `NET_CONNECT_ACTION`, `NetProtocol`, `net_connect_action`, `net_connect_parameters`, `NetConnectError`; 3 unit tests |
| `63c5e0a` | `aip-reconcile/src/action.rs`, `lib.rs` | `derive_action`, `DerivedAction`, `TCP_ESTABLISHED`; 2 unit tests |
| `63c5e0a` | `aip-reconcile/src/result.rs` | `ActionEvidenceSeal { mechanism }` with `pub(crate)` constructors; `ActionComparison::matched/mismatched`; mechanism in the canonical encoding; 5 new `ReasonCode`s (0x47–0x4b) |
| `63c5e0a` | `aip-reconcile/src/reconcile.rs` | `ActionCandidate`, `References::candidates`, `compare_action`, `ActionOutcome`; identity-Match branch derives the verdict; guard requires sealed Match + `action_continuity_verified` + exactly `Attested` |
| `63c5e0a` | `aip-reconcile/tests/{adversarial,corrective}.rs` | two doc comments updated; **no assertion changed** |
| demo | `ghost-demo/` (new crate), `Cargo.toml` workspace member | `src/lib.rs` scenario runner, `src/bin/ghost-demo-agent.rs`, `src/bin/ghost-demo.rs`, `tests/live.rs` |

No `aip-observe` change was needed: `ProcfsProbe::observe_sockets` (Stage 6.5)
already produced pidfd-anchored socket rows.

## RED → GREEN trail

| Test | Before (`2c58771`) | After |
|---|---|---|
| `p1_complete_evidence_for_a_tcp_connection_verifies_at_attested` | `CANNOT_PROVE / ActionEvidenceUnavailable` | `VERIFIED_EXECUTION / Attested / ActionEvidenceMatches` |
| `p2_unrelated_extra_sockets_do_not_block_verification` | `CANNOT_PROVE` | `VERIFIED_EXECUTION` |
| `n10_fabricated_evidence_under_open_provenance_does_not_verify` | `CANNOT_PROVE / ActionEvidenceUnavailable` (reason did not name provenance) | `CANNOT_PROVE / ProvenanceUnverifiedOpenPolicy` |

The 16 negative tests passed against the pre-implementation engine because
the positive class was unreachable; they are pinned so the new capability
cannot over-reach. Recorded as such, not as RED.

## Negative coverage (fixture-based, `action_evidence.rs`)

| Case | Test | Result |
|---|---|---|
| 1 no action evidence | n01 | `CANNOT_PROVE`, identity Match, action Unobservable |
| 2 non-ESTABLISHED states | n02 | `CANNOT_PROVE` for LISTEN, SYN_SENT, TIME_WAIT, CLOSE_WAIT |
| 3 different remote | n03 | `CANNOT_PROVE` (Mismatch) |
| 4/5/6/19 wrong instance (pid, start, boot, exe) | n04… | never Match, never verified |
| 7 same label, different digest (port, family) | n07 | `CANNOT_PROVE` |
| 8 right digest, wrong kind (`Write`) | n08 | `CANNOT_PROVE`, action Unobservable |
| 9 agent-signed observer | n09 | `CANNOT_PROVE / ObserverKeyIsAgentKey` |
| 10 fabricated under Open | n10 | `CANNOT_PROVE / ProvenanceUnverifiedOpenPolicy` |
| 11/18 other decision, no claim | n11 | `CANNOT_PROVE` |
| 12 unprovisioned mechanism | n12 | refused at attestation (`MechanismNotProvisioned`) |
| 13 counted loss | n13 | `CANNOT_PROVE / ObserverDegraded` |
| 14 restart | n14 | `CONTINUITY_FAILURE` |
| 15 mutation of 12 signed fields | n15 | `SENSOR_INTEGRITY_FAILURE / Proven` each |
| 16 digest domain separation | n16 | other domains / no domain never reproduce it; tuple injective |
| 17 other agent | n17 | `CANNOT_PROVE` |
| 20 batch before / straddling the window | n20 | `CANNOT_PROVE`, `OutsideWindow` |
| — caller cannot assert | `caller_cannot_assert_…` | no verdict field in the record; stranger-signed health is an integrity failure |

## Live demonstration (`ghost-demo`, this host)

Real child process, real TCP connection to a real listener, binding collected
from procfs, real decision point, real socket table read under pidfd, real
collector, real engine. In one process — labelled `NOT_PRODUCTION_CAPABILITY`
because production must separate those trust domains.

| Scenario | Result | Strength | Reason |
|---|---|---|---|
| authorized connection made | **`VERIFIED_EXECUTION`** | `Attested` | `ActionEvidenceMatches`, action `Match(ProcNetTable)` |
| A expected, not executed | `CANNOT_PROVE` | — | `ActionEvidenceUnavailable` (instance seen; never `PHANTOM_CLAIM`: polled) |
| B executed, not expected | `CANNOT_PROVE` | — | `ExpectedSideCompletenessUnknown` (never `UNATTRIBUTED_EFFECT`) |
| C different parameters | `CANNOT_PROVE` | — | `ActionEvidenceDoesNotMatch`, action `Mismatch` |
| D wrong instance, same binary | `IDENTITY_DIVERGENCE` | `Attested` | `IdentityDiverged` |
| E counted loss | `CANNOT_PROVE` | — | `ObserverDegraded` |
| F replayed for another decision | `CANNOT_PROVE` | — | `ActionEvidenceUnclaimed`, `replay_detected` |
| G tampered attested batch | `SENSOR_INTEGRITY_FAILURE` | `Proven` | `ObserverSignatureInvalid` |

`cargo test -p ghost-demo` (8 live tests) and `cargo run -p ghost-demo --bin
ghost-demo` reproduce this. The positive record carries `availability:
Unavailable { WindowNotCovered }` — honest: the action was observed inside the
window; the window as a whole was not covered.

## Test results

| Suite | Before Stage 7 | After |
|---|---|---|
| aip-standalone `cargo test --workspace` | 454 / 0 / 3 ignored | **486 / 0 / 3 ignored** |
| aip-service `cargo test` | 39 / 0 | 39 / 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` (both) | clean | clean |
| `cargo fmt --all --check` (both) | clean | clean |

Added: aip-authorize +3 unit; aip-reconcile +19 (`action_evidence`) +2 unit;
ghost-demo +8 live. Unchanged and passing: Skill 3 (`aip-core` 141,
`aip-protocol` 26+26+9+6), Skill 4 (`aip-real-tests` 67, binding tests), Skill
5 (`aip-authorize` adversarial 32), Skill 6/6.5 (`aip-observe` 22+4+6+36+9),
Skill 7 (`adversarial` 30, `corrective` 9), `aip-test` 16. No assertion in any
predecessor suite was modified.

## What was proven

- For the one observable class, an honest, complete evidence set yields
  `VERIFIED_EXECUTION` at `Attested`, and each of the twenty adversarial
  variations plus the seven live negatives does not.
- The positive result cannot be supplied by a caller: no verdict field, sealed
  action variants with crate-private constructors, one derivation site, and a
  central guard.
- Every signed field of the evidence is mutation-detected at `Proven`.
- The parameter digest is domain-separated and injective in the tuple.
- The claim never produces evidence; it only ties evidence to a decision.

## What was not proven (CANNOT_PROVE)

- Any action other than an established TCP connection; any `Standard(Action)`.
- Payload, bytes, request content, application parameters.
- When the connection was created; whether it pre-dates the authorization;
  whether one connection served two overlapping decisions.
- Truth of socket-table content on a root-compromised host — hence the
  permanent `Attested` cap.
- Non-execution from the absence of a connection in a polled table.
- Anything under `ProbePolicy::Open`; independence without the agent key.

## Architectural risks

1. **Polled table, not events.** A connection that opens and closes between
   two polls is invisible; a long-lived connection is visible across many
   windows. Verification therefore says "existed during", never "was made
   during". Closing this needs the kernel-pushed socket-state primitive.
2. **Root-forgeable content.** Same as identity (Skill 6 A4); the collector's
   provenance regime is the only defence, and it bounds labels, not content.
3. **Demonstrator trust collapse.** `ghost-demo` runs DP, collector and
   verifier in one process; it demonstrates the pipeline, not the trust
   separation. Anyone reading its output as a production result would be
   wrong, and the crate says so in its first line.
4. **Vocabulary coupling.** A decision-point caller that encodes the same
   endpoint any other way will never match. `net_connect_parameters` is the
   only sanctioned encoder.
5. Unchanged from Skill 7: withheld future evidence, unsigned reconciliation
   records, verifier-dependent independence checks.

## Evidence still missing for a general `VERIFIED_EXECUTION`

An independent, instance-bound sensor for the action itself — for anything
that is not a socket tuple, that means an effect source that sees the
operation (syscall, file, exec argument, request) and binds it to the
instance without trusting the host. None exists in this repository.

## Gate

Action-level evidence exists for one class, is adversarially tested, and is
live-demonstrated. Skill 8 (warrant) was not started and is **not**
authorized by this report; whether it may begin is a separate decision that
should weigh that `VERIFIED_EXECUTION` currently means one thing only.
