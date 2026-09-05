# ACTION_EVIDENCE

Stage 7 (action-level evidence) — the layer that lets one authorized action be
independently observed and cryptographically matched against its
`ExpectedExecution`, so that `VERIFIED_EXECUTION` becomes reachable for that
action and for nothing else.

> **Status: PARTIALLY_IMPLEMENTED — one action class.** Implemented and
> live-demonstrated for `ghost.net.connect.v1` (an established TCP connection
> to a remote endpoint). Every other action kind remains unobservable and
> reconciles to `CANNOT_PROVE`. Strength is `Attested`, never `Proven`. See
> `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md` for the evidence trail.

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
that a connection **existed at the sample**, not when it was created; a
connection that pre-dates the authorization window and is still open inside
it will verify. Connection-creation events are `NOT_IMPLEMENTED`
(`SNIFFER_DOG.md` §9).

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
- When a connection was created; whether it pre-dates the window; whether
  one connection served two decisions.
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

## 12. The missing kernel primitive

Stronger action evidence than a polled table needs a **kernel-pushed
socket-state event** bound to the process instance — on Linux a tracepoint on
`inet_sock_set_state` (or the `sock_diag`/`INET_DIAG_DESTROY` netlink
family) read from user space, which requires an eBPF or tracing loader this
repository does not have and does not claim. Until then, the class stays
socket-level, polled and `Attested`.

## 13. NOT_IMPLEMENTED / NOT_PROVEN

eBPF, XDP, tracepoints, packet or wire capture, filesystem or syscall
observation, exec-argument capture, connection-creation events, payload
digests, UDP actions, any second action class, zero loss, root-compromise
resistance, warrant or containment logic, TRL, latency, throughput, hardware
validation.
