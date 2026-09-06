# GAP_MATRIX

Discovered at commit `377d5fc`. Priorities per skill §21:
**P0** security correctness · **P1** architectural dependency ·
**P2** production hardening · **P3** performance · **P4** research.

Status updates (rows marked **CLOSED** / **PARTIAL** below keep their
original discovery text for traceability):

- Stage 0 (Skill 3) closed at `830c1e5`…`f78a599` — see
  `AIP_CORRECTNESS_REPORT.md`.
- Stage 1 (Skill 4) closed at `4ff1f5c` — see
  `EXECUTION_BINDING_IMPLEMENTATION_REPORT.md`.
- Stage 2 (Skill 5) — library decision point `aip-authorize`; see
  `DECISION_POINT_IMPLEMENTATION_REPORT.md`.
- Stage 3 (Skill 6) — observer/collector split `aip-observe`; see
  `OBSERVER_IMPLEMENTATION_REPORT.md`.
- Stage 6.5 (Sniffer Dog) — kernel-mediated sources and provenance gating in
  `aip-observe` (protocol v2); see `SNIFFER_DOG.md` and
  `SNIFFER_DOG_IMPLEMENTATION_REPORT.md`.
- PR3 corrective review — see `PR3_GAP_REVIEW.md`; three MUST-FIX items
  closed (section D below); reconciliation readiness decided.
- Stage 4 (Skill 7) at `ad9642a`, corrected at `6b2f5c7` (RED) / `b821a23`
  (GREEN) — reconciler `aip-reconcile`, `CANNOT_PROVE` default, five of eight
  result classes reachable; the corrective pass makes the reconciler
  re-derive coverage from the attested batches instead of trusting the
  collector's derived fields. See `RECONCILIATION_IMPLEMENTATION_REPORT.md`.
- Stage 7 (action-level evidence) at `44ed9b5` (RED) / `63c5e0a` (GREEN) plus
  the `ghost-demo` live demonstrator — `VERIFIED_EXECUTION` reachable for one
  action class (established TCP connection), `Attested`, live-demonstrated;
  see `ACTION_EVIDENCE.md` and `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md`.
- Stage 7b (kernel-pushed socket-state transitions) at `ed9c75b` (RED) and
  the following implementation commit — `sock:inet_sock_set_state` via
  `perf_event_open`, no eBPF; connection *creation* is now evidence,
  distinguished from presence; observer protocol v4, record v3. See
  `ACTION_EVIDENCE.md` §14 and `SNIFFER_DOG_IMPLEMENTATION_REPORT.md` §23.
- Stage 7c (process execution as action evidence) at `a5e2cbf` (decision +
  RED) / `1d52f93` (GREEN) — `sched:sched_process_fork` +
  `sched:sched_process_exec` via `perf_event_open`, no eBPF; a second action
  class, `ghost.process.exec.v1` (image **content** hash), `VERIFIED_EXECUTION`
  at `Attested`, live-demonstrated X-P/X-A/X-B/X-C; observer protocol v5;
  the Stage 7b perf clock defect found and fixed. See
  `NEXT_ACTION_EVIDENCE_DECISION.md`, `ACTION_EVIDENCE.md` §15 and
  `SNIFFER_DOG_IMPLEMENTATION_REPORT.md` §24.
- Sniffer Dog 2.0 (agent identity / profile / lineage / passport / ledger /
  history / evidence graph / API) — **DESIGN_ONLY**, specified in
  `SNIFFER_DOG_2_0_SPECIFICATION.md` with each component SD-01…SD-13
  classified against this matrix and Skills 3–8. No code. Five decisions
  recorded as NOT DETERMINED (§8 there) block the identity-lifecycle and
  agent-lineage parts.
- Sniffer Dog 2.0 Phase A/B — `SNIFFER_DOG_2_0_GAP_MATRIX.md` (inventory;
  finds the unwired `AgentIdentityDocument`, its parent-signed lineage proof,
  its unsigned lifecycle and the experimental reputation scorer) and the new
  crate `aip-agent`: validated identity, authority projection under the
  decision point's rules, dimension-separated profile view with no summary
  field. No new key or authority. See `SNIFFER_DOG_2_0_IMPLEMENTATION_REPORT.md`.
- Sniffer Dog 2.0 Phase C1 — `LineageEdge` / `derive_lineage_edges` in
  `aip-reconcile` (both ends bound, start verified, no agent identity) and a
  three-kind lineage section on the profile (identity from proofs across
  generations, authority paths, observed spawns with peer-expectation
  attribution); no reconciled lineage verdict yet (C2 after Phase D).
  `OUT_OF_TREE_HARVEST_REVIEW.md` classifies every branch and PR capability;
  none merged.
- Sniffer Dog 2.0 Phase D — `aip_agent::graph::DelegationGraph`: paths,
  outgoing delegations, agents-under, authority-reaching over chains verified
  whole by `aip_core`; dangling hops reported, verifier-supplied revocation
  set consumed; no new authority.
- Skill 8 (warrant engine) — `aip-warrant`: typed response gated on
  `Proven` evidence by an explicit match, advisory default, protected
  identities, signed warrant under `SYNTRIASS/GHOST/WARRANT/v1`; see
  `WARRANT_IMPLEMENTATION_REPORT.md`. Design lineage PR #3 `response.rs`.
- PR #3 harvest — `OT_SENTINEL_HARVEST_AUDIT.md` (forensic inventory, 40-row
  matrix, dispositions) and the collector restart-continuity audit
  (`CollectorSigner::resume`, four-way `ContinuityBreak`) harvested from
  `ot-sentinel/state.rs`; see `SNIFFER_DOG_PR3_HARVEST_REPORT.md`.
- Phase C2 (Gate 1 of the completion mandate) — `LINEAGE_VIOLATION`
  reachable through `reconcile_lineage` on complete two-sided evidence;
  record v4 carries the lineage comparison. `RECONCILIATION_MODEL.md` "The
  lineage question".
- Gate 2 (wire-level observation) at `36b026c` (RED) / `57849bd` (GREEN) /
  `275c4e3` (observer protocol v6) —
  mechanisms evaluated on the host (`OBSERVATION_MODEL.md` §5); an
  `AF_PACKET` header tap (`WireTapAfPacket`: TCP/IP headers, payload
  *length*, kernel realtime stamp, `tp_drops` loss, no pid, no payload) is a
  seventh probe source; record v5 carries `wire: WireCorroboration`, the
  device layer's answer to a socket-transition verdict, informational only.
  Live-demonstrated. `RECONCILIATION_MODEL.md` "The wire question".
- Gate 3 (socket send, third action class) at `c830a8d` (RED) / `4e4bd6a`
  (GREEN) — `ghost.net.send.v1`: `sock:sock_send_length` in the sender's
  context through `perf_event_open` (`SockSendTracepoint`, observer protocol
  v7), endpoint resolved from the attested transitions of the same kernel
  socket, digest = the endpoint only, byte count as signed context, no
  payload digest; `SendSocketUnresolved`; the probe's per-instance image
  cache (a host-wide source must not re-hash every sender's executable per
  event). Live-demonstrated S-P/S-A. `ACTION_EVIDENCE.md` §16.
- Gate 4 (file write, fourth action class) at `4a5f716` (RED) / `2f1ba9b`
  (GREEN) — `ghost.fs.write.v1`: `fanotify` with `FAN_REPORT_PIDFD` on a
  marked mount (`Fanotify`, observer protocol v8); the writer bound by the
  pidfd the kernel created for it; digest = the path bytes; `(dev, ino)`
  as signed context; the five observation states OBSERVED / NOT OBSERVED /
  AMBIGUOUS / LOSS / UNAVAILABLE each pinned; `FilePathUnresolved`.
  Live-demonstrated F-P/F-A/F-N. `ACTION_EVIDENCE.md` §17,
  `OBSERVATION_MODEL.md` §6.
- Gate 5 (application / database / proxy sensors) — **DECIDED, NOT BUILT**:
  `APPLICATION_LOG_SENSOR_DECISION.md`; such records are writer statements,
  never observation; a supporting tier, if ever admitted, is capped at
  `Correlated` / `Claimed` and never counts as coverage. Fence pinned by
  g5a–g5d.
- Gate 6 (Merkle commitment layer) at `e8e42db` (RED) / `533e44b` (GREEN) —
  new crate `aip-nexora`, module `merkle`: domain-separated leaves, RFC 6962
  tree, inclusion and consistency proofs with verifiers, every adversarial
  case pinned (m01–m16). No signed head or anchor yet (Gate 7).
  `NEXORA_BOUNDARY.md` §4 rows 1–3 CLOSED.
- Gate 7 (NEXORA proof layer, Skill 10) at `b6868de` (RED) / `e405d96` (GREEN) — `aip-nexora::commitment`:
  signed heads chained under `SYNTRIASS/NEXORA/HEAD/v1`, proof objects, an
  offline verifier yielding where-and-what-digest only, a head tracker that
  refuses rollback, fork and broken chains, an anchoring interface. NEXORA
  is no longer MISSING; the anchor's externality and durable storage are
  deployment and follow-up. `NEXORA_BOUNDARY.md` Gate 7 note.
- Gate 8 (strict continuity runtime semantics) at `48b53b0` (RED) / `8a4b759` (GREEN) —
  `aip-observe::{store, runtime}`: durable collector state (atomic snapshot,
  append-only health archive and continuity reports), `CollectorRuntime`
  with `ContinuityPolicy::{Strict (default), Advisory}`, every AMNESIA /
  ROLLBACK / FORK / TRUNCATION a signed `ContinuityReport`, strict refusal
  of the first three, quarantine of a fork under both, and a real collector
  process restarted by `ghost-demo-collector`. `OBSERVER_IMPLEMENTATION_REPORT.md`
  limitation 5 closed; key custody and transport remain open.
- Gate 9 (containment boundary, Skill 9) at `c06e10b` (RED) / `272feac` (GREEN) —
  new crate `aip-containment`: seventeen gates between a signed warrant and an
  actuator, `Proven` required by explicit match, target attributed live through
  a held pidfd (pid reuse refused), advisory by default, protected identities
  exempt, replay consumed durably before actuation, failures fail open, every
  attempt a signed record under a third authority, and one closed action —
  a Linux cgroup v2 freeze, exercised against a real process (`live_freeze`
  f_p/f_a/f_b/f_c). `CONTAINMENT_IMPLEMENTATION_REPORT.md`;
  `CONTAINMENT_MODEL.md` §9.

## D. PR3 corrective review (pre-reconciliation)

| Component | Found | Fix | Pri |
|---|---|---|---|
| `wellknown::verify_delegation_with_jwks` — **CLOSED** | verified the signature envelope only; a hop with rewritten `expires_at`/scope/grantee still verified (the Skill 3 attack through a public verifier) | recomputes the hop payload via `delegation::verify_delegation_token_signature`, shared with `verify_delegation_chain` | **P0** |
| `verify_ed25519` algorithm label — **CLOSED** | accepted any `Signature.algorithm`; an Ed25519 signature labelled `MlDsa65`/`Hybrid` verified (**I7**) | refuses non-Ed25519 labels with `EvolutionRequired` | **P0** |
| Per-mechanism coverage in signed health — **CLOSED** (observer protocol v3) | health stated *that* a window was covered, not *by which source*; `PHANTOM_CLAIM` would have required inferring kernel coverage from event presence (**I8**) | `ObservationBatch.active_mechanisms` (declared ∪ used, registry-bounded), `SensorHealth.covered_by` (intersection over the epoch), `covered_by_kernel_pushed_source()` | **P0** |
| Cross-crate domain-tag audit | no single test saw all 16 tags | `aip-test/src/domain_audit.rs` | — |
| Identity digests not byte-comparable across crates | `ExecutionBinding::identity_bytes` ≠ `ObservedProcess::identity_bytes` by design | documented: compare structurally via `matches_process_of` | E |
| `[u8;16]` identifiers indistinguishable by type — **CLOSED at the reconciliation boundary (`b821a23`)** | `decision_id`, `batch_id`, `probe_run_id`, `jti`, … | `DecisionId`/`BatchId`/`ProbeRunId`/`ObserverId`/`ObserverSequence`/`DecisionPointId` used throughout `EvidenceRef` and `ObservationTarget`; upstream crates still use bare `[u8;16]` | D |

## A. AIP correctness (must precede any Ghost work)

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Token/delegation expiry integrity — **CLOSED `830c1e5`** | `expires_at` absent from both signing payloads (`capability.rs:208`, `delegation.rs:369`); read by R10 (`verification.rs:495,497`) | expiry covered by issuer signature | agent extends its own authority window; all 14 rules pass, `tampered=false` | none — fix pattern already exists at `aip-core/src/lib.rs:135-142` | **P0** |
| `aip-core` canonical encoding — **CLOSED `830c1e5`** (encoder relocated to `aip_types::canonical`) | non-injective; unprefixed string concat (`delegation.rs:381-382`) | length-prefixed via `aip-protocol/src/canonical.rs` | one signature valid for two distinct tokens (**I14**) | batch with expiry fix (one wire break) | **P0** |
| Domain separation — **PARTIAL `830c1e5`** (all `aip-core` payloads tagged; packet/action/receipt payloads deferred to next wire bump) | absent in every signed preimage (`aip-crypto:151-162`) | type tag per signed object | new Ghost types confusable with packets/tokens | canonical encoder | **P0** |
| Authorization decision point — **PARTIAL (Stage 2)**: `aip-authorize::DecisionPoint` implemented as a library authority boundary with its own key and configured issuer anchors; deployment as a separate process and `/v1/evidence/generate` integration remain open | **does not exist**; `/v1/evidence/generate` seals caller assertions using a caller-supplied private key (`evidence.rs:130,220-300`) | adjudicating decision point emitting signed `ExpectedExecution` | agent is sole authority for its own execution (**I1**) | expiry + encoder fixes | **P0** |
| Service verify trust anchors — **PARTIAL `f78a599`** (documented as calculator; type-level separation pending decision point) | caller supplies `trusted_issuers` (`evidence.rs:161,307-309`) | documented as calculator; never an authority | self-authorization loop if consumed as a decision (**I19**) | doc + type-level separation | **P0** |
| Packet replay | no seen-set; same packet verifies forever | explicit replay oracle in `VerificationContext` | replayed evidence indistinguishable | none | **P1** |
| Absolute expiry — **DECIDED `f78a599`: no wall clock** (R10 semantics are explicit and offline relative to signed timestamps; see `AIP_CORRECTNESS_REPORT.md` "Verification-time semantics") | R10 never consults a clock; `is_token_expired` uncalled | optional `ctx.verification_time` | expired-years-ago token verifies | expiry fix | **P1** |
| `aip-service` duplicate authority engine | unsigned tokens, no attenuation at issuance, no expiry check, different `Action` enum (`aip-service/src/{delegation,capability}.rs`) | deleted; route through `aip-core` | two security models; log write ⇒ privilege escalation (**I18**) | — | **P1** |
| Private keys at rest — **PARTIAL `228b02e`** (custom `Debug` redacts; `Serialize` kept for `store.rs`; plaintext at rest remains) | plaintext JSON, `Debug`+`Serialize` on `KeyPair` (`aip-types:25-30`, `store.rs:149-151`) | `serde(skip)`, custom `Debug`, 0600, zeroize | key disclosure | — | **P1** |
| `validate_aip_id` panic — **CLOSED `14da5a8`** | byte-index slice on `&str` (`aip-crypto:81-82`), reachable from JSON | char-boundary safe | authenticated request abort | — | **P1** |

## B. Ghost prerequisites

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| `ExpectedExecution` — **CLOSED (Stage 2)**: `aip-authorize::ExpectedExecution`, domain `GHOST/ExpectedExecution/v1`, signed `issued_at`/`valid_until`, embeds `ExecutionBinding`, offline-verifiable against `DecisionPointTrustAnchors` | **MISSING** (0 occurrences) | signed pre-execution authorization record | no "expected" side of reconciliation | decision point (P0) | **P0** |
| `ExecutionBinding` — **CLOSED `4ff1f5c`** as a self-reported, agent-signed binding in `EvidencePacket` (R15); independent attestation of it remains the Observer's gap | **MISSING**; `RuntimeBinding` is self-reported, unwired, path-hashed | agent ↔ process-instance binding in signed evidence | cannot attribute execution to an agent (**I2**) | canonical encoder, packet version bump | **P0** |
| Process instance identity — **CLOSED `4ff1f5c`** | `pid` only (`runtime.rs:40`); no start time, no boot id | `(pid, pid_start_time, boot_id)` | PID reuse transfers attribution (**I4**) | ExecutionBinding | **P0** |
| Executable identity — **CLOSED `4ff1f5c`** (contents of `/proc/<pid>/exe`) | `sha256(path_string)` (`runtime.rs:41-44`) | `sha256(binary contents)` | different binary, same path, same hash | ExecutionBinding | **P0** |
| Observer — **PARTIAL (Stage 3 → 6.5)**: keyless host probe with four provenance-tagged sources — procfs poll, pidfd-anchored instance reads, kernel netlink process-event connector (fork/exec/exit with kernel time; `ENOBUFS` loss surfaced), kernel socket tables (socket-level only). Stage 7b/7c added the `sock:inet_sock_set_state` and `sched:*` tracepoints through `perf_event_open`; Gate 2 added the `AF_PACKET` header tap (`WireTapAfPacket`, device layer, headers only). Still no eBPF or XDP; procfs *content* remains root-forgeable; polled sources still miss what happens between polls | **MISSING** (0 files: ebpf/XDP/perf_event/procfs/netlink) | independent runtime observer | no observation of any kind | binding + attestation | **P1** |
| `ObserverAttestation` — **CLOSED (Stage 3)**: anchor decided as *remote collector*; key held by `CollectorSigner`, structurally unreachable from host-side types; deployment as a separate process remains an operator obligation | **MISSING** | trust root not held by observed agent | observation would be a second self-report (**I10**) | anchor decision (open) | **P0** for design, **P1** to build |
| Sensor health / continuity — **CLOSED (Stage 3 → 6.5)**: five signed states, collector-side ledger with replay/fork/rollback/gap/head-mismatch faults; 6.5 adds probe run-id (restart), per-run sequence discontinuity and counted kernel event loss as explicit `Degraded` causes, and `probe_policy` in signed health; coverage never back-fills an outage, a loss, or a restart | **MISSING** | 5 explicit states, signed | silence indistinguishable from coverage (**I9**) | observer | **P1** |
| Reconciler — **PARTIAL (Stage 4, `ad9642a` + `b821a23`)**: `aip-reconcile` joins on `decision_id` + structural `ExecutionBinding` match, verifies both signatures and the observer chain up to the signed health head, defaults to `CANNOT_PROVE`; reachable: `PHANTOM_CLAIM` (`RegisteredOnly`, kernel-pushed signed coverage, **and** coverage re-derived from the batches as gap-free, single-probe-run, kernel-pushed, ending no later than the collector's signed clock), `IDENTITY_DIVERGENCE` (claim must name the expectation's agent), `SENSOR_INTEGRITY_FAILURE`, `CONTINUITY_FAILURE`, `CANNOT_PROVE`; `VERIFIED_EXECUTION` **for one action class only** (Stage 7: established TCP connection to an authorized `(protocol, remote_addr, remote_port)`, derived from pidfd-anchored socket-table observations, `Attested`, claim-tied, batch inside window and coverage epoch); **unreachable**: `VERIFIED_EXECUTION` for any other action kind (`ActionComparison::Match` needs a seal only the action-derivation step builds), `UNATTRIBUTED_EFFECT` (no producer for the DP completeness statement), `LINEAGE_VIOLATION` (refused by the central precondition guard) | **MISSING** (0 occurrences) | join on `decision_id` + binding | no comparison exists | both producers | **P1** |
| `OBSERVATION_UNAVAILABLE` semantics — **CLOSED (Stage 4)**: `ObservationAvailability::Unavailable{reason}` is carried unchanged in every `Reconciliation`; `ReconciliationResult::default()` is `CannotProve`; every `Unavailable` reason and every non-`Active` observer state yields `CANNOT_PROVE` or an explicit failure class, never `PHANTOM_CLAIM` | **MISSING** | first-class type, `CANNOT_PROVE` default | risk of inferring non-execution from silence (**I8**) | reconciler | **P0** for design |
| Warrant engine — **CLOSED (Skill 8, `9574420`)**: `aip-warrant`, containment requires `Proven` by explicit match, advisory default, protected identities, signed warrant. Containment — **CLOSED (Skill 9, `272feac`)**: `aip-containment`, seventeen gates, live-attributed target, cgroup v2 freeze, signed records | **MISSING** | severity ⊥ strength; `Proven` gate | containment on suspicion (**I12**, **I13**) | reconciler | **P1** |
| Containment | **MISSING** (correctly) | proof-gated, advisory default | — | warrant engine | **P2** |

## C. Commitment / NEXORA

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Merkle primitives | `merkle_leaf/internal/empty` correct, domain-separated | reused as-is | none | — | — |
| Merkle **protocol** | **MISSING** — helpers called only from a test | tree, root over real set, inclusion proof | no commitment exists (**I15**) | verified executions | **P2** |
| Production commitment roots | all `merkle_empty()` (`aip-core/src/lib.rs:62,63,647`) | populated | roots are the empty hash | Merkle protocol | **P2** |
| Chain head anchoring | **MISSING** | signed, externally anchorable head | truncation undetectable | commitment log | **P2** |
| Audit chain | in-memory, unsigned, **no caller** (`scoped_audit.rs:154-156`) | signed, persisted, head-anchored — or deleted | dead code claiming a security property | decision: promote or remove | **P1** |
| NEXORA | **MISSING** from production; unmerged on PR #3 | portable commitment boundary | — | all of the above | **P2** |

## D. Out-of-tree

| Component | State | Disposition |
|---|---|---|
| `ot-sentinel` / NEXORA (PR #3) | **UNMERGED**, tree absent from HEAD | design input only (**I17**). Its two-axis warrant and sensor-attestation designs are worth harvesting |
| `aegis-quantum` XDP (`codex/val-ladder-sync`) | **UNMERGED**, 29 ahead / 22 behind, tree absent | design input only. Observes inbound packets on a bare 4-tuple with **no process identity** — cannot attribute, so cannot feed reconciliation unmodified |
| `aip-core::simulation` | shipped in `aip-cli` despite "not for production" doc (`lib.rs:11-14`) | feature-gate | **P2** |

## E. Test coverage gaps blocking confidence

| Missing test | Why it matters | Pri |
|---|---|---|
| mutate `expires_at`, re-seal, assert rejection | the P0 defect is currently unprovable by the suite | **P0** |
| canonical encoder injectivity / collision vectors | `canonical.rs` has **zero** tests | **P0** |
| PID-reuse attribution refusal | **I4** | **P0** (with binding) |
| `OBSERVATION_UNAVAILABLE` never yields `PHANTOM_CLAIM` — **CLOSED (Stage 4)**: `adversarial.rs` t02, t02b, t03b, t03c, t11, t11b, t14_t18, t17, t22; `corrective.rs` r1–r5 add fabricated coverage (hole, future window, forged mechanism, restart, future-dated health) | **I8** | **P0** (with reconciler) |
| suspicion cannot reach containment | **I12/I13** | **P1** |
| service: cross-tenant HTTP 401/403, revoked-JTI rejection | single auth guard has zero coverage | **P1** |

## F. Skill 7 corrective pass (post-reconciliation)

RED evidence: `6b2f5c7` (six tests failing against `362695b`, no production
change). Fixes: `b821a23`.

| Finding | Found | Fix | Pri |
|---|---|---|---|
| Hole between probe-claimed windows read as coverage — **CLOSED** | the collector unions `claimed_from_ms`/`claimed_to_ms` without checking that they abut, so two far-apart batches spanned a window nothing sampled → `PHANTOM_CLAIM` (**I8**) | `recompute_coverage` sweeps the claimed intervals in order and requires gap-free cover → `CoverageGapInWindow` | **P0** |
| Coverage claimed beyond the collector's own clock — **CLOSED** | a probe could claim an unfinished window; "nothing happened in the next 60 s" was attestable one second in | the window must end at/before `health.emitted_at_ms` → `CoverageEndsAfterHealth` | **P0** |
| Future-dated health treated as fresh — **CLOSED** | `availability_for` bounds only *old* health; a forward-set clock saturated to age 0 | health after the verifier's own time → `HealthNotYetEmitted` | **P0** |
| Kernel provenance read from a derived field — **CLOSED** | `covered_by` trusted although the batches it derives from were in hand | intersection recomputed over the covering batches | **P1** |
| Probe restart inside the window invisible — **CLOSED** | `probe_run_id` present in the evidence, never checked by the reconciler | one run required across the covering batches → `CoverageProbeRunChanged` | **P1** |
| Divergence keyed on an unauthenticated claim — **CLOSED** | any process able to register a claim could attach itself to another agent's `decision_id` and produce `IDENTITY_DIVERGENCE` against them | the claim's `agent_id` must name the expectation's agent, else `IdentityComparison::ClaimInconsistent` → `CANNOT_PROVE` | **P1** |
| Observer/decision independence never checked (**I1**, **I10**) — **CLOSED (when the key is supplied)** | a self-signed "observer" using the agent's key produced `Attested` evidence and `PHANTOM_CLAIM` | `ReconciliationContext::agent_public_key`; `ObserverKeyIsAgentKey` / `ExpectedSelfAuthorization`, always `CANNOT_PROVE` | **P1** |
| Verifier misconfiguration reported as proven tampering — **CLOSED** | `Err(_)` catch-all sent a malformed anchor key to `SENSOR_INTEGRITY_FAILURE` at `Proven` | exhaustive classification; only signature/payload/signer failures are `Proven` | **P1** |
| No central precondition enforcement — **CLOSED** | preconditions lived only in the branch that proposed each class | `Draft::precondition_holds` choke point; failures become `CANNOT_PROVE` / `InvariantNotSatisfied` | **P1** |
| `VERIFIED_EXECUTION` unreachability was a comment — **CLOSED** | `ActionComparison::Match` was freely constructible | `ActionEvidenceSeal` (private field, no constructor) | **P2** |
| Declared-but-unused newtypes cited as a property (**I15**) — **CLOSED** | `BatchId`/`ProbeRunId` were dead code | used throughout `EvidenceRef`/`ObservationTarget`; `ProbeRunId` drives the probe-run check | **P2** |

Remaining, and **not** closable inside Skill 7 (see the implementation
report, "Unresolved architectural risks"): withheld *future* observer
evidence is bounded only by health freshness and needs an external anchor for
the observer head (NEXORA); probe sampling claims are not countersigned by
anything, which caps `PHANTOM_CLAIM` at `Attested`; attribution remains a
claim; the independence checks depend on the verifier supplying the agent's
public key; reconciliation records are unsigned and unstored.

## G. Stage 7 — action-level evidence

RED evidence: `44ed9b5` (positive path failing against `2c58771`). GREEN:
`63c5e0a`. Live demonstrator: `ghost-demo` crate.

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Observable action vocabulary — **CLOSED for one class** | `aip-authorize::actions`: `ghost.net.connect.v1`, `net_connect_parameters` (raw-byte, injective, domain `GHOST/ActionParameters/v1`) | every action a decision point may authorize has an observable definition | only network connections are observable | effect-level sensors | **P1** |
| Action interpretation — **CLOSED for one class** | `aip-reconcile::action::derive_action`: ESTABLISHED TCP/TCP6 `ProcNetTable` row → kind + recomputed digest; everything else → not evidence | one deterministic mapping per observable class | one class | sensors | **P1** |
| `VERIFIED_EXECUTION` — **PARTIAL** | reachable for `ghost.net.connect.v1` at `Attested`; sealed constructors, central guard, eleven predicates (`ACTION_EVIDENCE.md` §5); live-demonstrated | reachable for authorized actions generally | no action content for anything else | effect-level sensors | **P1** |
| Connection *creation* events — **CLOSED (Stage 7b)**: `SockStateTracepoint` (`sock:inet_sock_set_state` through `perf_event_open`, `CLOCK_MONOTONIC` event clock — corrected in Stage 7c, `PERF_RECORD_LOST`); `CLOSE → SYN_SENT` pidfd-anchored to the caller with the start-time rule, paired to `SYN_SENT → ESTABLISHED` by `sk`; `ActionEvidenceKind::Transition`; a transition attested before the decision is `ActionPrecedesAuthorization` and disqualifies presence of the same connection | **MISSING** — the table shows existence at the sample, not creation | kernel-pushed socket-state event bound to the instance | verification means "existed during", never "was made during" | perf tracepoint (no eBPF) | **P1** |
| Wall-clock placement of kernel events | **PARTIAL (Stage 7b)**: *before* is provable by the collector's signed `attested_at_ms`; *inside* rests on the probe's `clock_anchor` (host clock, a claim) | — | placement inside the window is `Attested`, never `Proven` | a trusted kernel↔collector time anchor | **P2** |
| PID reuse within one `CLK_TCK` tick | **open by design** | — | the start-time rule cannot exclude reuse inside 10 ms; pidfd anchor + exe hash narrow it | finer start-time source | **P2** |
| Root suppression of the perf ring | **open by design** | — | disabling/filtering/starving the ring removes the mechanism or degrades the window; never becomes silent coverage | evidence source outside host control | **P2** |
| Payload / application parameters | **MISSING** (I23: metadata only) | — | application-level `parameter_digest`s can never match | out of scope for any procfs source | **P2** |
| Root-forgeable table content | **open by design** | — | caps the class at `Attested` permanently | evidence source outside host control | **P2** |
| Live demonstrator trust separation | `ghost-demo` runs DP, collector and verifier in one process, labelled `NOT_PRODUCTION_CAPABILITY` | separate processes on separate trust | demonstrates the pipeline, not the separation | deployment | — |

### G.2 Stage 7c — process execution (second action class)

Decision: `NEXT_ACTION_EVIDENCE_DECISION.md`. RED: `a5e2cbf`. GREEN:
`1d52f93`. Live: `ghost-demo` scenarios X-P, X-A, X-B, X-C.

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Process execution as action evidence — **CLOSED (Stage 7c)** | `ghost.process.exec.v1` with `exe_sha256` (image **content**, `aip-authorize::process_exec_parameters`); `SchedTracepoint` (`sched_process_fork` in the parent's context + `sched_process_exec` in the child's, via `perf_event_open`, no eBPF); `derive_executions` pairs by `child_pid`, kernel-time order and the anchored child's start tick; `VERIFIED_EXECUTION · Attested · Transition`; kernel `filename` is context, never in the digest | **MISSING** — an agent that runs tools but opens no TCP connection is invisible to the action layer | what an agent *ran* is now matchable to what it was *authorized to run* | perf tracepoints, pidfd anchor, clock anchor | **P1** |
| Perf event clock — **CLOSED (defect found in Stage 7c)** | `use_clockid` at bit 25 with `CLOCK_MONOTONIC`; the tracepoint PMU rejects `BOOTTIME`/`REALTIME`/`TAI` (`EINVAL`, measured); anchor carries realtime, boottime, monotonic and `CLK_TCK`; start ticks converted through the boot−monotonic offset | Stage 7b set the flag at the wrong bit, so samples were on the PMU default clock while the docs said `CLOCK_BOOTTIME` (~237 ms skew vs start ticks on this host) | none remaining for this host; a suspend between anchor and event shifts the offset, hence per-batch re-anchoring | — | closed |
| Exec arguments / environment | **MISSING** | — | the kernel exposes `filename` only; `argv`/`envp` are not in either tracepoint; authorizations that depend on arguments can never match | a different source (out of scope) | **P2** |
| Exec chain faster than anchoring | **open by design** | — | a child that execs again or exits before the probe anchors it is unbound → `CANNOT_PROVE`, never guessed | — | **P2** |
| Sched stream as lifecycle coverage | **refused by design** (`xe15`) | — | fork/exec events say nothing about exits; `PHANTOM_CLAIM` still requires `ProcConnector` coverage | — | — |
| File create/modify class — **CLOSED for completed writes (Gate 4)**: `ghost.fs.write.v1` through `fanotify`/`FAN_REPORT_PIDFD`; creates / deletes / renames remain **MISSING** (`FAN_REPORT_FID` refused here) | observable file evidence bound to the instance | agent writes were invisible to the action layer | see G.4 | **P1** |
| DNS / outbound-generic / privileged / credential / IPC classes | **MISSING** (ranked; see decision §5) | — | not observable with the current sources | own reviews | **P2** |

### G.3 Gate 3 — socket send (third action class)

RED: `c830a8d`. GREEN: `4e4bd6a`. Live: `ghost-demo` scenarios S-P, S-A.

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Socket send as action evidence — **CLOSED (Gate 3)** | `ghost.net.send.v1`; `SockSendTracepoint` (`sock:sock_send_length` in the caller's context, via `perf_event_open`, no eBPF); `derive_sends` resolves the endpoint from the latest attested transition of the same `sk` not later than the send, refusing a socket closed in between; digest = `net_send_parameters(endpoint)`, equal to the connect digest by construction; `bytes` signed as context; `VERIFIED_EXECUTION · Attested · Transition` | — | receive side, UDP, non-TCP families, sends on sockets whose transitions were not observed | — | — |
| Payload digest | **permanently absent from the kernel path** (I23) | a party holding the plaintext (Gate 5 decision) | authorizations that depend on content can never match kernel evidence | — | **P2** |
| Host-wide source anchoring cost — **CLOSED (defect found in Gate 3)** | the probe re-hashed each sender's executable per event (215 MB daemon binary on this host); now one hash per (instance, image), revalidated by start tick, inode, size, mtime and path | — | in-place rewrite preserving all five defeats revalidation — a root capability, already the `Attested` ceiling | — | — |

### G.4 Gate 4 — file write (fourth action class)

RED: `4a5f716`. GREEN: `2f1ba9b`. Live: `ghost-demo` scenarios F-P, F-A, F-N.

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| File write as action evidence — **CLOSED (Gate 4)** | `ghost.fs.write.v1`; `Fanotify` (`FAN_CLOSE_WRITE` on a marked mount, `FAN_REPORT_PIDFD`); the writer bound through the kernel's own pidfd; `derive_file_writes`; digest = path bytes; `(dev, ino)` signed context; the five states pinned (`ACTION_EVIDENCE.md` §17.1) | — | content, unmarked mounts, writers gone before the read | — | — |
| Kernel-bound attribution | **stronger than the tracepoint classes**: the pidfd is created by the kernel from the event's own process reference; no pid-number window | extend to other sources where the kernel offers it | tracepoints still anchor by number under the start-tick rule | — | **P2** |
| File identity independent of path | **MISSING here** — `FAN_REPORT_FID` refused (`ENODEV`, zero fsid on this root filesystem) | object handle in the event | a path is a name; renames and mount namespaces can make the authorized and observed names differ | a filesystem with a fsid | **P2** |
| Creates, deletes, renames | **MISSING** (need `FAN_REPORT_FID` directory events) | — | only completed writes are observable | as above | **P2** |
| Event time | **weaker than the tracepoints**: fanotify carries no kernel timestamp; the probe stamps at read | — | placement rests on read cadence plus the anchor | — | **P2** |
