# SNIFFER DOG — PR #3 HARVEST REPORT

Final report for the mandate "PR #3 / ot-sentinel harvest and main
integration". Ground truth, inventory and dispositions are in
`OT_SENTINEL_HARVEST_AUDIT.md`; this report records what was done with them.
Branch `claude/codebase-production-readiness-wm6idp`; the branch's own
predecessor stages are summarised in `CURRENT_SYSTEM.md` §8.

## 1. What PR #3 contained

One commit, `6cc439f`, importing `orbitaltrust-accountability/` (116 files,
35 673 lines) from the ASC-space repository (source commit `af2f4d9`) beside
— not into — `aip-standalone/`. Four Rust crates (`ot-accountability-core`,
`ot-sentinel`, `ot-mcp-gateway`, `ot-verifier`), a TypeScript console
(identity, ledger, NEXORA anchors, UI), a Python seal checker, two documents.
No kernel code, no eBPF, no XDP, no cgroup, no packet capture anywhere in it.
Twelve capabilities HEAD did not have (audit §C), of which the sentinel's
restart-continuity audit, its two-axis response policy, its application-log
sensors with stream attestation, the delegation-graph resolution shape, the
authority journal and the governed gateway are the substantive ones.

## 2. What was previously hidden or unmerged

Everything in §1 was unmerged and, per I17, not capability. Two things were
hidden in the sense that HEAD's documents said or implied they did not exist
anywhere: a worked two-axis response policy with proof-gated containment and
protected subjects (`response.rs`), and a four-way restart-continuity audit
of an observer against its own archive (`state.rs`). Both are now design
lineage for code in HEAD. The forty-row matrix in the audit marks every other
EXISTING-UNMERGED item (application-log effects and observed parameter
digests, gateway, authority journal, NEXORA anchors, unattributed-effect
reachability, `--strict-continuity` runtime discipline).

## 3. What was harvested into main (this branch)

| Capability | Source (PR #3) | Landed as | Commits | Tests |
|---|---|---|---|---|
| Two-axis response policy, proof-gated, advisory default, protected subjects | `rust/ot-sentinel/src/response.rs`, `finding.rs` @ `6cc439f` | `aip-warrant` (Skill 8): `Severity` × `EvidenceStrength`, `ResponseClass`, `WarrantPolicy`, signed `Warrant` | `b433f24` RED, `9574420` GREEN, `54984f2` report | 19 (w01–w19) |
| Restart continuity: snapshot, archive comparison, Amnesia / RolledBack / Forked / ArchiveTruncated, foreign-state refusal | `rust/ot-sentinel/src/state.rs`, `patrol.rs` (`resume`, `snapshot`, `audit_continuity`) @ `6cc439f` | `aip-observe`: `CollectorSnapshot`, `CollectorSigner::snapshot/resume`, `verify_continuity`, `ContinuityBreak`, `ObserverLedger::resume_at/quarantine` | `df36270` RED, `9db6326` GREEN, `1dd12c7` docs | 8 (rc01–rc08) |
| Delegation path resolution shape (walk child → root, whole path, effective scope) | `rust/ot-accountability-core/src/authority.rs` @ `6cc439f` | `aip-agent::graph::DelegationGraph` (Sniffer Dog 2.0 Phase D), over Ed25519-signed token chains | `2bdf49c` RED, `f96e51a` GREEN | 11 (d01–d11) |
| Lineage has a kind and an actor; edges need both ends; far-end attribution is separate | `lifecycle.rs`, `observation.rs` (`Subject::Claimed/Anonymous`) | `aip-agent::lineage`, `aip_reconcile::LineageEdge` (Phase C1) | `83bee50` RED, `07328c9` GREEN | 16 |

Every harvest is a **re-implementation over this repository's types and
signatures**, not a copy: PR #3's types (three-level strength, string DIDs,
JSON hash chains, HMAC/ML-DSA) are not this repository's and would have
introduced a second model (I18, I14). No file from
`orbitaltrust-accountability/` was merged.

## 4. What was intentionally rejected

| Item | Reason (audit §M / Phase 3) |
|---|---|
| second identity/authority/evidence model (DIDs, unsigned edges with a verifier that returns `true`, JSON hash chains) | I18, I14; main's signed tokens and canonical encoder are stronger |
| unsigned lifecycle anchors with an `actorDid` string as the actor | an unsigned actor is a claim; recorded as design input for the identity-authority decision |
| reconciliation keyed on `(tool, params_digest, agent, ±30 s)` and `phantom` from a declared tool list | I2, I8; main keys on `decision_id` + structural binding and recomputes coverage |
| `unattributed` inferred from absence in the sentinel's own ledger | I8; main requires a signed completeness statement from the decision point |
| log-tail sensors as evidence now | attribution is whatever the log writer wrote; root-forgeable; would need its own decision document, a `Correlated` ceiling and an observer protocol bump (Phase H) |
| gateway (`ot-mcp-gateway`) | unbuildable here (`ot-pqc` absent); its own evidence model; harvested only as the decision point's deployment shape |
| actuation (authority revocation inside the detector loop), `Quarantine`/`Terminate` responses | stage order: containment is Skill 9 and is not started |
| ML-DSA / Kyber / PQC stamps | I7; unimplemented here and prohibited as a claim |
| codex `aegis-quantum` eBPF/XDP, circuit breaker, benchmarks | telemetry with no process identity (I2); containment prototype (I13); performance figures not reproducible |
| statistical detectors (liveness, probing, model drift) | heuristic; Skill 8 already caps Heuristic at Alert; no evidence class in HEAD produces them |

## 5. What main already did better

Kernel-pushed observation with pidfd-anchored process identity and image
content hashes (PR #3: file tails with string subjects); an off-host collector
key (PR #3: sentinel on the observed host); `decision_id` + structural-binding
reconciliation with recomputed coverage (PR #3: digest/time correlation with a
declared list); four-level evidence strength with `Attested` as the honest
ceiling for host facts (PR #3: three levels, no attested tier); injective
binary canonical encoding with domain tags (PR #3: canonical JSON); signed
delegation chains with attenuation and expiry verified per hop (PR #3: edges
accepted by a verifier returning `true`); an independent decision point (PR
#3: the agent-side funnel). PR #3 also could not be built or tested here
beyond 138 library tests.

## 6. Exact commit SHAs sourced from PR #3

Source: `6cc439f190161ba28e76d46cea1901de8dd527ea` (the only commit on
`origin/import/orbitaltrust-accountability-layer`), files
`orbitaltrust-accountability/rust/ot-sentinel/src/{response.rs, finding.rs,
state.rs, patrol.rs, observation.rs}`,
`orbitaltrust-accountability/rust/ot-accountability-core/src/{authority.rs,
lifecycle.rs}`. Upstream provenance recorded in the import's `MANIFEST.md`:
ASC-space `af2f4d965eb13aae89b96e6a10f72ff671de969a`. Each harvesting commit
names its source in its message.

## 7. Test count before / after

| Suite | Before this mandate (`54984f2`, after Skill 8) | Before Sniffer Dog 2.0 (`de9a6bc`) | After (`1dd12c7`) |
|---|---|---|---|
| aip-standalone `cargo test --workspace` | 613 passed / 0 / 3 ignored | 548 / 0 / 3 | **621 / 0 / 3** |
| aip-service `cargo test` | 39 / 0 | 39 / 0 | **39 / 0** |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean | clean | **clean** |
| `cargo fmt --all -- --check` | clean | clean | **clean** |

The 73 tests added since `de9a6bc`: 39 `aip-agent`, 7 reconciler lineage
edges, 19 `aip-warrant`, 8 collector restart continuity. Every earlier test
is unchanged except fixture literals and two placeholder pins replaced by the
real sections they stood for, each documented in the phase report.

## 8. Live-test results

Environment: Linux 6.18.44, this container, uid 0, tracefs mounted by hand
(`mount -t tracefs nodev /sys/kernel/tracing`), `perf_event_paranoid = 2`.
Label: **live kernel** — real processes, real `perf_event_open` rings, real
TCP connections, real `/proc`. Not hardware-attested, not production.

| Suite | Result |
|---|---|
| `ghost-demo/tests/live.rs` (positive, A–G) | 8 passed, 0 skipped |
| `ghost-demo/tests/live_transition.rs` (T-A, T-C, T-P) | 5 passed, 0 skipped |
| `ghost-demo/tests/live_exec.rs` (X-P, X-A, X-B, X-C) | 8 passed, 0 skipped |
| `ghost-demo` binary, all fifteen scenarios | ran; T-C and T-P `VERIFIED_EXECUTION · Attested · Match(SockStateTracepoint, Transition)`; X-P `VERIFIED_EXECUTION · Attested · Match(SchedTracepoint, Transition)`; X-A `CANNOT_PROVE · ActionEvidenceDoesNotMatch`; X-B `CANNOT_PROVE · AmbiguousObservations`; X-C `CANNOT_PROVE · ActionPrecedesAuthorization · BeforeWindow` |

Mapping to the mandate's Phase 7 list: (1) real child creation/execution —
X-P; (2) real authorized execution — positive, T-P, X-P; (3) wrong binary —
X-A; (4) pre-authorization — T-A, X-C; (5) competing-instance ambiguity —
X-B; (6) real TCP observation — positive, T-C, T-P; (7) event-loss accounting
— live test E and `t15_live_kernel_event_loss_is_signalled_and_degrades_coverage`
(fixture-driven loss on the live connector); (8) lineage observation — the
X-P fork/exec pair is the kernel evidence `derive_lineage_edges` consumes
(edge derivation itself is fixture-tested, le01–le07; not yet exercised in
the demo binary); (9) observer provenance — every scenario runs under
`RegisteredOnly` with mechanisms in the signed health; (10) reboot/restart
continuity — **fixture-tested only** (rc01–rc08); no live restart scenario
exists in the demo binary. PR #3's own restart scenarios could not be run.

Reproduced from PR #3 (label: **integration, scratch workspace**):
`ot-accountability-core` 56/0, `ot-sentinel --lib` 82/0; `ghost_hunt`,
gateway and verifier do not build without `ot-pqc`.

Observed in the demo output and recorded as-is: `VERIFIED_EXECUTION` records
carry `availability = Unavailable { WindowNotCovered }` because the polling
epoch's coverage window does not span the action window while the action
itself is verified through kernel-pushed transition evidence inside attested
batch coverage. The two fields describe different things (health coverage
epoch vs. per-action batch coverage); nothing is inferred from the health gap.

## 9. Adversarial matrix A–Y

Each row names an existing test that establishes the property; "added" marks
tests written under this mandate or the Sniffer Dog 2.0 phases.

| # | Case | Result required | Evidence |
|---|---|---|---|
| A | unauthorized execution | `CANNOT_PROVE` (no `UNATTRIBUTED_EFFECT` without DP completeness) | live `b_executed_but_not_expected_is_cannot_prove`; `t05_unattributed_effect_requires_a_signed_complete_expected_side`; `t05b_unclaimed_observation_is_never_unattributed_effect` |
| B | execution before authorization | `ActionPrecedesAuthorization`, `BeforeWindow` | `tp02`, `tp03`, `xe08`, live `t_a_*`, `x_c_*` |
| C | wrong executable | mismatch on content, never verified | `xe02` (path never enters the digest), live `x_a_*` |
| D | wrong parameters | `ActionEvidenceDoesNotMatch` | live `c_different_parameters_*`; `tp*` endpoint mismatch |
| E | PID reuse | never transfers identity | `t07`, `t08`, `xe04`, `le05` (added), `pid_reuse_cannot_transfer_an_observation` |
| F | ambiguous competing processes | `AmbiguousObservations`, never a verdict | `t06b`, `xe07`, `tp10`, live `x_b_*`; `ChildAttribution::Ambiguous` (l05, added) |
| G | forged observed evidence | `SENSOR_INTEGRITY_FAILURE · Proven` or refused | `t13`, `xe12`, `t15b`, live `g_tampered_*`; rc07 (forged archive records ignored, added) |
| H | forged expected execution | rejected by anchors / key checks | `test_h_agent_key_under_a_fake_decision_point_id_is_not_trusted`, `self_issued_root_authority_is_denied_*`; p12 (added) |
| I | forged lineage | refused | l03 `Refused` (added); le03/le04/le07 (added) |
| J | fake parent agent | claimed ≠ endorsed; proof against genuine parent refused | l02, l03 (added) |
| K | fake child agent | child attributed only through a DP-signed peer expectation | l05, l06, l08 (added) |
| L | delegation transplantation | chain refused / not this agent's | `test_binding_transplant_detected_by_hash_and_signature`, `binding_for_another_agent_*`, p07 `LeafNotAgent` (added), d05 (added) |
| M | observer key compromise assumptions | stated, not solved | `r7_observer_key_equal_to_the_agent_key_is_never_independent_evidence`; `t17` (`steal the collector key` remains an open risk in `SNIFFER_DOG.md` §8) |
| N | observer silence | `CANNOT_PROVE`, never phantom | live `a_expected_but_not_executed_*`, `t22`, `collector_partition_produces_unavailability_not_a_verdict` |
| O | observation loss | degrades, blocks verification | `n13`, `t15`, `t15b`, `tp17`, `xe14`, live `e_lost_observation_*` |
| P | sensor degradation | `CANNOT_PROVE`; warrant never above Alert | `t14_t18`, `t17`, `t17b`; w04, w05 (added) |
| Q | phantom claim | only with recomputed lifecycle coverage | `t02`, `t03`, `r1`, `r2`, `r5`, `tp21`, `xe15` |
| R | unattributed effect | only with a DP completeness statement | `t05`, `t05b` |
| S | ledger tampering | `Proven` integrity failure | `t13`, `t15b`; `test_bundle_tampered_content_detected` |
| T | continuity break | `CONTINUITY_FAILURE`; collector fork quarantined | `t17`, `t04_t05`, `sequence_rollback_is_refused_and_a_fork_quarantines`; rc04 (added) |
| U | reboot / restart | `Recovering`/`Unverified`; amnesia, rollback, fork, truncation classified | `r5`, `stale_state_restoration_cannot_reconstruct_continuity`, `xe14`; rc01–rc08 (added) |
| V | timestamp manipulation | anchor is a claim; collector clock decides "before"; unanchored is unanchored | `tp03`, `tp04`, `xe09`, `le04` (added); nonce-tracker timestamp tests |
| W | network evidence mismatch | mismatch or precedes | `tp19`, live `c_*`, `t_a_*` |
| X | duplicate attribution | ambiguity reported | `t06b`, l05 `Ambiguous` (added) |
| Y | cross-agent evidence transplantation | never verifies another decision | `n11_n18_evidence_claimed_under_another_decision_does_not_verify_this_one`, `tp12`, `xe10`, live `f_replayed_evidence_does_not_verify_another_decision`; p13 (added) |

For every positive verdict the trust root is: the decision point's Ed25519
key (anchored by the verifier) over the expectation, plus the collector's
Ed25519 key (anchored by the verifier) over kernel-pushed events whose
subject was pidfd-anchored by the probe, joined on `decision_id` and the
structural binding. Nothing else produces a positive.

## 10. Remaining gaps

Containment (Skill 9); NEXORA and any Merkle commitment (Skill 10); signed
reconciliation records and warrants persistence; experience ledger, history,
profile API (2.0 Phases E–G); `LINEAGE_VIOLATION` reachability (Phase C2);
decision-point completeness statements (`UNATTRIBUTED_EFFECT` in production);
application-layer effect sensors (Phase H decision document); file, DNS,
credential and IPC action classes; identity issuer and lifecycle authority
(NOT DETERMINED); revocation truth (`aip-service` P1 gap); durable storage
and separate-process deployment of collector and decision point; live restart
scenario in the demonstrator; key lifecycle for every authority.

## 11. Claims that are now PROVEN (mechanically recomputable)

- A collector batch or health record altered after signing is detected
  (`SENSOR_INTEGRITY_FAILURE · Proven`).
- A forked collector chain (two heads at one sequence under one key), at the
  verifier or at collector resume, is detected.
- A warrant altered in any security field after signing is detected.
- An expectation or token altered after signing is detected.

## 12. Claims that are only ATTESTED

- An authorized process instance established an authorized TCP connection,
  or executed an image of the authorized content, inside its window.
- An authorized action was not executed while the observer had recomputed
  process-lifecycle coverage (`PHANTOM_CLAIM`).
- A different instance acted under an agent's authorization
  (`IDENTITY_DIVERGENCE`).
- A collector's continuity state (Recovering / Unverified / Degraded).
- Identity lineage endorsed by a parent's key; authority paths; observed
  spawn relations with peer attribution.

All rest on host-read facts a root attacker can fabricate or suppress, signed
by an off-host collector: `Attested`, never `Proven`.

## 13. Claims that remain ARCHITECTURAL TARGETS

Kernel-boundary payload or argument visibility (I23 says never from the
kernel); eBPF or packet-level observation; automatic isolation of any kind;
"zero false outages"; a Merkle-committed, externally anchored ledger;
unattributed-effect detection in production; an application-log effect
class; reboot continuity demonstrated live; PQC anything; performance,
line-rate or overhead figures; TRL.

## SNIFFER DOG STATUS

- [ ] NOT READY
- [x] **PARTIALLY INTEGRATED**
- [ ] INTEGRATED — VALIDATED CORE
- [ ] INTEGRATED — PRODUCTION HARDENING
- [ ] PRODUCTION READY

Why not "validated core": the specification's observation surface
(filesystem, packet, application logs), its ledger (Merkle commitment), and
its response path (containment) are absent from HEAD and from PR #3 alike;
the reconciler's positive results are `Attested`, not `Proven`; restart
continuity is fixture-tested, not live-tested. Why not "not ready": every
gate from AIP correctness through the warrant engine is implemented and
adversarially tested, two action classes verify live on a real kernel, and
the PR #3 material that passed the gates is in.
