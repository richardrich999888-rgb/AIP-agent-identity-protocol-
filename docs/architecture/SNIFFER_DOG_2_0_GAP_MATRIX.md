# SNIFFER DOG 2.0 — IMPLEMENTATION GAP MATRIX (Phase A)

Produced before any production code change for the Sniffer Dog 2.0
implementation programme. Companion to `SNIFFER_DOG_2_0_SPECIFICATION.md`
(the architecture) and `GAP_MATRIX.md` (the Ghost-programme matrix, which
this document does not replace).

## A.1 Baseline

| Item | Value |
|---|---|
| Commit | `de9a6bc` (branch `claude/codebase-production-readiness-wm6idp`) |
| Toolchain | rustc / cargo 1.94.1 |
| Host | Linux 6.18.44, uid 0, `perf_event_paranoid = 2`, tracefs **not mounted by default** — mounted by hand for the baseline so the live tests run |
| `aip-standalone` `cargo test --workspace` | see A.1a |
| `aip-service` `cargo test` | see A.1a |

### A.1a Baseline test results

Filled from the run at this commit (no code changed since `1d52f93`):

| Workspace | Passed | Failed | Ignored |
|---|---|---|---|
| aip-standalone | 548 | 0 | 3 |
| aip-service | 39 | 0 | 0 |

## A.2 Governing gate

**No installed skill is written for Sniffer Dog 2.0 phases B–G.** The
installed skills cover Stages 0–10 of the Ghost programme (`syntriass-*`),
the Ghost architecture review (`ghost-architecture-engineer`), the programme
orchestrator, the protocol change guard and service hardening. Therefore:

| Rule set | Applies to Phase B | How |
|---|---|---|
| `ghost-architecture-orchestrator` §2 invariants, §5 dependency gate, §6 change discipline, §8–9 crypto/domain rules, §14 adversarial tests, §15 status report, §16 stop conditions, §17 decision format | **yes — governing** | every phase passes the §5 gate before code; every report uses §15 |
| `syntriass-ghost-implementation` §2 (I1–I20), §4 test-first, §5 no security theatre, §6 change discipline, §8 documentation states | **yes** | RED before GREEN; `NOT_PRODUCTION_CAPABILITY` labels where a component is a placeholder |
| `aip-protocol-change-guard` | **only if** a signed/hashed field, canonical encoder, verification rule or wire format in `aip-crypto`/`aip-core`/`aip-protocol` is touched | Phase B touches none; if a later phase needs a signed record it applies in full |
| `syntriass-ghost-warrant` (Skill 8) | **not started; not a prerequisite** of phases B–G | phases B–G must add no input the warrant engine could later read as a trust signal |
| `syntriass-ghost-containment` (9), `syntriass-nexora-integration` (10) | **not authorized** | untouched |

The next numbered Ghost gate remains Skill 8. Sniffer Dog 2.0 phases run
beside that gate, not through it, and must not weaken it.

## A.3 Inventory — what the repository implements for each 2.0 layer

Classification vocabulary: `PRODUCTION` (wired into a production path and
tested), `IMPLEMENTED/UNWIRED` (exists, no production caller), `PARTIAL`,
`EXPERIMENTAL` (declared not-for-production by the crate itself),
`DESIGN_ONLY`, `MISSING`.

### Layer 1 — Agent identity

| Element | State | Evidence | Consequence for 2.0 |
|---|---|---|---|
| AIP-ID derivation `derive_aip_id(pubkey, ProvenanceTriple)` and `validate_aip_id` | `PRODUCTION` | `aip-crypto/src/lib.rs:49,65`; packet rule R2 re-derives it | **the** persistent identifier; reuse, never wrap in a new scheme |
| `AgentIdentitySummary { aip_id, public_key, provenance }` in every `EvidencePacket` | `PRODUCTION` | `aip-protocol/src/evidence_packet.rs:80`; R2 | packet-level identity; agent-supplied, derivation-checked |
| `AgentIdentityDocument` (AID): magic, version, flags, id, `created_at`, `expires_at`, primary/recovery/encryption keys, provenance, `status`, `sequence`, `lineage_depth`, `lineage_proof`, `capability_root`, `reputation_root`, `self_signature` | `IMPLEMENTED / PARTIALLY WIRED` | `aip-types/src/lib.rs:140`; created by `aip_core::create_identity`, activated and persisted by `aip-cli create-identity` (`main.rs:111-132`) through `aip_core::store`; validated by `validate_aid*`; **not** consulted by packet verification, the decision point, the observer or the reconciler | the identity *document* exists and is **self-signed** (`AIP/AgentIdentityDocument/v1`) — key possession only, no issuer |
| AID **lineage proof**: parent signs `(child_id, child_public_key)` under `AIP/LineageProof/v1`; verified by `validate_aid_with_parent` | `IMPLEMENTED / UNWIRED` | `aip-core/src/lib.rs:47-56, 236-256, 300-316`; adversarial tests in `aip-real-tests/src/adversarial.rs:173,191` | an **identity-level parent endorsement already exists** — answers one of the spec's NOT DETERMINED items with repository evidence (see A.5) |
| AID lineage depth | `PARTIAL` | `create_identity` sets `lineage_depth = 1` whenever a parent is given; the parent's own depth is not chained, so a grandchild is indistinguishable from a child by depth | grandparent → parent → child must be rebuilt from proofs, not from `lineage_depth` |
| AID **lifecycle** `Pending/Active/Suspended/Revoked` via `activate_identity` etc. | `IMPLEMENTED / UNWIRED`, **no authority** | `aip-core/src/lib.rs:356-410`: mutates `status` and `sequence` in place; no signer, no caller check; `status` and `sequence` are inside the self-signed canonical bytes (`:126-127`), so a mutated document no longer passes `validate_aid` unless re-signed by the agent itself; the CLI activates and stores without re-validating | lifecycle state is **not** authoritative for anything; it is the agent's own statement (to be pinned by a RED characterization test) |
| Identity **issuer** | `MISSING` | no signature by any party other than the agent (self) and, optionally, a parent identity (lineage) | the only external party naming an agent by signature is a `ScopedToken` issuer — an *authority* fact, not an identity fact |
| Identity **registry / organization binding / key rotation** | `MISSING` | `aip_core::store` is a local JSON file with the private key beside the document | out of scope for Phase B; recorded |
| **Reputation** (`reputation_root`, `ReputationVote`, `calculate_reputation`, BFT aggregation) | `EXPERIMENTAL` — crate doc `aip-core/src/lib.rs:10-15`, `AUDIT_CORRECTIONS.md` | produces a scalar score; roots are `merkle_empty()` | **PROHIBITED as a 2.0 input** (spec rule E1, I12); the profile crate must not depend on it and a test must pin that |
| Hardware attestation, liveness | `EXPERIMENTAL` | same | not consumed |

### Layer 2 — Agent profile

`MISSING` in every form. Inputs exist in four places (packets, tokens,
collector output, reconciler output); nothing composes them.

### Layer 3 — Parent / child lineage

| Kind | State | Evidence |
|---|---|---|
| Identity lineage (parent-signed child creation) | `IMPLEMENTED / UNWIRED` | AID `lineage_proof`, above |
| Authority lineage (`parent_jti` chain, attenuation, depth ≤ `MAX_DELEGATION_DEPTH`) | `PRODUCTION` | `aip-core/src/delegation.rs:179-252` |
| Process lineage (kernel fork by a bound parent, exec by the bound child) | `PARTIAL` | `KernelLifecycleKind::ProcessSpawn` / `ProcessExec`, both ends bound since Stage 7c; no joined edge; `LINEAGE_VIOLATION` refused by `Draft::precondition_holds` |
| The four-way parent classification (claimed / authorized / observed / reconciled) | `MISSING` | — |

### Layer 4 — Capability / delegation graph

`ScopedToken`, `DelegationToken`, `verify_scoped_token`,
`verify_delegation_chain`, `AuthorityRef { root_jti, chain_jtis }` in every
`ExpectedExecution`: `PRODUCTION`. Graph over many chains: `MISSING`.
`aip-service` carries a second, weaker delegation model (`GAP_MATRIX.md` §A,
P1) that 2.0 must not build on. `CapabilityGrant` (`aip-types:361`) is a
third capability representation in `aip-core` with its own domain
(`AIP/CapabilityGrant/v1`) and `capability_meet`; it is `IMPLEMENTED /
UNWIRED` and is **not** what the decision point consumes — 2.0 uses the
token model only (I18).

### Layer 5 — Execution instance

`ExecutionBinding` (`aip-types:694`), `ProcessInstance`, content hash,
observer-side `ObservedProcess` and structural comparison: `PRODUCTION`.
Nothing to add.

### Layer 6 — Observation, Layer 7 action evidence, Layer 8 reconciliation

`PARTIAL` as documented in `SNIFFER_DOG.md`, `ACTION_EVIDENCE.md` and
`RECONCILIATION_MODEL.md`. `Reconciliation` records are **unsigned and
unstored**; every 2.0 consumer of them inherits that until a signed record
exists (spec SD-09).

### Layer 9 — Experience / history, Layer 10 — profile API

`MISSING`. Preconditions: signed reconciliation records, then a ledger, then
(for portability) NEXORA.

## A.4 Hard stops in force for Phase B

| Stop | Source | Effect on Phase B |
|---|---|---|
| No identity issuer authority exists | orchestrator §16 "a prerequisite is missing"; spec §8 | the profile's `issuer` partition is derived **only** from verified `ScopedToken` issuers naming the agent; no `AgentIdentity` signer is invented |
| AID lifecycle has no authority | A.3 Layer 1 | `lifecycle` in the profile is the agent's self-assertion, labelled so; never `Active` on the profile's own authority |
| Reputation is experimental and scalar | I12, spec E1 | the profile crate does not depend on any reputation symbol; pinned by test |
| Reconciliation records are unsigned | spec SD-09 | the profile labels reconciled entries `VerifierLocal` and states that the profile builder must be the party that ran the reconciler; no aggregation (Phase F) |
| Parent classification is Phase C | user's phase order | Phase B exposes the AID lineage proof **only as present/absent and verified/unverified against a supplied parent key**; the four-way classification is Phase C |

## A.5 Repository evidence bearing on the specification's open decisions

| Spec §8 decision | Repository evidence found in Phase A | Effect |
|---|---|---|
| What is "agent creation" for agent lineage? | AID `lineage_proof`: the parent identity signs `(child_id, child_public_key)` at creation | one concrete, already-implemented definition exists: *identity lineage = parent-key-signed child creation*. It is an **authorized-by-parent** fact, not an observed one. Phase C will use it for `AUTHORIZED_PARENT` at the identity level; the decision whether other definitions are also admitted stays with the human |
| Who issues `AgentIdentity`? | nobody; AID is self-signed | unchanged — NOT DETERMINED; Phase B does not invent one |
| Who holds the reconciler key? | no reconciler key exists | unchanged — NOT DETERMINED; blocks signed records (Phase E precondition) |
| Profile audience / privacy | none | unchanged |
| Cross-host identity | none | unchanged |

## A.6 Phase plan mapped to the specification and the skills

| Phase | SD components | Gate | Prerequisites present? |
|---|---|---|---|
| A baseline + gap audit | — | orchestrator §5 | **this document** |
| B identity/profile data model | SD-01 (reuse), SD-02 skeleton, SD-03 (reuse), SD-05 projection | orchestrator + implementation skill; no protocol crate touched | yes, in the reduced form of A.4 |
| C parent/child lineage | SD-04 (identity lineage from AID proofs; process lineage from Stage 7c events; authority lineage from tokens), four-way classification | orchestrator; `LINEAGE_VIOLATION` guard change is a reconciler change under `syntriass-reconciliation` rules | identity + authority yes; process edges need a reconciler derivation |
| D capability/delegation lineage | SD-06 | orchestrator | yes (pure derivation over tokens) |
| E evidence-backed history | SD-09 signed records, SD-11 (unanchored ledger) | **blocked** on the reconciler-key decision; `aip-protocol-change-guard` applies to the new signed object | no |
| F experience derivation | SD-10 | after E | no |
| G profile projection / API | SD-13 | after F; `aip-service` duplicate authority model must be resolved first (`aip-service-hardening`) | no |
| H further sensors | SD-07/08 adapters | each its own decision document, RED first, as Stage 7c | file class next |

## A.7 Phase B decision record (orchestrator §17)

```
DECISION:      Build `aip-agent`: a validated identity projection and a
               dimension-separated profile view over existing artifacts.
               No new key, no new signed object, no new authority.
THREAT:        An agent (or an operator tool) composes a "profile" in which
               self-supplied text, unverified tokens, agent-mutated lifecycle
               state or experimental reputation appear as verified facts;
               a downstream reader takes the profile as authority.
ASSUMPTION:    Verifier-supplied trust anchors (issuer keys, decision-point
               keys) are correct; reconciliation records handed to the
               builder were produced by the builder's own trust domain.
MECHANISM:     Every partition of the profile is derived by re-verifying the
               artifact it comes from (AID self-signature and derivation,
               token signatures and chain rules, expected-execution
               signatures) or is labelled SELF_DECLARED / CLAIMED; the type
               has no numeric summary field; forbidden inputs are not linked.
IMPLEMENTATION: new crate `aip-standalone/aip-agent` (Phase B).
TEST:          RED first — characterization of the current weaknesses
               (unsigned lifecycle, unvalidated summary outside packets,
               depth not chained) and API-shaped tests for the profile
               invariants; then adversarial mutations of every input.
LIMITATION:    Identity issuer, lifecycle authority, signed reconciliation,
               aggregation, API and persistence are all out of scope and
               remain MISSING; a profile is a local, unsigned view.
DEPENDENCIES:  aip-crypto, aip-types, aip-core (capability, delegation,
               AID validation), aip-authorize (expected execution),
               aip-protocol (AgentIdentitySummary, EvidencePacket),
               aip-reconcile (Reconciliation).
STATUS:        authorized in the reduced form of A.4.
```

## A.8 Phase B outcome

| Component | State after Phase B | Evidence |
|---|---|---|
| SD-01 identity (validated projection over AID / packet summary) | **CLOSED for the projection**; issuer and lifecycle authority still `MISSING` | `aip-agent/src/identity.rs`; p01–p05 |
| SD-05 passport as read-only projection of tokens | **CLOSED** | `aip-agent/src/authority.rs`; p06–p08, p11 |
| SD-02 profile skeleton with fixed partitions and no scalar summary | **CLOSED for the skeleton**; lineage and experience partitions are explicit placeholders | `aip-agent/src/profile.rs`; p09–p15 |
| Reputation / scoring never consumed | **pinned** | p16 |
| Lifecycle without authority (A.3) | unchanged; **refused, not trusted** (`SelfAsserted` only) | c01, p02, p03 |
| Depth does not chain (A.3) | unchanged; Phase C rebuilds ancestry from proofs | c02 |

Test counts after Phase B: aip-standalone 567 / 0 / 3 ignored (+19), aip-service 39 / 0; clippy and fmt clean.

## A.9 Phase C1 outcome

| Component | State after C1 | Evidence |
|---|---|---|
| Process lineage edges (`LineageEdge`, `derive_lineage_edges`) | **CLOSED** for derivation; both ends bound, start verified, no agent identity | `aip-reconcile/tests/lineage_edges.rs` le01–le07 |
| Identity lineage across generations from proofs | **CLOSED**; `Claimed` / `Endorsed` / `Refused`; depth never read | l01–l03 |
| Authority lineage as paths | **CLOSED** (projection of Phase B chains) | l04 |
| Four-way parent classification | **PARTIAL**: identity (Claimed/Endorsed/Refused) and process (Observed, with the instance's own basis Claimed/AuthorizedTarget) exist; **Reconciled is unreachable** by type | l05–l09 |
| `LINEAGE_VIOLATION` reachability | **CLOSED (Phase C2)** — `reconcile_lineage`, record v4 | lv01–lv16 |
| Out-of-tree capabilities | classified in `OUT_OF_TREE_HARVEST_REVIEW.md`; none merged | — |

Test counts after C1: aip-standalone 583 / 0 / 3 ignored (+16), aip-service 39 / 0; clippy and fmt clean.

## A.10 Phase D outcome

| Component | State after D | Evidence |
|---|---|---|
| SD-06 delegation graph over verified chains | **CLOSED** for derivation and queries | d01–d11 |
| Incompleteness reporting (`DanglingHop`) | **CLOSED** | d03 |
| Revocation standing from a verifier-supplied set | **CLOSED** for consumption; revocation *truth* remains the P1 service/core gap | d04 |
| Conflict (one id, two signed terms) | implemented, **untested** — not reproducible from the public issuing API | — |
| `LINEAGE_VIOLATION` (C2) | **CLOSED** — complete two-sided evidence required; every gap `CANNOT_PROVE`, every ambiguity ambiguity | lv01–lv16 |

Test counts after D: aip-standalone 594 / 0 / 3 ignored (+11), aip-service 39 / 0; clippy and fmt clean.

## A.11 Gate 2 outcome (wire-level observation)

| Component | State after Gate 2 | Evidence |
|---|---|---|
| Wire-level mechanism evaluation (eBPF / tracepoints / perf / kprobes / cgroup / XDP / AF_PACKET / TC) | **DECIDED** — `OBSERVATION_MODEL.md` §5; `AF_PACKET` header tap chosen; XDP deferred to Gate 10 as a response hook | — |
| `WireTapAfPacket` source (headers only, kernel realtime stamp, `tp_drops` loss, no pid) | **CLOSED** | `aip-observe/tests/wiretap.rs` wt01–wt10 (wt10 live) |
| Wire corroboration of a socket transition (`Reconciliation.wire`, record v5) | **CLOSED** — informational; never raises strength or lowers a verdict | `aip-reconcile/tests/wire_corroboration.rs` wc01–wc15; `ghost-demo/tests/live_wire.rs` |
| Tap on a mirror / TAP host reconciled against the host's observer | **OPEN** — the code runs there unchanged; a second collector chain is refused (`MixedObservers`); cross-observer reconciliation not implemented | — |
| Payload, TLS, arguments | **permanently out of scope** for the kernel path (I23) | wt04 |

Test counts after Gate 2: aip-standalone 666 / 0 / 3 ignored (+29), aip-service 39 / 0; clippy and fmt clean.

## A.12 Gate 3 outcome (socket send, third action class)

| Component | State after Gate 3 | Evidence |
|---|---|---|
| `ghost.net.send.v1` vocabulary (endpoint digest, kind distinct from connect) | **CLOSED** | ss02 |
| `SockSendTracepoint` source (caller context, count, `sk`, loss) | **CLOSED** | sk01–sk07 (sk07 live) |
| Endpoint resolution from attested transitions; socket reuse refused | **CLOSED** — `SendSocketUnresolved` | ss04–ss06 |
| Verdict `VERIFIED_EXECUTION · Attested · Transition` | **CLOSED**, live | ss01, s_p |
| Payload digest | **permanently out of scope** for the kernel path (I23); a Gate 5 decision | sk04, ss02 |
| Host-wide anchoring cost | **CLOSED** — per-instance image cache with revalidation | `probe.rs` unit tests |
| Receive side, UDP | **OPEN** (not observed) | — |

Test counts after Gate 3: aip-standalone 690 / 0 / 3 ignored (+24), aip-service 39 / 0; clippy and fmt clean.

## A.13 Gate 4 outcome (file write, fourth action class)

| Component | State after Gate 4 | Evidence |
|---|---|---|
| `ghost.fs.write.v1` vocabulary (path bytes, validated, unnormalised) | **CLOSED** | fw02 |
| `Fanotify` source (mount mark, `FAN_REPORT_PIDFD`, overflow loss, no content) | **CLOSED** | fa01–fa07 (fa05/fa06 live) |
| Kernel-bound writer attribution (pidfd created by the kernel) | **CLOSED** — stronger than pid-number anchoring | fa05, fa06 |
| The five observation states | **CLOSED** — each pinned | fw01, fw03–fw06; `OBSERVATION_MODEL.md` §6.4 |
| Verdict `VERIFIED_EXECUTION · Attested · Transition`, live | **CLOSED** | fw01, f_p |
| File-handle identity, creates / deletes / renames | **OPEN** — `FAN_REPORT_FID` refused here (zero fsid) | — |
| Kernel event time | **OPEN by mechanism** — fanotify carries none; probe read stamp | `ACTION_EVIDENCE.md` §17.5 |

Test counts after Gate 4: aip-standalone 715 / 0 / 3 ignored (+25), aip-service 39 / 0; clippy and fmt clean.

## A.14 Gate 5 outcome (application / database / proxy sensors)

| Component | State after Gate 5 | Evidence |
|---|---|---|
| Decision on application-layer records | **DECIDED** — not observation; supporting tier only, `Correlated` / `Claimed` ceilings, never coverage | `APPLICATION_LOG_SENSOR_DECISION.md` |
| Supporting-tier adapter | **NOT BUILT**, preconditions stated | — |
| Executable fence | **CLOSED** | g5a–g5d |
| Spec §8 product decisions | **NOT DETERMINED** (human); recommended defaults recorded | `SNIFFER_DOG_2_0_IMPLEMENTATION_REPORT.md` Gate 5 |

## A.15 Gate 6 outcome (Merkle commitment layer)

| Component | State after Gate 6 | Evidence |
|---|---|---|
| Domain-separated leaves (`LeafKind`, `LEAF_DOMAIN`) | **CLOSED** | m03, m05 |
| RFC 6962 tree, root over a real set | **CLOSED** | m01, m02, m04 |
| Inclusion proof + verifier, bound to index and size | **CLOSED** | m04–m10, m14, m15 |
| Consistency proof + verifier, forward only | **CLOSED** | m11–m13, m16 |
| Signed head, proof object, offline verifier, external anchor | **OPEN** — Gate 7 | — |
