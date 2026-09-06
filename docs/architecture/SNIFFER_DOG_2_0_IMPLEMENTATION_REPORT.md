# SNIFFER DOG 2.0 — IMPLEMENTATION REPORT

Companion to `SNIFFER_DOG_2_0_SPECIFICATION.md` (architecture) and
`SNIFFER_DOG_2_0_GAP_MATRIX.md` (Phase A inventory). One section per phase,
in the orchestrator's §15 format. A phase not listed here has not started.

---

# Phase B — identity / profile data model

## Status

**PASS in the reduced form authorized by `SNIFFER_DOG_2_0_GAP_MATRIX.md`
A.4.** A new crate, `aip-standalone/aip-agent`, provides a validated agent
identity (SD-01, reused primitives), a read-only authority projection (SD-05,
reused tokens) and a dimension-separated profile view (SD-02 skeleton). It
introduces no key, no signed object, no authority, no store and no summary
field. Identity lifecycle, identity issuer, lineage classification,
experience, history and API remain **MISSING** and are labelled so inside
the profile itself.

## Commits

| Commit | Content |
|---|---|
| `3798614` | Phase A: baseline, governing gate, gap matrix |
| `4e3961d` | RED: crate with no items; `tests/characterization.rs` (3 pins, passing); `tests/profile.rs` (16 tests, 87 compile errors) |
| `8e350bb` | GREEN: `src/identity.rs`, `src/authority.rs`, `src/profile.rs`, `src/lib.rs`; workspace member |
| `047ad67` and the following commit | this report; spec, gap-matrix, plan pointers |

Edits to the RED test files after `4e3961d`, verified by `git diff -w`:
rustfmt reflow; `DecisionId::from` → `DecisionId::from_bytes` (the type has
no `From` impl by design, `aip-reconcile/src/ids.rs`); removal of a redundant
fixture input (`agent_public_key`) because the builder must use the validated
identity's key rather than a caller-supplied one; one clippy borrow. **No
assertion was changed.**

## Current State

| Symbol | What it is | Authority behind it |
|---|---|---|
| `AgentIdentity::from_document(aid, parent)` | validated identity from an `AgentIdentityDocument` via `aip_core::validate_aid` / `validate_aid_with_parent` | the agent's self-signature; optionally the parent's lineage signature against the key the caller asserts |
| `AgentIdentity::from_summary(summary)` | validated identity from a packet's `AgentIdentitySummary`: well-formed id, Ed25519 only, 32-byte key, `derive_aip_id` re-derivation (packet rule R2 outside `verify_packet`) | derivation only |
| `LifecycleAssertion::{NotEstablished, SelfAsserted{status, sequence}}` | the agent's lifecycle statement; **no authoritative variant exists** | the agent |
| `LineageProofState::{NotCarried, Absent, Present{signer_id, verified}}` | the parent proof as a proof, not as a parent | parent key holder (when verified) |
| `IssuerKeys`, `AuthorityChain`, `project_authority(agent, chains, keys, as_of)` | per-chain outcome under the decision point's rules 1–4 and 7: `SelfIssuedRoot`, `UntrustedIssuer`, `RootSignatureInvalid`, `ChainInvalid(AipError)`, `LeafNotAgent`; verified chains split into `authorized` / `not_in_standing` (`Expired` / `NotYetValid`) | token issuers, by signature, through `aip_core::verify_scoped_token` and `verify_delegation_chain` |
| `AuthorityProjection::issuers()` → `IssuerAssertion` | the issuer partition, from verified chains only | token issuers |
| `InstanceAssertion::{Claimed, AuthorizedTarget{decision_id, decision_point_id}}` | who vouched for an `ExecutionBinding` | agent / trusted decision point via `verify_expected_execution_for_agent` with the **validated** agent key |
| `ReconciledRecord{record, source: VerifierLocal}` | a `Reconciliation` carried verbatim, admitted only if its `decision_id` is one of this agent's verified expectations | the reconciler, in the builder's own trust domain |
| `AgentProfile` | twelve fixed partitions incl. `excluded_expectations`, `excluded_bindings`, `excluded_reconciliations`, `lineage: NotEvaluated`, `experience: NotDerived` | each partition names its own |
| `build_profile(&ProfileInputs)` | fails only when the identity does not validate; every other defect lands in an `excluded_*` partition with its reason | — |

Trust anchors (`IssuerKeys`, `DecisionPointTrustAnchors`) are supplied by the
builder. Nothing about whom to trust is read from the artifacts.

## Evidence

`aip-standalone/aip-agent/tests/characterization.rs` (pins of the existing
primitives; unchanged by GREEN):

| Test | Pinned fact |
|---|---|
| c01 | `activate_identity` / `suspend_identity` mutate `status` and `sequence` in place; `validate_aid` then returns `SignatureInvalid`. No lifecycle transition has a signer. |
| c02 | `lineage_depth` is 1 for a child and 1 for a grandchild; the proofs chain, the depth does not. |
| c03 | a root document carries only the agent's own signature; the parent lineage proof is the only external identity endorsement in the system. |

`aip-standalone/aip-agent/tests/profile.rs`:

| Test | Property |
|---|---|
| p01 | identity by re-derivation; other key → `DerivationMismatch`; malformed id → `MalformedId`; 3-byte key → `KeyLength` |
| p02 | a document mutated after signing is refused (`Document(SignatureInvalid)`), not relabelled |
| p03 | `LifecycleAssertion` has no authoritative variant (exhaustive `match`; a new variant is a compile error) |
| p04 | identity → instance link is the validated AIP-ID only; same pid, other agent → not this identity's |
| p05 | lineage proof reported as `Absent` / `Present{verified: None}` / `Present{verified: Some(true)}`; wrong parent key → `Document(LineageInvalid)` |
| p06 | projection reproduces the decision point's acceptance of the fixture chain: path, issuers, effective scope, `Valid` |
| p07 | untrusted issuer, rewritten root expiry (Skill 3 attack), rewritten hop grantee, chain ending at another agent, self-issued root → each excluded with the named reason, none authorized |
| p08 | expired / not-yet-valid chains are verified but `not_in_standing`, apart from both `authorized` and `excluded` |
| p09 | top-level partitions are exactly the twelve named; no key anywhere in the serialized profile contains score / trust / confiden / reputation / rating / rank / grade; placeholders explicit |
| p10 | self-declared text carries `SELF_DECLARED · UNVERIFIED` and appears under no other key, whatever it says |
| p11 | issuers derive only from verified authority; a rewritten root yields no issuer and one exclusion |
| p12 | DP-signed expectation → `AuthorizedTarget`; packet binding → `Claimed`; binding naming another agent → `excluded_bindings`; untrusted DP, agent-key DP (`DecisionKeyIsAgentKey`), expectation for another agent → `excluded_expectations` with reason |
| p13 | records join through `decision_id` of this agent's verified expectations; carried verbatim incl. `PHANTOM_CLAIM`; foreign decision and `None` decision excluded with reason |
| p14 | an empty profile asserts nothing: empty partitions, explicit placeholders, lifecycle = the document's own `Pending` |
| p15 | an identity that fails validation yields `ProfileError::Identity`, no profile |
| p16 | crate sources contain none of `calculate_reputation`, `ReputationVote`, `reputation_root`, `aggregate_reputation`, `evaluate_hardware_trust`, `verify_liveness`, `score`, `trust_level` |

## Security Findings (unchanged by this phase, recorded)

- **Lifecycle without authority.** The AID lifecycle state machine in
  `aip-core` has no signer and its mutations invalidate the self-signature
  (c01). The CLI activates and stores documents without re-validating. Phase
  B does not repair this; it refuses to trust it. Repair belongs to whoever
  becomes the identity authority (spec §8, NOT DETERMINED).
- **Depth does not chain** (c02). Ancestry must be rebuilt from proofs
  (Phase C).
- **Reconciliation records are unsigned.** The profile admits only
  `VerifierLocal` records; a profile built from records it did not compute is
  outside this phase's contract.
- **`aip-service` duplicate authority model** (P1, unchanged). The profile
  layer does not touch the service.

## Changes Made

| File | Change |
|---|---|
| `aip-standalone/Cargo.toml` | member `aip-agent` |
| `aip-standalone/aip-agent/Cargo.toml` | new crate; depends on aip-types, aip-crypto, aip-core, aip-authorize, aip-protocol, aip-reconcile, serde; dev: aip-observe, serde_json |
| `aip-standalone/aip-agent/src/{lib,identity,authority,profile}.rs` | new |
| `aip-standalone/aip-agent/tests/{characterization,profile}.rs` | new (RED commit), formatting + fixture fixes (GREEN commit) |

No file in aip-crypto, aip-core, aip-protocol, aip-authorize, aip-observe,
aip-reconcile, ghost-demo or aip-service was modified. No canonical encoder,
signed field, verification rule or wire format changed; the protocol change
guard did not apply.

## Tests

| Suite | Result |
|---|---|
| `cargo test -p aip-agent` | 19 passed (3 characterization + 16 profile), 0 failed |
| `cargo test --workspace` (aip-standalone) | 567 passed, 0 failed, 3 ignored (baseline 548 / 0 / 3; +19) |
| `cargo test` (aip-service) | 39 passed, 0 failed (unchanged) |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all --check` | clean |

All previous tests are unchanged. tracefs was mounted by hand so the Stage
7b/7c live tests ran rather than skipped.

## Remaining Gaps

Identity issuer and lifecycle authority (NOT DETERMINED); four-way parent
classification, `LineageEdge`, `LINEAGE_VIOLATION` reachability (Phase C);
delegation graph (Phase D); signed reconciliation records and reconciler key
(Phase E precondition, NOT DETERMINED); ledger, experience (Phases E–F);
persistence, API, export (Phase G); `aip-service` duplicate authority model.

## Security Claims

Supported by implementation and tests:

- An `AgentIdentity` exists only if the AIP-ID re-derives from the presented
  key and provenance and, for a document, the document's own signature
  verifies.
- The profile's `authority` partition contains only chains the decision
  point itself would accept, under the same `aip_core` verification calls.
- The profile's `reconciled` partition contains only records whose decision
  the builder verified as this agent's, carried verbatim.
- Nothing the agent writes about itself appears outside `self_declared`.
- The profile has no numeric or categorical summary across partitions.

Not claimed: that any agent is who it says beyond key possession; that any
lifecycle state is true; that any instance ran; that any authority was used;
that the profile is complete, persistent, portable or signed.

## Next Gate

Phase C (parent/child lineage): identity lineage from AID proofs across
generations, process lineage edges from Stage 7c fork/exec events, authority
lineage from tokens; the four-way `CLAIMED / AUTHORIZED / OBSERVED /
RECONCILED` classification for parent and child; `LINEAGE_VIOLATION`
precondition in the reconciler under `syntriass-reconciliation` rules. RED
first. Skill 8 remains the next numbered Ghost gate and is untouched.

---

# Phase C — parent / child lineage (C1: model and derivations)

## Status

**PASS for C1.** Lineage is now a real section of the profile in three
kinds that never merge — identity (from AID lineage proofs across
generations), authority (issuer → grantee paths from verified token chains)
and process (kernel fork/exec edges between bound instances) — with the
agent at either end of a process edge established only through a
decision-point-signed peer expectation. **C2 is not started:** there is no
reconciled lineage verdict; `LINEAGE_VIOLATION` remains refused by the
reconciler's central guard, and `ReconciledLineage` has exactly one variant,
`NotReachable`. C2 depends on the delegation graph (Phase D).

Design input harvested from out-of-tree work is recorded in
`OUT_OF_TREE_HARVEST_REVIEW.md` §5: lineage has a kind and an actor; an edge
cannot exist without both bound ends; attribution of the far end is a
separate fact; every relation carries how it was established.

## Commits

| Commit | Content |
|---|---|
| `3d2ecd2` | `OUT_OF_TREE_HARVEST_REVIEW.md` |
| `83bee50` | RED: `aip-reconcile/tests/lineage_edges.rs` (le01–le07), `aip-agent/tests/lineage.rs` (l01–l09); neither compiled |
| `07328c9` | GREEN: `LineageEdge` + `derive_lineage_edges` in `aip-reconcile`; `aip-agent/src/lineage.rs`; hop path on `AuthorizedCapability`; three new profile inputs |
| *(the following commit)* | this section and pointers |

Test-file edits since RED, by `git diff -w`: Phase C files — rustfmt only.
Phase B `tests/profile.rs` — three new empty fixture inputs; the two
assertions that pinned `lineage == LineageSection::NotEvaluated` (the Phase
B placeholder) now pin the real section's `reconciled == NotReachable`, no
identity parent and no process relation for those inputs; p16's source list
gained `lineage.rs`. These are the intended replacement of a placeholder by
the thing it stood for, not a weakening: every Phase B property still holds
and is still asserted.

## Current State

| Symbol | What it is | Authority behind it |
|---|---|---|
| `aip_reconcile::LineageEdge { parent, child, fork, exec, image_sha256, filename, mechanism, batch_sequence }` | "bound instance P forked bound instance C, which executed image H" | collector-signed kernel events; both ends pidfd-anchored; child start tick verified against the batch's clock anchor |
| `aip_reconcile::derive_lineage_edges(batches)` | the only production constructor: a completed, start-verified `ProcessExecution` and nothing less | reuses `derive_executions` pairing (Stage 7c) |
| `IdentityParent::{None, Claimed, Endorsed, Refused}` | how the parent named by the lineage proof stands | `Endorsed` only when the proof verifies against the parent's own validated document (or the key the caller asserted); `Refused` when the genuine parent document is present and the proof fails against it |
| `IdentityLineage { parent, ancestors: Vec<Ancestor{id, link: Endorsed}>, generations, excluded_documents }` | ancestry rebuilt generation by generation from proofs; stops at the first missing or invalid document; cycle-guarded; capped at 64 | each ancestor's own self-signature and the proof it signed |
| `AuthorityPath { root_jti, root_issuer, root_grantee, hops: Vec<AuthorityHop{jti, issuer_id, grantee_id}>, standing }`, `delegators()` | one verified chain as a path | token signatures through `aip_core` (Phase B projection) |
| `ChildAttribution::{Unattributed, AuthorizedTarget{agent_id, decision_id}, Ambiguous{agent_ids}}` | which agent an observed instance is | a peer `ExpectedExecution` verified against the builder's decision-point anchors whose binding matches the instance structurally (`matches_process_of`); two agents naming one instance is reported as ambiguous, never resolved |
| `ProcessLineage { spawned: Vec<ObservedSpawn{child, child_agent, parent_basis, edge}>, spawned_by: Vec<ObservedSpawnedBy{parent, parent_agent, child_basis, edge}>, unrelated_edges, excluded_peer_expectations }` | this agent's observed spawns and the spawn that produced it, each carrying how this agent's own instance was vouched for (`AuthorizedTarget` or `Claimed`) | kernel edges + the instance partition |
| `ReconciledLineage::NotReachable` | no verdict exists | — |
| `ProfileInputs.{peer_expectations, process_edges, ancestor_documents}` | new inputs | verified / validated inside the builder |

## Evidence

`aip-reconcile/tests/lineage_edges.rs`:

| Test | Property |
|---|---|
| le01 | bound fork + bound exec + verified start → one edge with both instances, kernel positions, image, mechanism |
| le02 | fork without exec → no edge |
| le03 | unbound parent or unbound child → no edge |
| le04 | no clock anchor → no edge |
| le05 | child start tick outside `[fork − tick, exec]` (recycled pid) → no edge |
| le06 | exec before fork in kernel time → no edge |
| le07 | an edge serializes with no agent id, attribution or decision, whatever the events claimed |

`aip-agent/tests/lineage.rs`:

| Test | Property |
|---|---|
| l01 | root identity: parent `None`, no ancestors, zero generations |
| l02 | parent `Claimed` without the parent's document, `Endorsed` with it; grandparent reached only through the parent; generations from proofs while `lineage_depth` stays 1 |
| l03 | mutated ancestor document excluded with reason, parent stays `Claimed`; unrelated document ignored; a proof forged under another key against the genuine parent document → `Refused` |
| l04 | one authority path per verified chain with hops, root issuer, standing and `delegators()`; a rewritten root yields none |
| l05 | observed spawn by this agent's `AuthorizedTarget` instance; child `Unattributed` until a verified peer expectation names its binding; untrusted anchors → nothing attributed, edge unrelated, peer excluded |
| l06 | the same edge from the child's side (`spawned_by`) with the parent attributed the same way |
| l07 | same pid with another start tick, or another image, is another process: no relation |
| l08 | the swarm shape: spawned by a known instance, no authority path, own instance only `Claimed`; `reconciled` matched exhaustively — no verdict variant exists |
| l09 | lineage partition has exactly `identity / authority / process / reconciled`; no forbidden key; a claimed parent never renders as endorsed |

## Security Findings (carried forward)

Unchanged from Phase B, plus: a process edge says which *instances* are
related, never which *agents*; attribution rests on decision-point-signed
expectations, which are the agent's own binding claims countersigned as the
authorized target. An agent that never requested a decision is unattributed
in every edge it appears in — that is `CANNOT_PROVE` for its identity, not
evidence of anything else.

## Changes Made

| File | Change |
|---|---|
| `aip-reconcile/src/action.rs` | `LineageEdge`, `derive_lineage_edges`; `Serialize` on `EventPosition`; no change to any comparison, guard or result |
| `aip-reconcile/src/lib.rs` | exports |
| `aip-agent/src/lineage.rs` | new |
| `aip-agent/src/authority.rs` | `root_grantee`, `hops` on `AuthorizedCapability` |
| `aip-agent/src/profile.rs` | three inputs; `lineage: Lineage` replaces the placeholder |
| `aip-agent/src/lib.rs`, `Cargo.toml` | exports; `aip-observe` becomes a regular dependency |

No canonical encoder, signed field, verification rule or wire format
changed; the protocol change guard did not apply.

## Tests

| Suite | Result |
|---|---|
| `cargo test -p aip-agent` | 28 passed (3 characterization + 16 profile + 9 lineage), 0 failed |
| `cargo test -p aip-reconcile --test lineage_edges` | 7 passed, 0 failed |
| `cargo test --workspace` (aip-standalone) | 583 passed, 0 failed, 3 ignored (Phase B: 567; +16) |
| `cargo test` (aip-service) | 39 passed, 0 failed (unchanged) |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all --check` | clean |

All Stage 0–7c tests unchanged. tracefs mounted by hand so live tests ran.

## Remaining Gaps

C2 (reconciled lineage, `LINEAGE_VIOLATION`) after Phase D; identity issuer
and lifecycle authority (NOT DETERMINED); revocation status; everything
listed under Phase B.

## Security Claims

- A `LineageEdge` exists only for a kernel fork whose parent and child were
  both pidfd-anchored and whose child start tick was verified.
- An identity ancestor appears only when the proof verifies against that
  ancestor's own validated document.
- An authority path is exactly one verified token chain.
- No lineage verdict is produced; nothing in the type system can express one.

Not claimed: that a spawned child inherited anything; that an unattributed
instance belongs to no agent; that lineage across hosts is visible.

## Next Gate

Phase D — delegation graph over verified token chains (index by grantee,
all paths reaching an agent, effective scope per path, explicit
incompleteness), harvested shape from `OUT_OF_TREE_HARVEST_REVIEW.md` §2.1;
then C2. Skill 8 remains untouched.

---

# Phase D — delegation graph (SD-06)

## Status

**PASS.** `aip_agent::graph::DelegationGraph` is a projection over token
chains that `aip_core` verified whole. It answers who delegated what to
whom — paths to an agent, delegations an agent issued, agents under an
issuer, authority reaching an agent for an action — and reports exactly
what it could not verify: hops without their parent in hand
(incompleteness) and one id carrying two sets of signed terms (conflict).
Revocation is a verifier-supplied set of token ids, the shape the packet
verifier's rule R9 already consumes; the graph decides nothing about what
is revoked. No new authority, key or signed object.

The path-resolution shape (walk child → root, report the whole path,
effective scope at the leaf) is the design harvested from the OrbitalTrust
authority module (`OUT_OF_TREE_HARVEST_REVIEW.md` §2.1), rebuilt over
Ed25519-signed tokens instead of edges whose verifier returned `true`.

## Commits

| Commit | Content |
|---|---|
| `2bdf49c` | RED: `aip-agent/tests/graph.rs` d01–d11; Phase B/C fixtures gain `loose_hops` and `revoked_jtis`; the lineage partition pin gains `delegation`; did not compile |
| `f96e51a` | GREEN: `aip-agent/src/graph.rs`; `verify_chain_terms` split out of the per-agent projection; `Lineage.delegation`; two new profile inputs |
| *(the following commit)* | this section and pointers |

Test-file edits since RED, by `git diff -w`: rustfmt; one unused fixture
field removed; one `clone` → `from_ref`; and **one corrected expectation**:
d10 first asserted that the orchestrator holding one root token presented
through two chains has *two* paths, which contradicts d02's dedupe rule —
it has one path, because one token is one authority. The corrected
assertion is the stricter reading. No other assertion changed.

## Current State

| Symbol | What it is | Authority behind it |
|---|---|---|
| `DelegationGraph::build(chains, loose_hops, keys, revoked_jtis, as_of)` | nodes from every chain `verify_chain_terms` accepts (no self-issued root, trusted and valid root signature, `aip_core::verify_delegation_chain`); a chain that fails is excluded whole with its reason | token signatures through `aip_core` |
| `GraphNode { jti, parent_jti, issuer_id, grantee_id, scope, depth, issued_at, expires_at, terms_hash }` | one verified token; `terms_hash` is the signed payload hash | issuer signature |
| `DanglingHop` / `incomplete()` | a hop supplied outside a chain: not verified alone (that would be a second verifier), reported with the parent it needs | — |
| `conflicts()` | one id, two `terms_hash`es among verified tokens: both refused. Defensive; not reproducible from the public issuing API, which chooses ids itself, so **not claimed as a tested property** | — |
| `PathStanding::{Valid, Expired, NotYetValid, Revoked{jti}}` | standing of a root-to-grantee path at `as_of`; `Revoked` names the nearest-to-root revoked token | verifier-supplied revocation set |
| `paths_to`, `valid_paths_to`, `authority_reaching(agent, action)`, `agents_under(issuer)`, `delegated_by(agent)`, `standing_at(jti)`, `is_complete` | queries; every path ends at a root node or is not a path; cycles are not paths | — |
| `Lineage.delegation: DelegationSummary { paths_to_agent, delegated_by_agent: Vec<OutgoingDelegation{jti, grantee_id, standing}>, agents_under_agent, incomplete, conflicts, excluded }` | the graph's answers for the profiled agent | — |
| `ProfileInputs.{loose_hops, revoked_jtis}` | new inputs | verifier-supplied |

The per-agent projection (`project_authority`, Phase B) and the graph share
`verify_chain_terms`; the projection adds the decision point's "chain ends
at this agent" rule, the graph does not — a chain reaching another agent is
`LeafNotAgent` for the agent's own authority and an ordinary edge for the
graph (d10).

## Evidence

| Test | Property |
|---|---|
| d01 | one verified chain → two nodes, one path, root issuer first, delegators, effective scope, `Valid`, complete |
| d02 | shared root is one node; `agents_under(root issuer)` is transitive; `delegated_by(orchestrator)` is exactly its two hops |
| d03 | a hop without its parent is `incomplete` naming the missing parent, not a node or path; supplying the chain resolves it |
| d04 | revoked hop → that path `Revoked`, no valid path, no authority for any action, sibling unaffected; revoked root → every path revoked |
| d05 | rewritten hop → chain excluded whole (`ChainInvalid(SignatureInvalid)`), no node from it |
| d06 | identical token through two chains and as a loose hop → one node, no conflict, complete |
| d07 | hops extended until `aip_core` refuses (`LineageInvalid`), always below `MAX_DELEGATION_DEPTH`; every prefix grantee has one path of increasing length |
| d08 | `authority_reaching` = valid ∧ scope permits; out-of-scope → none; expired path still a path (`Expired`), reaches nothing, not excluded |
| d09 | self-issued root → `SelfIssuedRoot` before any key lookup; untrusted issuer → `UntrustedIssuer(id)` |
| d10 | profile carries paths to the agent, its outgoing delegations, agents under it, incompleteness and conflicts; the agent's own authority still excludes chains ending elsewhere |
| d11 | serialized graph has no key naming score / trust / confidence / reputation / rating / rank / grade |

## Changes Made

| File | Change |
|---|---|
| `aip-agent/src/graph.rs` | new |
| `aip-agent/src/authority.rs` | `verify_chain_terms` extracted; per-agent `verify_chain` reuses it |
| `aip-agent/src/lineage.rs` | `Lineage.delegation` |
| `aip-agent/src/profile.rs` | `loose_hops`, `revoked_jtis` inputs; graph built per profile |
| `aip-agent/src/lib.rs` | exports |

No file outside `aip-agent` changed. No protocol crate touched.

## Tests

| Suite | Result |
|---|---|
| `cargo test -p aip-agent` | 39 passed (3 + 16 + 9 + 11 graph), 0 failed |
| `cargo test --workspace` (aip-standalone) | 594 passed, 0 failed, 3 ignored (Phase C: 583; +11) |
| `cargo test` (aip-service) | 39 passed, 0 failed (unchanged) |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo fmt --all --check` | clean |

## Remaining Gaps

Revocation *truth*: `aip-core`'s `RevocationLog` is unwired and
`aip-service` carries its own; the graph consumes whatever set the verifier
supplies. Conflict branch untested (see above). C2 (`LINEAGE_VIOLATION`)
now has its prerequisite and remains not started.

## Security Claims

- Every node is a token whose chain `aip_core` verified; nothing enters on
  its own say-so.
- A path exists only from a root node; a hop without its parent yields no
  path and is reported.
- A revoked token, wherever it sits on a path, makes that path confer no
  authority.
- The graph carries no scalar summary and decides nothing about revocation.

Not claimed: that the graph is complete over the world's tokens (it says
`is_complete` only over what it was handed); conflict detection as a tested
property.

## Next Gate

Skill 8 (warrant engine), authorized alongside this phase; then Phase C2.

---

# Phase C2 — the lineage verdict (Gate 1 of the completion mandate)

## Status

**PASS.** `LINEAGE_VIOLATION` is reachable, through one entry point
(`aip_reconcile::reconcile_lineage`), only on complete evidence from both
the observed and the claimed side, at `Attested`. The definition, the
preconditions and every gap are in `RECONCILIATION_MODEL.md` "The lineage
question"; the mechanics in `RECONCILIATION_IMPLEMENTATION_REPORT.md`
"Phase C2 note".

## Commits

| Commit | Content |
|---|---|
| `8c263fe` | RED: `aip-reconcile/tests/lineage_violation.rs` lv01–lv16, did not compile |
| `6dcec84` | GREEN: record v4 with `lineage`, `LineageComparison`/`LineageLink`, reason codes `0x70–0x78`, `LineageInputs`/`DecisionAuthority`/`IdentityLineageInput`, shared `prologue`, `reconcile_lineage`; fixtures in `aip-warrant` and `aip-agent` gain the field |
| *(the commit carrying this section)* | documentation: this section, `RECONCILIATION_MODEL.md` "The lineage question", `RECONCILIATION_IMPLEMENTATION_REPORT.md` "Phase C2 note", spec, gap matrices, plain-English text |

Test-file edits since RED: rustfmt, a fixture variable renamed from
`scene` to `sc` where it shadowed the fixture function, an unused fixture
field removed and a doc-comment list re-indented for clippy. No assertion
changed.

## Evidence (mandate's required behaviours → tests)

| Behaviour | Tests |
|---|---|
| child cannot invent parent | lv04 (forged parent attribution → unattributed), lv11 (no bound parent → no edge) |
| parent cannot invent child | lv05 (other instance → no edge), lv13 (second claim on the child → ambiguity) |
| token-chain authority verified | lv06 (transplanted), lv07 (mutated), lv12 (revoked) |
| delegation graph from verified authority only | Phase D d01–d11 |
| observed parent must match where the claim requires it | lv01 (violation), lv02 (delegator), lv03 (identity parent) |
| identity lineage requires a valid parent-signed proof | lv08 |
| authority lineage requires a valid chain | lv09 |
| missing evidence ⇒ `CANNOT_PROVE` | lv04–lv09, lv11, lv12 |
| ambiguity ⇒ never a violation | lv10, lv13 |
| positive requires both sides | lv01 against lv08 and lv09 |
| observer gates | lv14 |
| record and guard | lv15, lv16, unit `lineage_violation_is_refused_without_a_contradicted_lineage` |

## Security Claims

- A `LINEAGE_VIOLATION` names a kernel edge (two `KernelEvent` references),
  the parent's decision (an `Expected` reference) and the subject's
  decision; every element is signed by the collector or the decision point.
- No single side, no unattributed parent, no unverified token, no
  unverified proof and no ambiguity can produce it.

Not claimed: that a violation is malicious; that consistency is authorization;
anything about hosts the observer does not cover.

## Next Gate

Gate 2 of the completion mandate (network / wire observation beyond TCP
state transitions).

---

# Gate 2 — wire-level observation (completion mandate)

## Status

**PASS.** A second kernel path by which a connection is seen — the device
layer, through an `AF_PACKET` header tap — is a probe source with its own
mechanism, event kind, loss counter and kernel capture stamp; the reconciler
reports, on record v5, whether that path corroborates a socket-transition
verdict, and cites the segments. The mechanism evaluation that led here is
in `OBSERVATION_MODEL.md` §5; the reconciler semantics in
`RECONCILIATION_MODEL.md` "The wire question".

## Mechanism evaluation (summary; full table in `OBSERVATION_MODEL.md` §5.2)

Measured on this host first: `bpf()` usable, BTF present, `AF_PACKET`
usable, `sock`/`net`/`skb`/`xdp`/`syscalls` tracepoints present, no
`tc`/`bpftool`. eBPF (kprobes, `cgroup/connect4`, `sockops`, TC) was
rejected for this gate: loadable here, but it lives under the same host root
as the tracepoints, adds a loader and a bytecode toolchain, and its one
distinctive capability — payload access through `sk_msg` — is forbidden by
I23. XDP is a response hook and is Gate 10. `AF_PACKET` was chosen because
it is the only candidate whose code produces the same evidence on a mirror
port or TAP host outside the observed host's root, and because it costs
nothing but `CAP_NET_RAW`.

## Commits

| Commit | Content |
|---|---|
| `36b026c` | RED: `aip-observe/tests/wiretap.rs` wt01–wt10, `aip-reconcile/tests/wire_corroboration.rs` wc01–wc15, `ghost-demo/tests/live_wire.rs` w_p/w_n; did not compile |
| `57849bd` | GREEN: `wiretap.rs` (`parse_wire_frame`, `WireTap`), `SourceMechanism::WireTapAfPacket` (0x07), `KernelLifecycleKind::WireSegment` (0x07) + `WireDirection` + `tcp_flags`, `BootClockAnchor::realtime_ns_to_monotonic`, `ProcfsProbe::ingest_wire_event`; record v5 with `wire: WireCorroboration`; `corroborate_wire`; ghost-demo tap wiring and `run_without_wire_tap` |
| `275c4e3` | observer protocol v6: the new mechanism and event-kind codes are refused by verifiers that do not know them |
| *(the commit carrying this section)* | documentation |

Test-file edits since RED: rustfmt; two `#[allow(clippy::too_many_arguments)]`
attributes on fixture constructors. No assertion changed. One earlier test,
`lv15`, pinned `RECONCILIATION_VERSION == 4`; it now pins `>= 4` at compile
time ("lineage entered the record at v4"), because a record version is
raised by every gate that adds a signed field and an equality would break
each time without protecting anything.

## Evidence (mandate's requirements → tests)

| Requirement | Tests |
|---|---|
| strongest independent mechanism evaluated and chosen with reasons | `OBSERVATION_MODEL.md` §5.2–5.3 |
| observer holds no identity key; collector signs | the tap lives in `ProcfsProbe`, which has no key; wt08 (registry gates the mechanism), wc15 (tamper after signing is `Proven` `SENSOR_INTEGRITY_FAILURE`) |
| headers only, never payload, never a payload hash | wt04 (payload measured by length; no payload byte in the event, its JSON or its canonical bytes) |
| the wire names no process | wt06, wt07 (no `subject_pid`, never bound, never attributed even with a registered claim), wc12 (wire alone: `CANNOT_PROVE`, `NoReference`) |
| loss counted, never silent | wt10 (`PACKET_STATISTICS` counted zero), wc10 (loss never corroborates) |
| kernel-stamped, placed through the signed anchor | wt09, wt10, wc06, wc11 |
| corroboration cites its evidence and raises nothing | wc01–wc03 |
| every gap named on the record, never a verdict change | wc04–wc09, wc11, wc13 |
| record versioned, canonical, injective | wc14, wt06 |
| live | wt10 (loopback capture: SYN out, SYN-ACK in, 19 bytes measured by length, zero drops); `live_wire.rs` w_p (`Corroborated`) and w_n (`Unavailable` without the tap) |

## Live run on this host

`cargo run -p ghost-demo --bin ghost-demo`, scenario T-P:

```
agent pid 17338 → 127.0.0.1:44093; 1 established connection(s) in the table,
6 kernel socket transition(s) captured, 24 wire segment(s) captured (tap open)
result=VERIFIED_EXECUTION strength=Attested reason=ActionEvidenceMatches
identity=Match { observations: 4 } action=Match(ActionEvidenceSeal { mechanism: SockStateTracepoint, kind: Transition }) temporal=WithinWindow
wire=Corroborated
```

Test counts after Gate 2: aip-standalone 666 / 0 / 3 ignored (+29 over
Gate 1), aip-service 39 / 0; clippy `-D warnings` and fmt clean.

## Security Claims

- A `Corroborated` record cites two collector-signed wire segments whose
  headers, direction, interface and kernel capture stamp are inside the
  signed bytes, alongside the two socket transitions.
- No segment can be bound to a process, attributed to an agent, or verify
  anything on its own; nothing in the wire path can raise a record above
  `Attested` or turn a verdict into a violation.

Not claimed: payload visibility or any payload hash; eBPF, XDP or packet
*filtering*; zero loss; that the tap covers the path a connection took;
independence from the observed host's root when the tap runs on that host;
cross-observer reconciliation for a tap on a mirror host (its own collector
chain is refused as `MixedObservers` today).

## Next Gate

Gate 3: action-level network evidence beyond TCP connect. Candidate from the
evaluation: `sock:sock_send_length` — per-socket byte counts in the caller's
task context, linked by `sk` — with explicit semantics "bytes the kernel
accepted for send on this socket", never a payload hash.

---

# Gate 3 — socket send, the third action class (completion mandate)

## Status

**PASS.** `ghost.net.send.v1` is observable and reconcilable: the kernel's
`sock:sock_send_length` tracepoint, in the sender's own task context, gives
the socket and the byte count; the socket's endpoint is resolved from the
attested transitions of the same kernel socket; the verdict is
`VERIFIED_EXECUTION · Attested · Transition`. Hash semantics are explicit
and tested: the digest names the endpoint only, the count is signed
context, no payload digest exists. `ACTION_EVIDENCE.md` §16.

## Commits

| Commit | Content |
|---|---|
| `c830a8d` | RED: `aip-observe/tests/socksend.rs` sk01–sk07, `aip-reconcile/tests/send_evidence.rs` ss01–ss13, `ghost-demo/tests/live_send.rs` s_p/s_a; did not compile |
| `4e4bd6a` | GREEN: `net_send_action` / `net_send_parameters` / `NET_SEND_ACTION`; `socksend.rs` (`parse_sock_send_record`, `SockSendTracer`); `SourceMechanism::SockSendTracepoint` (0x08), `KernelLifecycleKind::SocketSend` (0x08), observer protocol v7; `ProcfsProbe::ingest_send_event` and the per-instance image cache; `SocketSend` / `derive_sends` / `TransitionEvidence::Send`; `ReasonCode::SendSocketUnresolved` (0x4f); ghost-demo S-P/S-A and bounded drains |
| *(the commit carrying this section)* | documentation |

Test-file edits since RED: rustfmt; one `#[allow(clippy::too_many_arguments)]`
on a fixture; `wt05` (Gate 2) pinned the mechanism count at exactly seven
and now pins "at least seven, all codes distinct". No assertion changed.

## Evidence (mandate's requirements → tests)

| Requirement | Tests |
|---|---|
| smallest new class beyond `connect()` | one tracepoint, one event kind, one action; `ACTION_EVIDENCE.md` §16 |
| explicit hash semantics | ss02 (endpoint digest equals the connect digest; kind differs; any count verifies), `sk04` (count inside the signed bytes, no payload-shaped field) |
| never claim a raw payload hash unless captured | no payload is captured; no digest of bytes exists in the vocabulary, the observer or the reconciler (`sk04`, `ss02`, `ACTION_EVIDENCE.md` §16.1) |
| kernel-pushed, attributed in the caller's context | sk01, sk05, sk07 (live), ss01 |
| endpoint from attested transitions only; socket reuse refused | ss04–ss06 |
| every weaker set of facts is not a verdict | ss03, ss07–ss12 |
| tampering | ss13 (Proven `SENSOR_INTEGRITY_FAILURE`) |
| registry gating | sk06 |
| live | sk07; `live_send.rs` s_p (`VERIFIED_EXECUTION`), s_a (`ActionEvidenceDoesNotMatch`) |

## Defect found and closed

A host-wide source fires for every process; the probe re-hashed each
sender's executable per event (a 215 MB daemon binary here), and eight
parallel live observers never finished draining. Closed by a per-instance
image cache revalidated by start tick, inode, size, mtime and path, with
unit tests, and by bounded drains in the demonstrator. `ACTION_EVIDENCE.md`
§16.5 records the residual.

## Live run on this host

```
S-P. authorized send, kernel-reported byte count
    agent pid 32369 sent its hello to 127.0.0.1:38287; authorized send to 127.0.0.1:38287; 1 send event(s) captured (send tracer open)
    result=VERIFIED_EXECUTION strength=Attested reason=ActionEvidenceMatches
    action=Match(ActionEvidenceSeal { mechanism: SockSendTracepoint, kind: Transition }) temporal=WithinWindow
S-A. send authorized to a different endpoint
    result=CANNOT_PROVE strength=Heuristic reason=ActionEvidenceDoesNotMatch
    action=Mismatch(ActionEvidenceSeal { mechanism: SockSendTracepoint, kind: Transition })
```

Test counts after Gate 3: aip-standalone 690 / 0 / 3 ignored (+24),
aip-service 39 / 0; clippy `-D warnings` and fmt clean.

## Security Claims

- A `ghost.net.send.v1` verdict cites one collector-signed send event
  bound to the instance and rests on collector-signed transitions of the
  same kernel socket for its endpoint; both are kernel-authored facts
  under the observed host's root — `Attested`, never `Proven`.
- Nothing in the class can name, hash or reveal what was sent.

Not claimed: payload content or any payload digest; that the bytes left
the host or reached the peer; the receive side; UDP or any non-TCP family;
anything on a host whose root starves the ring.

## Next Gate

Gate 4: filesystem / syscall observation, one action, with
OBSERVED / NOT OBSERVED / AMBIGUOUS / LOSS / UNAVAILABLE stated. Candidates
from this host: `syscalls:sys_enter_openat` family tracepoints (714 syscall
tracepoints present) and `fanotify` (`CONFIG_FANOTIFY=y`, `FAN_REPORT_PIDFD`).

---

# Gate 4 — file write, the fourth action class (completion mandate)

## Status

**PASS.** One filesystem action, `ghost.fs.write.v1`, is observable and
reconcilable with its five observation states stated and pinned. The
source is `fanotify` with `FAN_REPORT_PIDFD`: the kernel itself binds the
writing instance to the event, which is stronger attribution than the
pid-number anchoring of the tracepoint classes. Evaluation:
`OBSERVATION_MODEL.md` §6; class: `ACTION_EVIDENCE.md` §17.

## Commits

| Commit | Content |
|---|---|
| `4a5f716` | RED: `aip-observe/tests/fanotify.rs` fa01–fa07, `aip-reconcile/tests/file_evidence.rs` fw01–fw15, `ghost-demo/tests/live_file.rs` f_p/f_a/f_n; did not compile |
| `2f1ba9b` | GREEN: `fs_write_action` / `fs_write_parameters` / `FS_WRITE_ACTION`; `fanotify.rs` (`parse_fanotify_buffer`, `FanotifyWatch`, `FileObservation`); `SourceMechanism::Fanotify` (0x09), `KernelLifecycleKind::FileEvent` (0x09), observer protocol v8; `PidFd::from_raw`; `ProcfsProbe::ingest_file_event` measuring through the kernel's pidfd; `FileWrite` / `derive_file_writes` / `TransitionEvidence::File`; `ActionOutcome::Unresolved { reason }` with `FilePathUnresolved` (0x56); agent `--write`, scenarios F-P/F-A/F-N |
| *(the commit carrying this section)* | documentation |

Test-file edits since RED: rustfmt; one `#[allow(clippy::too_many_arguments)]`
on a fixture; `sk03` (Gate 3) pinned the mechanism count at exactly eight
and now pins "at least eight, all codes distinct". No assertion changed.

## Evidence (mandate's requirements → tests)

| Requirement | Tests |
|---|---|
| one filesystem action | `ghost.fs.write.v1` (`ACTION_EVIDENCE.md` §17) |
| OBSERVED / NOT OBSERVED / AMBIGUOUS / LOSS / UNAVAILABLE stated | fw01, fw03, fw04, fw05, fw06; `OBSERVATION_MODEL.md` §6.4 |
| attribution never from a pid number alone | fa05 (kernel pidfd), fa06 (writer gone → unbound), fw10 |
| explicit hash semantics | fw02 (path bytes only; inode is context; validation) |
| no content claim | fa04 (no content-shaped field), `ACTION_EVIDENCE.md` §17.3 |
| loss counted, never silent | fa02, fw05 |
| registry gating | fa07, fw06 |
| tamper | fw15 |
| live | fa05, fa06; F-P / F-A / F-N |

## Live run on this host

```
F-P. authorized file write, kernel-bound writer
    agent pid 6473 wrote /tmp/ghost-demo-6315/f-p.txt; authorized write to the same path; 1 file event(s) captured on the mount (fanotify open)
    result=VERIFIED_EXECUTION strength=Attested reason=ActionEvidenceMatches
    action=Match(ActionEvidenceSeal { mechanism: Fanotify, kind: Transition }) temporal=WithinWindow
F-A. write authorized for a different path
    result=CANNOT_PROVE strength=Heuristic reason=ActionEvidenceDoesNotMatch  action=Mismatch(… Fanotify, Transition)
F-N. write authorized, never done
    result=CANNOT_PROVE strength=Heuristic reason=ActionEvidenceUnavailable  identity=Match { observations: 2 }  0 file event(s)
```

Test counts after Gate 4: aip-standalone 715 / 0 / 3 ignored (+25),
aip-service 39 / 0; clippy `-D warnings` and fmt clean.

## Security Claims

- A `ghost.fs.write.v1` verdict cites one collector-signed event whose
  writer the kernel bound through a pidfd it created for that process,
  and whose object the kernel resolved to the authorized path; the
  measurement content is procfs — `Attested`, never `Proven`.
- Nothing in the class can reveal, hash or claim what was written.

Not claimed: content; file-handle identity (refused on this host); creates,
deletes, renames; kernel event time (the probe stamps at read); writes on
unmarked mounts; anything on a host whose root removes the mark.

## Next Gate

Gate 5: application / database / proxy sensors — an explicit decision
first (`OT_SENTINEL_HARVEST_AUDIT.md`, Phase H); self-reported logs can be
supporting evidence only and never independent observation.

---

# Gate 5 — application, database and proxy sensors (decision; completion mandate)

## Status

**DECIDED, NOT BUILT.** `APPLICATION_LOG_SENSOR_DECISION.md` (Phase H)
records the decision in the I20 format: such records are statements by
host-side writers, not observation (I16, I22, rule 18); if ever admitted
they form a *supporting* tier with a `Correlated` strength ceiling, a
`Claimed` attribution ceiling, no coverage, no effect on result, strength
or reason, writer-signed under their own domain, with their own RED suite
and protocol bump. No adapter is built by this gate. The fence is
executable: `aip-observe/tests/gate5_no_log_sensor.rs` g5a–g5c and
`aip-warrant/tests/gate5_ceiling.rs` g5d.

## Commits

| Commit | Content |
|---|---|
| *(the fence commit)* | g5a–g5d, all passing against HEAD |
| *(the commit carrying this section)* | the decision document and this section |

## The decisions of spec §8 remain NOT DETERMINED

Who issues `AgentIdentity`; what "agent creation" is for agent lineage;
who holds the reconciler key; profile audience; cross-host identity. These
are product decisions and stay with a human. What this programme has done
is remove their blocking effect where it could: `LINEAGE_VIOLATION` (Gate 1)
is defined over the two lineages that *are* signed today (authority chain,
parent-signed identity proof), so it needs no answer to "who issues
identity" to be reachable; the signed reconciliation record (Gate 7) will
be keyed by whoever runs the verifier, stated as a fifth trust root and
nothing more. A recommended default for each, for the human to accept or
reject, is in `APPLICATION_LOG_SENSOR_DECISION.md`'s companion table below.

| Decision | Recommended default (not adopted) | Why |
|---|---|---|
| Identity issuer | the `ScopedToken` root issuer's organization, signing `AgentIdentityDocument`s under a distinct domain | reuses the one trust root the authority model already has (I18) |
| Agent creation | the first decision-point-signed expectation naming a new `agent_id` whose binding was observed forked by a bound parent | the only definition with a kernel fact and a decision behind it |
| Reconciler key | the verifier operator, separate from the collector | keeps observation and interpretation on different keys |
| Profile audience | internal, per organization | least exposure until SD-13 exists |
| Cross-host identity | none until NEXORA anchors exist (Gate 7) | a `boot_id` is per host by construction |

## Next Gate

Gate 6: the Merkle commitment layer.
