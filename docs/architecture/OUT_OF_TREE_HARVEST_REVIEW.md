# OUT-OF-TREE HARVEST REVIEW — every branch and pull request against Sniffer Dog 2.0

Reviewed at `395dc9d` on `claude/codebase-production-readiness-wm6idp`.
Governing rule: **I17** — anything not merged into HEAD is design input only.
Nothing below is production capability by virtue of existing on a branch.
Each item is classified as one of:

- **HARVEST-DESIGN** — the idea or structure is adopted; implemented here
  RED-first, in this repository's types, under this repository's invariants.
- **ALREADY-COVERED** — HEAD implements the same property, usually more
  strictly; nothing to take.
- **REJECT-INVARIANT** — adopting it would violate a named invariant.
- **DEFER-TO-GATE** — belongs to a later skill gate (8 warrant, 9
  containment, 10 NEXORA); recorded there, not built now.
- **OUT-OF-SCOPE** — unrelated to the security architecture.

## 1. Inventory

| Ref | Branch / PR | State vs `main` | Content (measured, not from the branch name) |
|---|---|---|---|
| B1 | `origin/claude/aip-security-architecture-audit-zpf9b3` | ahead 1 | three skill files: `execution-binding-engineer`, `ghost-reconciliation-engineer`, `ghost-adversarial-tester` (945 lines, no code) |
| B2 / **PR #3 (open)** | `origin/import/orbitaltrust-accountability-layer` | ahead 1, 116 files, 35 673 lines | `orbitaltrust-accountability/`: `ot-accountability-core` (identity, lifecycle typestate, delegation edges, authority journal, hash chain), `ot-sentinel` (11 detectors, two-axis findings, log-tail sensors with stream attestation, restart continuity, response policy), `ot-mcp-gateway`, `ot-verifier`, TypeScript console (agent profile, persistent identity, NEXORA anchors, delegation graph), Python SDK, IDF for typestate authorization |
| B3 | `origin/codex/aip-v4-accountability` | ahead 7, behind 17; merge-base is the initial commit | "AIP v4" protocol modules (`decision.rs`, `graph.rs`, `attestation.rs`, `policy.rs`, `ports.rs`), viewer dashboard, `aegis-quantum` eBPF/XDP + circuit breaker + PQC proxy |
| B4 | `origin/codex/val-ladder-sync` | ahead 29 (superset of B3), behind 17 | everything in B3 plus: `aip-core/src/passport.rs` + `aip-service/src/passport.rs` (Agent Passport phase one), `airon-verify`, Python SDK with LangChain/torch/pandas hooks, hybrid PQC paths, chaos harness, pitch decks, website, notebooks |
| PR #1, PR #2 (closed, merged) | `claude/codebase-production-readiness-wm6idp` at earlier commits | merged into `main` | evidence packets / verifier repositioning; CI, PostgreSQL backend, audit-export bundle |

Existing prior reviews already cover parts of B2 (`PR3_GAP_REVIEW.md`,
`NEXORA_BOUNDARY.md` §1, `CURRENT_SYSTEM.md` §7) and the eBPF part of B3/B4
(`IMPLEMENTATION_PLAN.md`: a bare IPv4 4-tuple `ConnectionKey` with no
process identity). This document extends those to the identity, lineage,
passport, sensor and profile material that Sniffer Dog 2.0 is about.

## 2. Dispositions — B2, PR #3 (OrbitalTrust import)

### 2.1 `ot-accountability-core`

| Capability | What it is | Disposition | Reason / where it lands |
|---|---|---|---|
| `lifecycle.rs` typestate `AgentGenesis → DelegatedAgent → ActiveExecution → RevokedAgent`, each transition appending a hash-chained anchor with an `actorDid` (the supervisor) | a lifecycle **with a named actor** — exactly the property HEAD's `AgentIdentityDocument` lifecycle lacks (gap matrix A.3) | **HARVEST-DESIGN** for the identity-authority decision (spec §8): a lifecycle transition is a record *attributed to an actor*. **REJECT-INVARIANT** as implemented: anchors are unsigned JSON; `actorDid` is a string nobody vouches for; a hash chain is not a protocol (I15) and the chain is unanchored | Phase C records "who caused" as a field that must be signed by that actor before it is anything but `Claimed`; the compile-time ordering idea (IDF) is noted, not adopted — a Rust typestate in a library the agent links is not an independent authority (I1) |
| `authority.rs` `DelegationEdge { parent_did, child_did, scope, clearance, multi_sig, validity, status, signature: Option }`, `resolve_authority` (walk child → root officer, intersect scope, min clearance, union multi-sig, depth ≤ 16) | a delegation **graph** with path resolution — SD-06 | **HARVEST-DESIGN** for Phase D: index by child, walk to root, report the full path and the intersection. **REJECT-INVARIANT** as implemented: `TrustedStoreVerifier::verify` returns `true` unconditionally; edge signature is optional and (TS side) an HMAC whose issuer and verifier share the secret; "latest usable edge wins" is a policy choice that hides forks | HEAD's `DelegationToken` chains are Ed25519-signed per hop with attenuation and expiry checked by `aip_core::verify_delegation_chain`; Phase D builds the graph over those, never over unsigned edges |
| `authority_journal.rs` append-only journal of `Grant`/`Revoke` with replay and `RecoveryReport { torn_tail, unmatched_revokes }` | durable, tamper-evident authority store; revocation as a journal event | **HARVEST-DESIGN** for the revocation-status gap (SD-05) and for Phase E's ledger shape: torn tail and unmatched revoke are good failure names. **DEFER-TO-GATE** (10) for anchoring: a hash chain without an external anchor does not detect truncation (I15) | recorded in `SNIFFER_DOG_2_0_GAP_MATRIX.md` A.8 follow-ups |
| `identity.rs` `PrincipalBinding { method: Unauthenticated/…/Spiffe/PlatformAttestation, credential_digest }`, `CredentialRegistry` rebuilt from enrolment anchors | who called the funnel, and how that was proven | **HARVEST-DESIGN** vocabulary: an identity link has a *method* and a `verified_at`; `Unauthenticated` is an explicit state, never a default `true` | maps onto `LifecycleAssertion::NotEstablished` / `InstanceAssertion::Claimed` in `aip-agent`; nothing to code now |
| `chain.rs`, `stream.rs`, `merkle.rs` | second hash-chain construction, not wire-compatible with `aip-core` (import README says so) | **REJECT-INVARIANT** (I18: one model) | HEAD keeps `aip_types::canonical`; no second encoder |
| `wasm.rs` | browser verifier | OUT-OF-SCOPE for 2.0 |

### 2.2 `ot-sentinel`

| Capability | Disposition | Reason / where it lands |
|---|---|---|
| `finding.rs` two axes `Strength::{Indicator, Corroborated, Proof}` × `Severity`, `capped_at` lowers never raises | **ALREADY-COVERED** — HEAD has `EvidenceStrength::{Heuristic, Correlated, Attested, Proven}` as a separate type (Skill 7), with the central guard capping every content fact at `Attested` | vocabulary mapping recorded for Skill 8: Indicator≈Heuristic, Corroborated≈Correlated, Proof≈Proven; the sentinel has no equivalent of `Attested` (an off-host signer over host facts), which is HEAD's actual ceiling |
| `response.rs` `ResponsePolicy::decide` — containment requires `Proof`, advisory unless `--autonomous`, protected DIDs, evidence-less findings capped at Alert | **DEFER-TO-GATE** (Skills 8/9) — this is a warrant + containment policy, and a well-shaped one | cited as design input in `CONTAINMENT_MODEL.md` §3 lineage; **not** built now (NO CONTAINMENT YET) |
| `reconcile.rs` one-to-one matching of observations to packets on `(tool, params_digest, agent, ±tolerance)`, `executed_despite_denial`, `phantom` only for `covered_tools` | **ALREADY-COVERED**, more strictly: HEAD joins on `decision_id` + structural `ExecutionBinding`, never on tool name + time (I2), and `PHANTOM_CLAIM` needs recomputed process-lifecycle coverage, not a declared tool list | the "phantom requires declared coverage" instinct is the same; HEAD derives coverage from signed batches instead of trusting a flag |
| `RegistrationDetector` — a DID acting that was never born; an agent acting after terminal revocation | **HARVEST-DESIGN** for Phase C/E findings on the profile: `VERIFIED_EXECUTION` after a *signed* retirement is a finding | blocked until a lifecycle authority exists (spec §8); until then `CANNOT_PROVE` |
| `EffectConformanceDetector` + fail-closed `EffectPolicy` allow-lists for egress destinations and spawn commands | an operator policy comparison, not evidence | **DEFER-TO-GATE** (8): this is "was the destination ever approved", i.e. warrant-side policy over `UNATTRIBUTED_EFFECT`; HEAD reaches that class only with a `DecisionPointCoverageStatement` | |
| `ChainIntegrityDetector` (fork, reused sequence, non-recomputing link, temporal anomaly at `Proof`) | **ALREADY-COVERED** — Skill 6 collector ledger: replay, fork, rollback, gap, head mismatch → `SENSOR_INTEGRITY_FAILURE` at `Proven` when recomputable | |
| `state.rs` `ContinuityBreak::{Amnesia, RolledBack, Forked, ArchiveTruncated}` for the sentinel's *own* restart | **ALREADY-COVERED** in mechanism (`Recovering`, `ContinuityUnverified`, probe run id, sequence discontinuity); **HARVEST-DESIGN** for naming: "a forged state file is not a kill switch — the finding names no subject" is a rule worth carrying into Skill 8 | |
| `attestation.rs` `SensorCheckpoint { sensor, offset, stream_tail_hash }` + `deep_verify` (catches same-length retroactive edits of a log file), file identity (dev/inode) rotation detection | **HARVEST-DESIGN** for Phase H *if* an application-log adapter is ever admitted; for the kernel-pushed sources HEAD has, the collector's signed chain already covers the stream | |
| `sensors.rs` `JsonlAccessLog` / `JsonlEffectLog` tailing tool-server and egress logs; `Subject::Claimed(did) / Anonymous` | an **effect-level sensor at the application layer** — the class `RECONCILIATION_IMPLEMENTATION_REPORT.md` lists as not implemented | **DEFER** to Phase H with a decision document like `NEXT_ACTION_EVIDENCE_DECISION.md`: attribution is `Claimed` by the log writer, root-forgeable, no kernel boundary, so its ceiling would be `Correlated`; it must never stand in for coverage. Not chosen ahead of the file class | |
| `LivenessDetector`, `ProbingDetector`, `ModelDriftDetector` | statistical / heuristic detectors | **DEFER-TO-GATE** (8) at `Heuristic` only; HEAD's model digest lives in `ProvenanceTriple` and is not recomputed by anyone | |
| `registry.rs` `AgentRegistry::from_anchors` (known agents, closed, last heartbeat) | **HARVEST-DESIGN** shape for SD-01 lifecycle once an authority signs transitions | |
| `runtime.rs` deployable `sentinel` binary, atomic state, `--strict-continuity` | **HARVEST-DESIGN** for the collector's deployment shape (an operator obligation today) | no code now |

### 2.3 `ot-mcp-gateway`

A decision point on the MCP wire: every `tools/call` adjudicated and sealed
before reaching upstream, signing through a custody trait (`trust.rs`,
`IssuerRegistry`, `SignedEdgeVerifier`). **HARVEST-DESIGN** for
`DECISION_POINT.md` §18 (deployment as a separate process) and as the natural
*producer* of `ExpectedExecution` at the tool boundary. **REJECT-INVARIANT**
for its evidence model (its own packet format and HMAC-era signatures; I18).
Also the natural source of `DecisionPointCoverageStatement`s (Case 3).

### 2.4 TypeScript console

| Capability | Disposition | Reason |
|---|---|---|
| `agent-profile.ts` `AgentEmployeeProfile` (department, clearance, supervisor, `assignedPermissions`, `revocationStatus`, model/prompt digests, enclave, one HMAC signature over everything) | **REJECT-INVARIANT** as a profile: it fuses IDENTITY, AUTHORITY and LIFECYCLE into one self-consistent document signed by the same runtime that verifies it (spec rule E1 in spirit, I18, I19). **HARVEST-DESIGN** for the `ISSUER_DECLARED` partition's field vocabulary: role, organization, supervisor, enclave label with `SOFTWARE_SANDBOX` as the honest default | `aip-agent`'s profile keeps these as separate partitions with separate signers |
| `persistent-identity.ts` — identity carries no permissions; grants are separate, time-bounded, revocable; **`status` is deliberately outside the grant signature** so revocation does not wait for the delegator's key | **HARVEST-DESIGN**, important: this is a considered answer to spec §8 "who may revoke" — a registry-live kill switch separate from issuance. HEAD must decide whether revocation is (a) an issuer-signed record, (b) a separately-keyed revocation authority, or (c) unsigned registry state. (c) is what the AID lifecycle does today and is refused as authority | NOT DETERMINED, now with two concrete options on the table |
| `nexora/*` anchors (`AGENT_GENESIS … ACTION_EXECUTION_SEAL`), packets carry the anchor head, seals name the packet | **DEFER-TO-GATE** (10) — already catalogued in `NEXORA_BOUNDARY.md` | |
| `nexora/delegation-graph.ts` attenuation re-checked at resolution, edges anchored before stored | **HARVEST-DESIGN** for Phase D (same as 2.1 row 2) | |
| UI, voice copilot, tactical tools | OUT-OF-SCOPE |

### 2.5 `docs/IDF-TYPESTATE-AUTHORIZATION.md`

Compile-time ordering of authorize → execute → seal via linear typestates.
**HARVEST-DESIGN** as an engineering pattern for library code paths that must
not skip a step (e.g. a `LineageEdge` cannot exist without both bound ends).
**REJECT** as a security claim: a typestate in the agent's own binary is
enforced by the agent's compiler, not by an independent party (I1, I5); it
prevents *omission by an honest developer*, not *bypass by a hostile agent*,
and the document itself says the sentinel exists because inline enforcement
cannot see its own bypass.

## 3. Dispositions — B3 / B4 (codex branches)

| Capability | Disposition | Reason |
|---|---|---|
| `aip-protocol` v4 modules: `SessionContext`, `derive_decision_id`, `DecisionRecord::create` **signed by the agent**, `ActionAttestation`, `AccountabilityGraph::trust_floor`, `TrustFloorPolicy` | **ALREADY-COVERED / SUPERSEDED**: `main` carries `DecisionRecord`, `ActionAttestation`, `TrustFloor` and `AccountabilityGraph` in `aip-protocol` from PR #1; the independent decision point (Skill 5) exists precisely because an agent-signed decision is not authority (I1) | nothing to take |
| `aip-core/src/passport.rs` `AgentPassport { header{alg}, body{ subject{agent_id, keys}, issuer{id, registry_url, classical_pubkey, pqc_pubkey}, constraints{issued/expires, capabilities: Vec<String>, max_delegation_depth}, lineage: Vec<LineageEntry{actor, action, timestamp, signature}>, environmental_lock{runtime, image_hash} }, proof{signature, pqc_signature} }`, `aip-service/src/passport.rs` Ed25519 verify over `serde_json::to_vec(body)` | **HARVEST-DESIGN** for the identity-issuer decision (spec §8): an **issuer-signed document naming the agent, its key, an environmental lock and a lineage of signed actor/action entries** is the missing SD-01 issuer record. **REJECT-INVARIANT** as implemented: (i) it carries `capabilities` — a second authority model beside `ScopedToken` (I18); (ii) signed bytes are `serde_json::to_vec`, not the injective canonical encoder (I14); (iii) `pqc_pubkey` / `pqc_signature` / `alg` fields present a capability that is not implemented (I7) even though the phase-1 verifier refuses them; (iv) `LineageEntry.signature` is a free string never verified; (v) `image_hash` is a string with a `sha256:unknown` default rather than measured content | the harvested shape for a future `AgentIdentity` issuer record: subject key, issuer, validity, environmental lock as measured `exe_content_sha256`, lineage entries each individually verifiable — **no capabilities**, canonical bytes, Ed25519 only |
| `aegis-quantum` eBPF/XDP `ConnectionKey` (IPv4 4-tuple, no process identity), AF_XDP, LRU maps | **ALREADY REJECTED** (`IMPLEMENTATION_PLAN.md`): telemetry that cannot be attributed to an instance (I2/I3); HEAD's `SockStateTracepoint` binds the initiation to a pidfd-anchored instance instead | |
| `aegis-quantum-circuit-breaker` | **DEFER-TO-GATE** (9); building a breaker now is the `anomaly → kill` shape the architecture forbids (I13) | |
| PQC proxy, hybrid ML-KEM/ML-DSA paths, `pqc-audit.ts`, `PqcAuditStamp` with `SPEC_TARGET` latency provenance | **REJECT-INVARIANT** for any claim (I7, "NO PQC CLAIMS"); the `latencyProvenance` field that refuses to dress a design number as a measurement is the one idea worth keeping | |
| `airon-verify`, Python SDK (`PersistentAgentIdentity.load_or_issue`, LangChain / torch / pandas stamping), notebooks | OUT-OF-SCOPE for the security core; the SDK's "identity is a JWT from the service" model rests on the `aip-service` duplicate authority (P1) | |
| pitch decks, website, dossier bundle | OUT-OF-SCOPE |

## 4. Dispositions — B1 (audit-branch skills)

`execution-binding-engineer`, `ghost-reconciliation-engineer` and
`ghost-adversarial-tester` predate the `syntriass-*` skill set on this branch
and use their own vocabulary (`TrustFloor::ExecutionObserved`, "synthetic
observer first", a result vocabulary for attacks). The orchestrator names an
`adversarial-security-test-engineer` specialist that has **no installed skill
here**; `ghost-adversarial-tester` is the closest candidate.

Disposition: **DEFER to a human decision.** Importing them alongside the
`syntriass-*` skills would create two gate vocabularies for the same stages;
`SECURITY_INVARIANTS.md` forbids a second numbering. Recommended: adopt
`ghost-adversarial-tester` §36–§69 (result vocabulary, attacker models,
method) as the adversarial-validation gate **after** reconciling its terms
with I1–I23, and drop the other two as superseded by Skills 4 and 7.

## 5. What is harvested into code now

Only items that pass the orchestrator's §5 gate today and fall in the next
authorized phase (C — lineage):

| Harvest | Source | Lands as |
|---|---|---|
| Lineage has a *kind* and an *actor*, and the three kinds never merge | 2.1 lifecycle actor; 2.4 identity vs grant separation; spec SD-04 | `aip-agent::lineage`: `identity` (from AID proofs, multi-generation, verified against each ancestor's own validated document), `authority` (full issuer → grantee hop path from verified chains), `process` (kernel edges) — three sections, one type each |
| A process edge exists only with both ends bound and the child's start verified | 2.5 typestate "cannot exist without" | `aip_reconcile::derive_lineage_edges` — a completed, start-verified `ProcessExecution` and nothing less; no `LineageEdge` constructor outside it |
| Attribution of an observed child is a *separate* fact from the edge | 2.2 `Subject::Claimed / Anonymous` | `ChildAttribution::{Unattributed, AuthorizedTarget{agent_id, decision_id}}` — attributed only through a decision-point-signed expectation whose binding matches the child process structurally |
| A parent relation carries how it was established | spec's four-way rule; 2.1 `PrincipalBinding.method` | `IdentityParent::{None, Claimed{..}, Endorsed{..}}` for identity lineage; process relations are always `Observed`; `ReconciledLineage::NotReachable` until the reconciler has a lineage result (Phase C2, after D) |

Not harvested now, with the gate that owns each: revocation journal (SD-05
follow-up), delegation graph resolution (Phase D), issuer-signed identity
record (spec §8 decision), registration-after-revocation finding (Phase E),
application-log sensors (Phase H decision document), response policy
(Skill 8), circuit breaker (Skill 9), anchors (Skill 10), audit-branch skills
(human decision).

## 6. Claims this review does not permit

That any capability on B2–B4 "exists" in this system; that the sentinel's
114 tests or the gateway's 80 tests establish anything about HEAD; that
eBPF, XDP, PQC, a browser verifier, a governed MCP wire, a durable authority
store or a NEXORA chain are implemented here. Each remains `UNMERGED` /
`MISSING` in `GAP_MATRIX.md` until it is rebuilt through this repository's
gates.
