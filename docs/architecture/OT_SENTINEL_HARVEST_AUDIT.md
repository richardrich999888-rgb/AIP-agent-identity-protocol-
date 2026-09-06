# OT-SENTINEL HARVEST AUDIT — PR #3 forensic inventory and mapping (Phases 0–3)

Ground truth established at `54984f2` on
`claude/codebase-production-readiness-wm6idp`. Nothing in this document is a
capability of HEAD; it inventories what PR #3 contains and decides what may
be harvested through this repository's gates. Companion to
`OUT_OF_TREE_HARVEST_REVIEW.md` (all branches, shorter) and
`PR3_GAP_REVIEW.md` (the earlier corrective review of PR #3's authority
claims).

## Phase 0 — ground truth

### A. Branch identity and commit graph

| Item | Value |
|---|---|
| current branch | `claude/codebase-production-readiness-wm6idp` at `54984f2` |
| main | `origin/main` at `872dbf3` (Merge PR #2) |
| PR #3 | open, "Import: OrbitalTrust accountability layer (side-by-side, not merged)", head `6cc439f190161ba28e76d46cea1901de8dd527ea`, base `872dbf3` |
| branch containing `ot-sentinel` | `origin/import/orbitaltrust-accountability-layer` — one commit, `6cc439f` (2026-08-28), "Import the OrbitalTrust accountability layer from ASC-space" |
| merge base with main | `872dbf3` (PR #3 is exactly one commit ahead of main, zero behind) |
| merge base with HEAD | `872dbf3` (our branch and PR #3 diverged from the same point) |
| files unique to PR #3 | 116, all under `orbitaltrust-accountability/`; **zero files outside it** — PR #3 touches nothing in `aip-standalone/`, `aip-service/` or `docs/` |
| upstream provenance | `MANIFEST.md`: source commit `af2f4d965eb13aae89b96e6a10f72ff671de969a` of the `ASC-space` repository; 114 files, 35 440 lines, per-file SHA-256 |
| superseded by main | nothing — there is no overlap in paths; conceptual overlaps are in §B/§M |

### B. Unique files, packages, modules

| Package | Lines (Rust) | Modules | Builds here? |
|---|---|---|---|
| `rust/ot-accountability-core` | 4 700 | `aip.rs` (funnel, co-signature), `authority.rs` (delegation edges, resolve), `authority_journal.rs` (append-only grant/revoke journal, replay), `chain.rs`, `identity.rs` (principal binding, credential registry), `lifecycle.rs` (typestate genesis→delegated→active→revoked), `merkle.rs`, `stream.rs`, `wasm.rs` | yes (serde, serde_json, sha2) — see A.1a |
| `rust/ot-sentinel` | 8 013 | `attestation.rs` (sensor stream checkpoints), `conformance.rs` (egress/spawn allow-lists), `detector.rs` (11 detectors), `finding.rs` (kind × strength × severity), `observation.rs` (effects, subjects, sensors), `patrol.rs`, `reconcile.rs`, `registry.rs`, `response.rs` (response policy), `runtime.rs` (deployable loop, state, archive), `sensors.rs` (JSONL tail, rotation, deep verify), `state.rs` (restart continuity), `time.rs`; `bin/sentinel.rs`; `tests/ghost_hunt.rs` | library and unit tests: yes; `ghost_hunt` integration tests: **no** — dev-depends on `ot-mcp-gateway` and `ot-pqc` |
| `rust/ot-mcp-gateway` | 6 653 | governed MCP proxy, keyring, identity (ML-DSA challenge), provision, trust (issuer registry, signed edge verifier), session, sink, upstream, optional mTLS HTTP | **no** — depends on `ot-pqc`, which is **not in the import** (it lives in the ASC-space workspace) |
| `rust/ot-verifier` | 2 045 | offline verifier CLI, report | **no** — depends on `ot-pqc` |
| `rust/ot-api-governance/governance.rs` | 1 file | fleet governance ingestion | not a crate |
| `rust/workspace-Cargo.toml` | — | the ASC-space workspace (26 members, of which 4 are here) | — |
| `typescript/` | — | agent identity (profile, persistent identity, registry, store, permission guard), accountability ledger + exporter + verifier, NEXORA (anchors, delegation graph, store, verifier), governed dispatch, PQC audit, UI, 11 test suites | not evaluated here (no Node toolchain in scope) |
| `python-sdk/otgovern` | — | cross-language seal check | not evaluated |
| `docs/` | — | `ACCOUNTABILITY_PRODUCT_LINE.md`, `IDF-TYPESTATE-AUTHORIZATION.md` | read |

**Consequence:** the gateway, the verifier and the sentinel's end-to-end
scenarios (`ghost_hunt.rs`, 39 scenarios) cannot be built or run from this
repository as imported. Their test counts are claims of the import README
(80 / 11 / 114), not results reproduced here.

#### A.1a Reproduced build and test results (scratch workspace, pinned deps)

Extracted `orbitaltrust-accountability/rust` from `6cc439f` into a scratch
workspace with pinned third-party versions (serde 1, serde_json 1, sha2
0.10, tempfile 3) and the unbuildable dev-dependencies removed:

| Crate | Target | Result |
|---|---|---|
| `ot-accountability-core` | `--lib` unit tests | **56 passed, 0 failed** (matches the README) |
| `ot-sentinel` | `--lib` unit tests | **82 passed, 0 failed** |
| `ot-sentinel` | `tests/ghost_hunt.rs` (31 end-to-end scenarios incl. the six restart scenarios) | **does not build** — imports `ot_mcp_gateway` and `ot_pqc` |
| `ot-mcp-gateway`, `ot-verifier` | any | **do not build** — depend on `ot-pqc`, absent from the import |

So 138 of the ~260 Rust tests PR #3 claims are reproducible here; the
end-to-end escape/containment/restart scenarios are not. Their properties
were re-established in this repository's own tests where harvested.

### C. Unique capabilities (what PR #3 has and HEAD does not)

| # | Capability | Where |
|---|---|---|
| C1 | Application-layer **effect sensors** tailing JSONL access and egress/spawn logs, with per-sensor stream-hash checkpoints, rotation detection by device/inode, and `deep_verify` that recomputes a stream from a sealed checkpoint to catch same-length retroactive edits | `sensors.rs`, `attestation.rs` |
| C2 | **Sentinel self-continuity**: persisted `PatrolState`, an external archive of the sentinel's own sealed anchors, and `verify_continuity` classifying a resumed state against the archive as Amnesia / RolledBack / Forked / ArchiveTruncated; refusal of state from another sentinel; `--strict-continuity` | `state.rs`, `patrol.rs`, `runtime.rs` |
| C3 | **Response policy** (two-axis warrant): containment requires proof; advisory default; uncited findings capped; protected DIDs | `response.rs` |
| C4 | **Effect conformance**: fail-closed allow-lists for egress destinations and spawn commands | `conformance.rs`, `detector.rs` |
| C5 | Behavioural detectors: liveness (silence while effects continue), probing (breadth of denials), model drift (digest in packets vs chain), registration (never-born / acting after terminal revocation), principal (unauthenticated caller) | `detector.rs` |
| C6 | **Deployable runtime**: cycle loop, atomic state write, archive append, deep-verify cadence | `runtime.rs`, `bin/sentinel.rs` |
| C7 | Delegation **graph resolution** over edges with scope intersection, clearance minimum, multi-sig union | `authority.rs` |
| C8 | **Authority journal**: append-only hash-chained grant/revoke with replay and recovery report | `authority_journal.rs` |
| C9 | Typestate **lifecycle** with an actor per transition | `lifecycle.rs`, IDF |
| C10 | **Governed MCP gateway** (funnel, default-deny methods, sealed tickets, custody trait, ML-DSA challenge identity) | `ot-mcp-gateway` |
| C11 | NEXORA anchors, delegation graph, verifier (TypeScript) | `typescript/telemetry/nexora` |
| C12 | Browser/WASM verifier, Python cross-language seal check | `wasm.rs`, `python-sdk` |

### D. Dependencies between capabilities

```
sensors (C1) ──► attestation checkpoints ──► state/continuity (C2) ──► runtime (C6)
   │                                              ▲
   └──► observation ──► reconcile ──► detectors (C5) ──► finding ──► response (C3)
                            ▲                                ▲
gateway (C10) ── packets ───┘        conformance (C4) ───────┘
core: lifecycle (C9) ── anchors ──► registry ; authority (C7) ◄── journal (C8)
```

### E. Cryptographic / signing changes

- Hash chain: `seal_hash(prev_hex ‖ canonical_json)` → hex; `GENESIS_HASH` =
  64 zeros. Canonical form is `serde_json` with sorted keys. **Not**
  wire-compatible with HEAD's `aip_types::canonical` (binary,
  length-prefixed, domain-tagged).
- Signatures in `ot-accountability-core`: none over anchors (anchors are
  hash-chained JSON; `actorDid` is a string). Delegation edge `signature:
  Option<Value>`; `TrustedStoreVerifier::verify` returns `true`.
- Signatures in the gateway: ML-DSA via `ot-pqc` (absent here); HMAC on the
  TypeScript side.
- No domain-tag mechanism comparable to HEAD's; domain separation is by JSON
  field names.

### F. Observation / kernel / network changes

- **No kernel code.** `git grep` for `unsafe`, `ebpf`, `XDP`, `cgroup` in
  `orbitaltrust-accountability/rust`: zero hits.
- Sensors read **files written by other software** (tool servers, proxies);
  subject attribution is whatever `agentDid` the log line carries
  (`Subject::Claimed`) or `Anonymous`.
- The product-line document itself: "Sensors beyond files — Roadmap … no live
  eBPF/syscall/cloud-audit adapters exist in-repo (the sovereign overlay's
  eBPF module is a user-space policy model, no kernel loader)".

### G. Enforcement / containment changes

- `response.rs`: `Response::{Observe, Alert, Constrain, Quarantine,
  Terminate}`; `ResponsePolicy::decide` requires `Strength::Proof` for
  `Quarantine`, advisory unless `autonomous`, protected DIDs exempt.
- `EnforcementAction` is sealed into the sentinel's own chain.
- Actuation = **authority revocation** through the gateway's authority store
  (`the_full_circuit_closes … the_agent_really_loses_authority`). No process
  kill, cgroup, XDP or firewall anywhere.

### H. Ledger / Merkle / provenance changes

- Per-agent hash-chained anchor lists and packet lists; `merkle.rs` helpers;
  `ChainIntegrityDetector` (fork, reused sequence, non-recomputing link,
  temporal anomaly at `Proof`).
- `authority_journal.rs`: hash-chained JSONL of grant/revoke events with
  replay, torn-tail and unmatched-revoke reporting.
- No externally anchored head; truncation of a whole chain is undetectable
  by the chain alone (the sentinel's archive comparison is the one
  cross-record check, and only for the sentinel's own chain).

### I. Continuity / recovery changes

- `verify_continuity(sentinel_did, resumed_sequence, resumed_tail, archive)`
  → `Amnesia` (resumed at genesis, archive non-empty), `RolledBack`,
  `ArchiveTruncated`, `Forked` (same sequence, different hash).
- `Patrol::resume` refuses state whose `sentinel_did` differs.
- The break latches and is reported every patrol at `Proof`/`Critical`,
  **naming no subject** so a forged state file cannot become a kill switch
  against an agent.
- Runtime writes state before archive so a crash between the two reads as
  `ArchiveTruncated` (recoverable) rather than `Forked`.

### J. Test additions

| Crate | `#[test]` count (measured) | README claim |
|---|---|---|
| `ot-accountability-core` | 56 | 56 |
| `ot-sentinel` | 113 (incl. 39 `ghost_hunt` scenarios) | 114 |
| `ot-mcp-gateway` | 80 | 80 |
| `ot-verifier` | 11 | — |
| TypeScript | not counted | 117 |

Restart scenarios in `ghost_hunt.rs`: amnesia caught by archive; resumed
sentinel extends its chain; baseline survives restart; rollback caught;
break reports without revoking the sentinel; foreign state refused.

### K. Benchmark / performance evidence

None in PR #3. Performance claims live on the `codex` branches
(`aegis-quantum/README.md`: "TRL-4", "8–15 µs packet latency", "10 Gbps+
wire speed", "~30x faster"). Their benchmark code measures a userspace
circuit-breaker map and Kyber operations with `criterion`; there is no XDP
throughput harness, no NIC/driver/kernel record, no loss counters, and the
XDP validator is a Scapy script with a `--dry-run` mode. **No performance
claim is reproducible from either branch.**

### L. Experimental or unsafe

- ML-DSA / Kyber usage (gateway, aegis) — post-quantum claims, prohibited
  here (I7) and unbuildable here (crate absent).
- `TrustedStoreVerifier` accepting every edge.
- Anchors and lifecycle transitions unsigned.
- HMAC with shared secret on the console side (issuer = verifier).
- Statistical detectors (probing, liveness) — heuristic by construction; the
  sentinel itself caps them at `Indicator`/`Corroborated`.

### M. Conflicts with current main architecture

| PR #3 | HEAD | Conflict |
|---|---|---|
| second identity/authority/evidence model (DIDs, edges, JSON chains) | `aip-core` tokens, `aip-protocol` packets, `aip_types::canonical` | **I18** one authority model; **I14** injective canonical encoding |
| observer trust = the sentinel's own process, on the observed host, reading files root can edit | probe/collector split, key off-host | **I5, I10** |
| `Strength` three-level (Indicator/Corroborated/Proof) | `EvidenceStrength` four-level with `Attested` as the ceiling for content facts | vocabulary; HEAD's is stricter |
| `Subject::Claimed(did)` from a log line is the attribution | pidfd-anchored `ExecutionBinding` compared structurally | **I2, I3** |
| `PHANTOM_CLAIM` (`phantom`) from a declared `covered_tools` list | coverage recomputed from signed batches with process-lifecycle mechanism | **I8** |
| reconciliation keyed on `(tool, params_digest, agent, ±30 s)` | keyed on `decision_id` + structural binding | **I2** |
| revocation as actuation inside the detector pipeline | warrant (Skill 8) → containment (Skill 9) as separate gates | stage order |

## Phase 1 — capability matrix against the Sniffer Dog specification

Columns: spec capability · PR #3 · current HEAD · best implementation · test
evidence · security status · integration required · notes. "EXISTING-UNMERGED"
marks something PR #3 (or a codex branch) has and HEAD does not.

| # | Spec capability | PR #3 | HEAD | Best | Test evidence | Security status | Integration | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | Independent kernel observation | none (file tails) | perf tracepoints via `perf_event_open`, pidfd anchors, off-host signer | **HEAD** | Stage 6.5/7b/7c fixtures + live | attested; root can starve | none | PR #3 has no kernel path |
| 2 | eBPF / tracepoint instrumentation | none | static tracepoints via perf, **no eBPF** | HEAD (tracepoints) | live tests | — | none | eBPF exists only as an unattributable prototype on codex (`aegis-quantum`), EXISTING-UNMERGED, rejected (I2) |
| 3 | exec / process observation | `Effect::ProcessSpawn{command}` from a log line | `sched_process_fork`/`exec`, image content hash | **HEAD** | xe01–xe16, X-P..X-C live | attested | none | |
| 4 | socket / network observation | `Effect::NetworkEgress{destination, bytes}` from a log line | `sock:inet_sock_set_state` transitions + socket tables | **HEAD** | te*, T-* live | attested | none | |
| 5 | packet / wire observation | none | none | — | — | — | none | codex XDP prototype EXISTING-UNMERGED, no process identity; **MISSING everywhere as attributable evidence** |
| 6 | filesystem / syscall observation | none | none | — | — | — | Phase H decision document | MISSING everywhere |
| 7 | action evidence | tool invocation, egress, spawn effects (app layer) | `ghost.net.connect.v1`, `ghost.process.exec.v1` (kernel) | HEAD for kernel; **PR #3 EXISTING-UNMERGED for application-layer effects** | ghost_hunt (not runnable here) | PR #3: claimed attribution, root-forgeable | Phase H: application-log adapter with `Correlated` ceiling | see Phase 3 C1 |
| 8 | payload / parameter digesting | `params_digest = sha256(canonical_json(params))` of the tool call as the log recorded it | `ActionParameters` digest of what the decision point authorized; kernel metadata only (I23) | HEAD for authorization side; PR #3 EXISTING-UNMERGED for *observed* application parameters | — | observed digest comes from a log the host writes | Phase H | the spec's "hash of the raw payload" is only ever what a log writer recorded |
| 9 | execution binding | none | `ExecutionBinding` (pid, start ticks, boot id, image content) | **HEAD** | Skill 4 tests | — | none | |
| 10 | process identity anchoring | none | pidfd anchors, start-tick rule | **HEAD** | | | none | |
| 11 | PID reuse defences | none | start ticks + boot id + content hash | **HEAD** | xe04, le05 | | none | |
| 12 | parent/child process lineage | none (spawn effect names a command string) | `LineageEdge` from bound fork/exec | **HEAD** | le01–le07 | attested | none | |
| 13 | agent identity lineage | typestate genesis with supervisor actor (unsigned) | AID lineage proofs across generations (parent-signed) | **HEAD** (signed) | l01–l03 | | none; actor-per-transition idea recorded for the identity-authority decision | |
| 14 | authority lineage | delegation edges + resolve (unsigned edges, verifier `true`) | signed token chains, `DelegationGraph` (Phase D) | **HEAD** | d01–d11 | | none | shape harvested in Phase D |
| 15 | agent-to-agent attribution | `Subject::Claimed` | peer expectation structural match, `Ambiguous` reported | **HEAD** | l05–l08 | | none | |
| 16 | expected execution | gateway seals a packet per call (agent-side funnel) | `ExpectedExecution` signed by an independent decision point | **HEAD** | Skill 5 | | none | gateway is the *deployment shape* for a DP (design input) |
| 17 | decision-point signatures | ML-DSA in gateway (unbuildable) | Ed25519 DP key, anchors, `DecisionKeyIsAgentKey` | **HEAD** | | | none | |
| 18 | gateway integration | `ot-mcp-gateway` (default-deny MCP proxy, sealed tickets) | none | PR #3 EXISTING-UNMERGED | 80 tests (claimed) | second evidence model; ML-DSA dep | **rejected as code; harvested as DP deployment design** | see Phase 3 C10 |
| 19 | append-only event/trace ledger | per-agent JSON hash chains; authority journal | collector-signed batch chain (heads, sequences); no persistence | PR #3 EXISTING-UNMERGED for *durable* journal shape | core tests | unanchored | Phase E (2.0) | |
| 20 | Merkle commitment/tree/root | helpers only | helpers only (`merkle_leaf/internal/empty`) | neither | — | — | Skill 10 | MISSING everywhere |
| 21 | phantom-claim detection | `phantom` if tool ∈ declared `covered_tools` | recomputed process-lifecycle coverage over the window | **HEAD** | t-series, xe15 | | none | |
| 22 | unattributed-effect detection | `unattributed` when no packet matches | requires `DecisionPointCoverageStatement` (no producer) | PR #3 EXISTING-UNMERGED (reaches the class); HEAD stricter (refuses without completeness) | | PR #3 infers absence of authorization from absence of a packet in *its* ledger | **Skill 5 follow-up**: coverage statements | HEAD's refusal is the correct conservative reading (I8) |
| 23 | reconciliation | tool/params/time matcher | decision-id + structural binding, 8 classes | **HEAD** | Skill 7 | | none | |
| 24 | observer attestation | none (sentinel on host) | collector off-host, signed batches/health | **HEAD** | Skill 6 | | none | |
| 25 | coverage / loss accounting | sensor checkpoint liveness, `CoverageGap` finding | `ENOBUFS`, `PERF_RECORD_LOST`, sequence discontinuity, per-mechanism coverage | **HEAD** | | | none | |
| 26 | warrant system | `ResponsePolicy` | **`aip-warrant` (Skill 8, `9574420`)** | HEAD (harvested design) | w01–w19 | signed warrant | done | |
| 27 | proof-gated enforcement | authority revocation on `Proof` | none (Skill 9 not started) | PR #3 EXISTING-UNMERGED (revocation actuation) | | actuation inside detector pipeline | **Skill 9**, not now | |
| 28 | XDP / network isolation | none | none | — | — | — | Skill 9 | codex prototype EXISTING-UNMERGED, rejected |
| 29 | cgroups / process containment | none | none | — | — | — | Skill 9 | MISSING everywhere |
| 30 | strict continuity | `--strict-continuity`, `verify_continuity` | ledger `note_restart` → `Recovering`/`Unverified`; no persistence, no archive comparison | PR #3 EXISTING-UNMERGED for the four-way audit | restart scenarios (not runnable here) | archive comparison is arithmetic | **HARVEST (Phase 4, C2)** | |
| 31 | crash / reboot recovery | atomic state write, archive append order | none | PR #3 EXISTING-UNMERGED | | | HARVEST with C2 | |
| 32 | tamper-evident observer history | sentinel seals its own enforcement/attestation anchors | collector signs health heads; no self-archive | PR #3 EXISTING-UNMERGED for the self-archive | | | HARVEST with C2 (archive = signed health records) | |
| 33 | offline verification | `ot-verifier` (unbuildable), TS verifier | `aip-verify`, `verify_packet`, reconciler | HEAD | | | none | |
| 34 | replay | reused sequence detection | `Replay`/`Fork`/`Rollback` faults; packet replay P1 gap | HEAD | | | none | |
| 35 | NEXORA boundary | anchors + seals (TS), lifecycle anchors (Rust) | boundary document only | PR #3 EXISTING-UNMERGED | | unanchored JSON chains | Skill 10 | |
| 36 | post-quantum boundaries | ML-DSA via `ot-pqc` (absent), PQC stamps | `AlgorithmId::MlDsa65` label refused as unimplemented | HEAD (honest refusal) | | **prohibited claim** | none | |
| 37 | air-gapped operation | `AIR_GAP_ENCLAVE_TRANSFER` anchor type only | none | neither | | | none | a label, not a capability |
| 38 | OT / industrial runtime | none (space-domain overlay in ASC-space, not imported) | none | neither | | | none | |
| 39 | autonomous machines beyond AI agents | none | none | neither | | | none | |
| 40 | tests and live demonstrations | 260 unit/integration tests claimed, 0 kernel | 613 tests incl. live kernel suites (`ghost-demo`) | HEAD | see §8 of the harvest report | | none | |

## Phase 2 — security review of each candidate capability

| Cap. | Trust assumptions | Keys / controller | Agent can forge? | Observer forgeable? | Independent? | Timestamps | Identity transplant | PID reuse | Reboot | Loss detectable | Network completeness | Positive from insufficient evidence? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| C1 log sensors | the log writer is honest and the file is not edited between write and tail | none (hash chain, no signature) | yes — the agent can write to a log it has access to; `agentDid` is a string | yes — root on the host edits the file; `deep_verify` catches edits only after a checkpoint sealed before them | no (same host, same trust domain as the workload) | log writer's clock | trivially (string DID) | n/a | checkpoints survive only with C2 | partially (rotation, shrink) | n/a | `matched` requires `params_digest` equality within tolerance — a positive **correlation**, not proof; `phantom` from a declared list is a positive from a *policy* |
| C2 self-continuity | the archive is held somewhere the resumed process cannot rewrite in the same stroke | none | n/a (about the observer) | the check is arithmetic on two records | yes, if the archive is separately held | none needed | n/a | n/a | **this is the reboot mechanism** | yes (four-way) | n/a | no — a break is a negative finding about the observer, never a workload verdict |
| C3 response policy | none beyond the finding's own strength | — | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | structurally no (proof required) — **harvested as Skill 8** |
| C4 conformance | the allow-list is correct and complete | operator | no | n/a | n/a | n/a | n/a | n/a | n/a | n/a | destination strings only | a positive "unauthorized egress" from *policy membership*, not from evidence about authorization — a warrant-side input, not a reconciliation result |
| C5 detectors | statistical | — | partly (an agent can shape its own rate) | — | — | log clocks | — | — | — | — | — | capped at Indicator/Corroborated by PR #3 itself |
| C7 graph | edge store is honest (`verify` = `true`) | delegator (HMAC, TS) | yes (unsigned edges) | — | — | ISO strings | yes | — | — | — | — | yes — resolves authority from unverified edges; **rejected**, rebuilt over signed tokens in Phase D |
| C8 journal | file integrity between writes | none | — | — | — | — | — | — | replay with torn-tail report | — | — | no positive; a source of revocation truth if signed |
| C9 lifecycle | actor string honest | none | yes (unsigned anchors) | — | — | ISO strings | — | — | — | — | — | yes — a lifecycle anchor asserts a supervisor acted with no signature |
| C10 gateway | the agent routes through it | gateway ML-DSA keys | bypass, not forgery (the sentinel exists for the bypass) | — | it *is* the funnel | — | ML-DSA challenge | — | — | — | — | no; but its evidence model is a second one |

**Safety rule check.** Every PR #3 positive verdict that rests on
insufficient evidence — `matched` on digest+time correlation, `phantom` from
a declared tool list, `unattributed` from absence in the sentinel's own
ledger, `resolve_authority` over unverified edges, lifecycle actor strings —
is **not** harvested. HEAD's `CANNOT_PROVE` semantics are retained in full.

## Phase 3 — dispositions

| Subsystem | Disposition | Why |
|---|---|---|
| C3 response policy | **B adapted → done (Skill 8, `9574420`)** | shape retained; rebuilt over `EvidenceStrength` (four levels), `ReconciliationResult`, `EvidenceRef`, signed warrant |
| C2 self-continuity (snapshot, archive comparison, foreign-state refusal, four-way break) | **B adapted → Phase 4 of this mandate** | main's collector has restart → `Recovering` but no persistence and no archive audit; the arithmetic is sound and observer-only |
| C7 graph resolution | **C merged with stronger HEAD → done (Phase D, `f96e51a`)** | rebuilt over signed chains |
| C1 log sensors + stream attestation | **B adapted, deferred to a Phase H decision document** | a genuine additional evidence class (application-layer effects, parameters as recorded) with a `Correlated` ceiling and `Claimed` attribution; must never stand in for coverage; needs its own RED suite and observer protocol bump |
| C4 conformance | **E retained as design for Skill 8/9 policy** | policy membership is warrant-side |
| C5 detectors | **E** | heuristic; Skill 8 already caps Heuristic at Alert; no evidence class in HEAD yields them |
| C6 runtime | **B, partially with C2** (state/archive discipline); the binary itself **E** | HEAD's collector deployment is an operator obligation |
| C8 journal | **E → Phase E input** (revocation truth) | unsigned hash chain; would need a signer and an anchor |
| C9 lifecycle | **D rejected as code; A as design input** | unsigned actor; typestate is not independent enforcement |
| C10 gateway | **D rejected as code (I18, unbuildable); A as DP deployment design + coverage-statement producer** | |
| C11 NEXORA TS | **D now; Skill 10 input** | |
| C12 WASM/Python | **D** | out of scope |
| codex `aegis-quantum` | **D** | unattributable telemetry; containment prototype; PQC claims |

Main's canonical authority model remains authoritative throughout. No
duplicate identity, delegation or evidence engine is introduced.
