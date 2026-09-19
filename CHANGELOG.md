# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added (expected-side completeness — `UNATTRIBUTED_EFFECT` reachable)
- **Decision-point coverage statements, produced from a ledger.** The
  decision point (`aip-authorize`) now records every `ExpectedExecution` it
  signs in an in-process `DecisionLedger` and issues
  `DecisionPointCoverageStatement`s from it
  (`DecisionPoint::coverage_statement(agent_id, window, issued_at_ms)`). The
  decision list is **computed, never supplied**; the producer refuses a
  window before its declared epoch (`with_coverage_ledger`) or not yet closed
  at issue time; and once a statement is issued, a decision for that agent
  at or before the attested `to_ms` is denied
  (`DenialReason::AttestedWindowClosed`, new variant) so the statement cannot
  be falsified afterwards. Check, signature and append share one guard.
- **`UNATTRIBUTED_EFFECT` fires live.** `ghost-demo` scenario B now attaches
  the decision point's statement over the observed window and reconciles to
  `UnattributedEffect` / `Attested` / `NoExpectationAttested` from a real
  process, the real observer and the real reconciler; new scenario **B-U**
  (`ExecutedNotExpectedUnattested`) pins that the same observation without a
  statement stays `CannotProve` / `ExpectedSideCompletenessUnknown`.
- **Type moves, no wire change.** `CoverageWindow` now lives in `aip-types`
  (re-exported unchanged from `aip-observe`; gains `is_well_formed` and
  `intersects`); `DecisionPointCoverageStatement`, `CoverageStatementError`
  and the coverage domain/version constants moved from `aip-reconcile` to
  `aip-authorize` and are re-exported from `aip-reconcile` at their old
  paths. Domain string, version, preimage and verification rule are
  unchanged.
- Tests: producer attacks `aip-authorize/tests/coverage.rs` (P-01..P-14);
  live attacks `ghost-demo/tests/live_coverage.rs` (CS-01..CS-06); ledger
  unit tests. Ledger `docs/security/ADVERSARIAL_RESULTS.md` §CS;
  `docs/architecture/DECISION_POINT.md` §16a states the restart contract.
  Chosen over SD-11 (a `NexoraProof` version bump that buys packaging, not a
  new security property).

### Added (committed verdicts — SD-10)
- **Signed verdicts committed to NEXORA, verifiable offline.** New
  `LeafKind::SignedReconciliation` (code `0x0a`, appended; earlier codes
  frozen) commits `SignedReconciliation::canonical_bytes()` — the verdict
  *plus* the reconciler's signature, under its own domain
  (`SYNTRIASS/GHOST/SIGNED_RECONCILIATION/v1`, distinct from the signing
  preimage's) so stored bytes can never pose as something the reconciler
  signed. `aip_nexora::commit_signed_verdict` appends one;
  `aip_nexora::verify_committed_verdict` lets a party holding only the proof,
  the signed verdict and its own anchors establish, in order: the reconciler's
  attestation (reconciler anchors), the inclusion under an anchored head
  (NEXORA anchors), that the leaf is a signed-verdict leaf (a bare verdict
  relabelled is refused), and that the committed bytes are *this* verdict's,
  recomputed from the struct — never trusted from the proof. Result and
  strength are carried verbatim, never raised. Both new domains registered in
  the Gate-13 domain audit (now 28, prefix-free). Tests over real-engine
  verdicts: bare-leaf relabel, proof-for-another-verdict, untrusted reconciler,
  post-commit tamper, unanchored head, and preimage/commit domain separation.
  Closes SD-10; SD-11 (signed verdict inside `NexoraProof`, a version bump)
  and SD-12 (`nexora-verify` surface) remain.

### Added (reconciliation attestation — SD-09)
- **Signed reconciliation verdicts.** `aip-reconcile` gains a fourth authority
  that signs its verdict: `ReconcilerSigner` (custody-based, so the key may be
  wrapped or off-host) produces a `SignedReconciliation`, verified offline with
  `SignedReconciliation::verify` against `ReconcilerTrustAnchors` the verifier
  supplies. The signature covers a domain-separated
  (`SYNTRIASS/GHOST/RECONCILIATION_ATTESTATION/v1`), length-prefixed preimage
  binding the envelope version, reconciler id, key version, and the verdict's
  own canonical bytes — so a verdict's bytes cannot be replayed as an
  attestation and identity/version fields cannot be swapped. Signing attributes
  the verdict; it never strengthens it (a `CannotProve` stays `CannotProve`).
  No existing signed struct, canonical encoder, or wire version changed —
  additive new signed object. Adversarial tests (mutation, swapped id, untrusted
  key/version, foreign-key forger, bare-verdict-signature domain confusion,
  unsupported version) plus a real-engine end-to-end test
  (`ghost-demo/tests/signed_verdict.rs`). Closes SD-09; unblocks SD-10 (NEXORA
  commit of the signed verdict).

### Added (two-host pilot — Phase 1)
- **`aip-transport`** — an authenticated probe↔collector channel over blocking
  TCP (std only; no async runtime). Length-prefixed frames bounded before
  allocation; an Ed25519 challenge/response handshake and a per-frame signature
  over a domain-separated preimage (session nonce + strictly increasing
  sequence + `sha256(batch)`). Evidence-agnostic: it carries opaque batch bytes
  and holds no evidence key. Refuses replay, reorder, tamper, oversize, and an
  unlisted probe key. Unit + loopback tests.
- **`aip-collector`** — the off-host collector daemon. Attests authenticated
  batches under a wrapped signing key, binds each batch to its authenticated
  probe id, persists chain state, keeps a fresh signed health record, and fails
  closed on a continuity refusal. An operator-controlled JSON allow-list gates
  which transport key may submit as which probe id.
- **`aip-probe`** — the host-side probe daemon. Drives `aip-observe`'s perf
  sensors (sched, sockstate, socksend), ships unsigned batches to the collector,
  and holds a transport-auth key only — never an evidence key.
- **Custody-composable collector runtime.** `CollectorRuntime::start_with_custodian`
  and `CollectorSigner::resume_with_custodian` (plus `CollectorKey::into_custodian`)
  let the persistence/continuity runtime resume under a wrapped-file custodian
  without the raw key ever entering the process as bytes. `resume` now delegates
  to the custody path, so there is one continuity implementation. No signed
  field, canonical encoder, verification rule, or protocol version changed.
- **End-to-end proof** (`aip-collector/tests/e2e.rs`): a probe ships a real
  `ObservationBatch` over TCP to a collector holding a wrapped key; the
  resulting `AttestedBatch` verifies offline against the collector's public key;
  an unlisted transport key is refused with nothing attested.
- Design record `docs/pilot/PHASE1_DAEMONS.md`; `deploy/pilot/` updated to the
  built, env-driven daemons.

### Security
- **Observer integrity boundary (observation-integrity finding).** A foreign
  eBPF program on a tracepoint Sniffer Dog samples suppresses that tracepoint's
  perf submission host-wide with no dropped-record accounting, so a live,
  continuity-verified observer can be silently blind — and, before this change,
  still sign `Active` coverage and let a blinded window drive a `PhantomClaim`.
  Fixed, fail-safe and strictly monotone (it can only turn a coverage claim
  into `CannotProve`, never the reverse):
  - New `ObserverState::IntegrityUnknown`, carried inside the signed
    `SensorHealth`, set when the collector detects a foreign tracepoint gate.
  - `PerfTracepoints::foreign_bpf_program_count` (via `PERF_EVENT_IOC_QUERY_BPF`)
    and `ProcessTracer::mechanism_integrity` — the synchronous, fail-closed
    detector.
  - `covered_by_kernel_pushed_source` now requires a gate-independent
    kernel-pushed mechanism (netlink connector / `fanotify` / `AF_PACKET`); a
    lone perf-tracepoint mechanism no longer licenses a non-occurrence claim.
  - Reconciler maps `IntegrityUnknown` to `cannot_prove(ObserverIntegrityUnknown)`.
  - **Wire change:** `OBSERVE_PROTOCOL_VERSION` 8 → 9 (additive state code
    `0x06`; all in-tree records rebuild against v9). `CANNOT_PROVE`,
    `EvidenceCeiling` and the single reconciler authority are unchanged.
  Specs: `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`,
  `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`,
  `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md`; reproduction in
  `validation/observation_integrity/`.
- **Observer integrity boundary — extended to every perf sensor and wired
  live.** The first cut detected the foreign tracepoint gate only on the
  `sched` process tracepoints. An adversarial pass found
  `sock:inet_sock_set_state` and `sock:sock_send_length` still went silently
  blind. Now closed, fail-safe and monotone, with no wire change
  (`MechanismIntegrity` is not serialized; state code `0x06` already ships):
  - `SockStateTracer::mechanism_integrity` and
    `SockSendTracer::mechanism_integrity` added, all three perf sensors routed
    through one fail-closed `MechanismIntegrity::from_foreign_program_query`.
  - New `MechanismIntegrity::Unverifiable` for a refused kernel query, distinct
    from a *found* gate and failing closed identically.
  - `CollectorSigner::note_mechanism_integrity` is keyed per `SourceMechanism`
    (worst-of), so a clean reading cannot mask a gated one; state self-heals
    when the gated mechanism clears.
  - The detector is wired into `ghost-demo`'s live drain, not only the
    validation recorder.
  - New adversarial ledger `docs/security/ADVERSARIAL_RESULTS.md`; live
    before/after evidence sealed under
    `validation/observation_integrity/results/20260917T_*` via
    `validation/observation_integrity/pipeline_under_gate.sh`.

### Added
- **Signed audit-export bundle.** `GET /v1/evidence/{id}/export` returns a
  portable `application/zip` (evidence, verification report JSON + Markdown,
  authority graph JSON + DOT, manifest, Ed25519 bundle signature) for offline
  verification by auditors/regulators. New `aip-protocol::bundle`
  (`build_zip`/`verify_zip`), raw Ed25519 helpers in `aip-crypto`, and
  `aip-verify bundle.zip` (PASS/WARNING/FAIL). Spec: `docs/AUDIT_EXPORT_SPEC.md`.
  Tenant-scoped export (cross-tenant → 404); every tamper scenario flips a
  named bundle check (tested in `aip-protocol/tests/bundle.rs` and an
  in-process HTTP test).

### Added (storage)
- **PostgreSQL Evidence Vault backend.** New `EvidenceStore` trait with two
  implementations: `JsonlEvidenceStore` (the original append-only file) and
  `PostgresEvidenceStore` (feature `postgres`) — durable, transactional,
  tenant-isolated. Handlers depend only on the trait; backend chosen at
  runtime via `AIP_STORE_BACKEND` (`jsonl` default | `postgres`) + `DATABASE_URL`.
- Schema: `evidence_packets` (+ tenant/hash/created_at indexes) and
  materialised, tenant-isolated `authority_nodes` / `authority_edges`
  (`deploy/sql/schema.sql`; applied idempotently on startup under an advisory
  lock).
- `aip-migrate` tool: idempotent JSONL → PostgreSQL import preserving each
  record's tenant (requires `--features postgres`).
- `aip-service` converted to lib + bins (`airon-aip`, `aip-migrate`).
- Live-DB integration tests (store/get/all/count, cross-tenant isolation,
  tenant-conflict, authority materialisation) gated by `AIP_TEST_DATABASE_URL`;
  10k-packet benchmark (`pg_benchmark_10k`, `--ignored`).
- `docs/BACKUP_AND_RECOVERY.md`, `docs/STORAGE_PERFORMANCE.md`; docker compose
  now wires PostgreSQL as the primary backend with a healthcheck.

### Changed
- Authority graph is now built from a supplied packet list
  (`AuthorityGraph::from_packets`), making it storage-backend agnostic.

### Added (prior)
- `aip-verify`: standalone offline EvidencePacket verifier CLI for auditors
  (`cargo install --path aip-standalone/aip-verify`). Verifies integrity with
  no configuration; accepts trusted issuer/counterparty keys and a revocation
  list for full authority verification.
- GitHub Actions: `ci.yml` (fmt, clippy `-D warnings`, test, audit, deny,
  best-effort coverage), `security.yml` (cargo-audit, gitleaks, trivy),
  `release.yml` (multi-target binaries → GitHub Release).
- 