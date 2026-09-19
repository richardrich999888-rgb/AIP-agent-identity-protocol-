# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Security (pre-evaluation fixes for a supervised BFSI pilot)
- **The second authority engine in `aip-service` is gone.**
  `POST /v1/identity/delegate` and `POST /v1/identity/verify-chain` — unsigned
  delegation tokens whose keyless hash omitted `scope` and `expires_at`, no
  attenuation at issuance, an unauthenticated chain verifier that answered
  ADMIN for a bare root JWT — are removed together with
  `aip-service/src/{delegation,capability}.rs` and `AIP_DELEGATION_LOG_PATH`.
  Delegated authority is expressed only by signed `aip-core` chains inside
  evidence packets. The discovery document (`AipConfiguration`, `aip-types`)
  no longer advertises a delegation endpoint (`delegation_verify_uri`
  removed — a wire change to an unsigned discovery document).
- **Revocation is a tenant-scoped, authenticated fact.** `RevocationEntry`
  carries `tenant_id` (from the administrator's API key, never the body);
  the in-memory set is keyed `(tenant, jti)`; identity JWTs carry the
  minting tenant as a `tid` claim and are checked against their own tenant's
  revocations; `GET /v1/identity/revocation-status/{jti}` requires a key and
  answers for the caller's tenant only (it was a public oracle over every
  tenant's log); `cascade` is refused rather than silently ignored; JTIs are
  canonicalised to 32 hex characters so a UUID JWT id and a 16-byte evidence
  JTI share one spelling. Pre-tenancy log lines load under the legacy tenant
  with their original hash.
- **`POST /v1/evidence/verify` consults the server-side revocation set.**
  The caller's `revoked_jtis` are unioned with the tenant's revocations
  recorded through `POST /v1/identity/revoke`; a revoked chain JTI fails
  `REVOCATION` whether or not the caller lists it. Tests:
  `aip-service/tests/revocation_scope.rs` (HTTP level, two tenants).
- **The two-host observer can now sign `IntegrityUnknown`.** `ObservationBatch`
  gains `mechanism_integrity: Vec<MechanismIntegrityReport>` — the probe's
  per-sensor foreign-eBPF finding — inside the attested bytes
  (`OBSERVE_PROTOCOL_VERSION` **9 → 10**; version-9 batches are refused).
  `aip-probe` reports every open tracer every cycle; `CollectorSigner`
  absorbs reports fail-closed (a `Verified` report counts only for a
  mechanism the batch declares active); `aip-collector`'s sink treats a
  declared gate-able sensor with no report as `Unverifiable`. `ghost-demo`
  now declares findings into the probe so the demo and the pilot share one
  path. Tests: `aip-collector/src/sink.rs`; ledger §OI rows OI-09..OI-12.
- **The pilot probe drives the netlink process-event connector**
  (`AIP_PROBE_SENSORS=...,connector`; `CAP_NET_ADMIN` and `AF_NETLINK` added to
  the systemd unit). It is the pilot's only gate-independent kernel-pushed
  source and the only coverage the reconciler accepts for a process-lifecycle
  non-occurrence claim; without it `PHANTOM_CLAIM` was unreachable in the
  pilot topology. `ENOBUFS` is recorded as counted loss.

### Added (RBI requirements coverage — R12, R13: supply chain and storage)
- **Release artefacts are signed (R12).** `release.yml` signs each archive
  with keyless Sigstore and then **verifies the signature it just produced**,
  under the same identity constraints a downloader uses. An unverified
  signing step is a step that can silently stop signing; this one fails the
  release instead. No long-lived signing key exists, so there is none to leak
  or rotate. `VERIFYING.md` ships with the release and says plainly that
  omitting the identity flags accepts any Sigstore signature ever issued, to
  anyone, which is not a check.
- **The evidence store's immutability is now the database's property, not the
  service's (R13).** `deploy/sql/hardening.sql`, applied once by the owning
  role: the service connects as a role holding SELECT and INSERT only.
  A fully compromised service still cannot delete or alter a stored packet,
  because the connection it holds was never granted the privilege.
- **Legal hold binds the operator too.** A `BEFORE DELETE` trigger refuses to
  remove a held packet even for the role that runs the retention job — a hold
  the operator can step around is not a hold. Holds are per packet or
  tenant-wide, and a tenant-wide hold covers packets stored after it was
  placed. Releasing it restores retention.
- **Retention floor is a constraint.** 180 days (CERT-In) as a CHECK, so a
  misconfigured policy is refused at write time rather than discovered at an
  inspection.
- **Row-level security closes the single-forgotten-WHERE disclosure.** The
  policy reads `aip.tenant_id`, which the store now sets inside each
  transaction (`is_local`, so a pooled connection cannot carry one request's
  tenant into the next). A connection that declared no tenant sees nothing:
  failing closed is the whole value of the control. `count()` consequently
  reports zero under RLS, because a cross-tenant total is exactly what tenant
  isolation forbids.
- The store tolerates a database it may not provision: DDL refused for lack
  of privilege is followed by confirming the tables exist, so a restricted
  role starts cleanly while a genuinely unprovisioned database still fails
  loudly at startup rather than on the first request.
- **These are proven, not asserted.** `aip-service/tests/storage_controls.rs`
  runs against a real PostgreSQL and checks what the database refuses: the
  service role's DELETE, UPDATE, TRUNCATE, DROP and `DISABLE ROW LEVEL
  SECURITY`; an unfiltered SELECT crossing tenants; an undeclared
  connection; a held packet against the owner; a 90-day retention policy.
  They are `#[ignore]` rather than self-skipping, so an unconfigured run
  reports them as *ignored* instead of *ok* — the failure mode the audit
  recorded in the existing Postgres suite.
- **Not done, stated:** backup, disaster recovery and a tested restore drill.
  Immutability is not durability; a table nobody can delete from is still lost
  with its disk.

### Changed — wire (RBI requirements coverage — R5: container identity)
- **`EXECUTION_BINDING_VERSION` is 2.** `ExecutionBinding` gains
  `container: Option<ContainerIdentity>`. The version is inside both the full
  and the identity encodings, so a v1 binding and a v2 binding never produce
  equal bytes even when every other field agrees: **existing stored bindings
  do not match newly collected ones, and a deployment upgrades both sides
  together.** No packet format changed; `PACKET_VERSION` is untouched.
- **What v1 could not see.** Two containers on one host, running the same
  image, whose processes the kernel gave the same PID in different PID
  namespaces and which started in the same clock tick, agree on every v1
  field. A payments agent and a reporting agent would reconcile against each
  other's evidence. `ContainerIdentity` carries the pid, mount and network
  namespace inodes — the only stable identifiers a namespace has — and those
  three are the identity.
- **The cgroup v2 id is recorded context, not identity.** It is in the full
  canonical encoding and deliberately absent from `identity_bytes`: a
  cgroup-v1-only host exposes none, and making it load-bearing would withdraw
  container identity from those hosts entirely; and a process migrated
  between cgroups is still the same execution.
- **Absence is not difference.** `ExecutionBinding::compare_execution`
  returns a reason rather than a boolean, and distinguishes
  `DifferentContainer` (the kernel separates these workloads — a positive
  finding v1 could not make) from `ContainerNotComparable` (exactly one side
  recorded an identity). A consumer that collapsed those two would let an
  un-instrumented collector manufacture divergences out of its own
  blindness. The collector records all three namespaces or none, never a
  partial identity, and never zeros — zeros are a real container.
- `aip-core` reads `/proc/<pid>/ns/{pid,mnt,net}` link text and the cgroup id
  under the cgroup2 mount. A read failure costs container identity, never the
  whole binding: a binding without it is weaker, not wrong.
- **Not done, stated:** `aip_observe::ObservedProcess` does not carry the
  field, so the observer cannot yet assert container identity independently
  and the reconciler cannot compare it. That is an observe-protocol version
  bump and is folded into R8, where the probe is being changed anyway.

### Added (RBI requirements coverage — R6, R7: what the offline verifier can establish)
- **A verifier can now require that something other than the agent decided
  (R6).** `VerificationContext::independent_authority_required`
  (`aip-verify --require-independent-authority`) fails `AUTHORITY_CHAIN`
  when the acting agent is its own authority root. Both spellings are
  caught: the declared principal being the agent, and the root token's
  issuer being the agent, so relabelling one does not evade the other. The
  default is unchanged, because some deployments are legitimately their own
  principal — but a self-issued pass is no longer silent: the rule's detail
  says the root is the agent itself and that independence was not
  established. Self-issuance is not recorded as tamper evidence; nothing was
  altered.
- **Revocation is a signed, time-bounded document (R7).**
  `aip_protocol::RevocationList` (AIP_SPEC §4.4): domain
  `AIP/RevocationList/v1`, length-prefixed canonical encoding, every field
  inside the signature, entries sorted and unique so one set of revocations
  has one encoding, a per-issuer `sequence` so a replayed older list is
  visible as older, and an `issued_at`/`valid_until` window the verifier
  places against its own instant. `verify_revocation_list` is the only way
  to obtain a `VerifiedRevocationList`, so the engine cannot be handed a
  list nobody checked or one that has expired.
- **The vacuous revocation pass is gone.** `REVOCATION` previously reported
  "no token in the authority chain is revoked" whenever the verifier's set
  was empty — a claim about the world made by a verifier that had not looked
  at the world. It now separates three states: a hit in any source FAILS
  (whatever the source's freshness: a revocation does not lapse); a usable
  source with no hit PASSES **citing that source**, including the admission
  that a bare identifier list carries no issuer, issue time or expiry; and
  no usable source is NOT EVALUATED, naming what was missing. An expired or
  unanchored list lands in the third state, which is the R7 acceptance
  criterion. `valid` is unaffected, since it already ignored unevaluated
  rules.
- `aip-verify` gains `--revocations`, `--trust-revocation-issuer
  <id>:<version>=<hex>` and `--require-independent-authority`. A list
  supplied without `--at`/`--now` is refused at the command line rather than
  applied against an assumed present. A list that fails to verify is carried
  into the report as the reason the rule could not be evaluated, not dropped
  with a warning the operator may scroll past.
- First tests for the `aip-verify` binary itself (7): the compiled command,
  real files, exit codes and printed output — because the library being
  correct is not the same as the command being correct.

### Added (RBI requirements coverage — R4: the tool boundary)
- **A mandate can carry transaction parameters without carrying them.**
  `aip-authorize` gains the `ghost.tool.invoke.v1` action class
  (`tool_invoke_action`, `tool_invoke_parameters(tool_id, params_commitment)`,
  `MAX_TOOL_ID_LEN`, `ToolInvokeError`). The decision point seals a tool
  identifier and the agent SDK's domain-separated commitment to the canonical
  tool arguments (`aip_airi::parameter_commitment`) into the expectation's
  parameter digest; the arguments themselves (an amount, a beneficiary) enter
  no signed document. No existing action class or digest changes.
- **A third signer at the tool boundary.** `aip-airi::ToolReceipt`, signed by
  the institution's tool gateway (`GatewaySigner`, `GatewayTrustAnchors`,
  `verify_tool_receipt`): the gateway's own recomputation of the commitment
  over the request it actually received, the decision it cited, the agent it
  named, and what the gateway did with it (`GatewayDisposition`). Domain
  `GHOST/AIRI/ToolReceipt/v1`, length-prefixed canonical encoding, every
  field inside the signature. A gateway anchored under the agent's own key is
  refused (`GatewayKeyIsAgentKey`), as a decision point (I1) and an observer
  (I10) are.
- **Authorized versus received versus claimed.** `aip-airi::compare_tool_boundary`
  recomputes the sealed digest from the verified receipt through the same
  `tool_invoke_parameters` the decision point used and names the outcome:
  `ReceiptDoesNotMatchAuthorization` (what reached the system is not what was
  authorized, whatever the agent said), `ClaimDoesNotMatchAuthorization` (the
  request was in order; the agent misreported it), `Agrees` with the claim's
  standing, or `NotEvaluated` with a reason — an absent receipt is a coverage
  statement, never a finding. Built on AIRI's existing `ToolInvocation`; there
  is no second tool-call layer. Like `AiriAnnotation` and `aip-approval`, the
  outcome sits beside a reconciliation and is not a verdict: engine
  integration remains gated (ADR-016 §gate).
- **The kernel side says nothing about this class, on purpose.** The
  reconciler derives no action evidence for `ghost.tool.invoke.v1` and
  returns `ACTION_EVIDENCE_UNAVAILABLE` even with a kernel-pushed socket
  transition on the authorized instance claimed under the decision
  (`aip-airi/tests/tool_boundary.rs`, 12 tests, real engine). A socket is not
  a tool call and is not matched to one.
- Not done, stated: committing receipts to NEXORA (a twelfth leaf kind is a
  wire change and is batched with the next one); policy over plaintext
  amounts at the decision point (the decision point receives a commitment; a
  policy engine that needs the arguments is a separate, DPDP-scoped design).

### Merged (branch consolidation before further roadmap work)
- `claude/vanian-audit-maturity-addendum-n5ysvd`: `aip-enforce` (seccomp
  user-notify execve gate under a signed `CapabilityEpoch`), `aip-interlock`
  (dead-man heartbeat, actuator watchdog), `aip-approval` (shown-versus-
  authorized over two signed artefacts). Its ADR-008/009 are renumbered
  ADR-015/016 to avoid colliding with the skill-25 series.
- `claude/skill-25-implementation-xbz0t3`: `aip-conformance` (invariant ×
  domain matrix, threat × layer execution log, substitution and versioning
  suites), `aip-industrial`, `aip-space`, `aip-enterprise`, ADR-008..014,
  mutation-assurance results and the regression tests they produced in
  `aip-nexora` and `aip-reconcile`.
- Both branches pinned the proof tree at nine leaf kinds and observe protocol
  9; the tree is at eleven kinds and protocol 10. Six pins moved to 11 with
  corrected rationale; conformance blocker B-10 now accepts the equivalent
  `cargo test --workspace` this CI runs. Full workspace green after both
  merges.

### Added (RBI requirements coverage — R2, R3)
- **Resource-scoped authority at the decision point (R2).** A resource grant
  is a `res:<id>` entry in the existing signed capability scope
  (`aip_registry::resource_scope_action`), so it is covered by the issuer's
  signature and attenuates down the delegation chain with **no change to any
  token's wire format**; explicit deny overrides. `DecisionPoint::
  with_resource_policy(ResourcePolicy)` adopts the institution's registry
  after verifying it; adjudication reads the network destination from the
  same parameter bytes the expectation signs, resolves it, and denies
  `DestinationMalformed`, `DestinationUnregistered` (an unnamed system is not
  a permitted one) or `ResourceNotGranted`. The resolved name is kept out of
  the expectation's parameter digest, which must stay exactly what the
  reconciler recomputes. Without a policy no resource check runs, and the
  decision point says so. Resource ids are capped at 60 bytes so a grant
  fits a `Custom` action. Tests: `aip-authorize/tests/resources.rs`.
- **Per-agent access ledger (R3).** `aip-ledger::AccessLedger`: for one
  agent over one window, every endpoint reached (socket effects and
  kernel-pushed connect initiations attributed to the agent), resolved
  against a verified registry revision it cites, with the reconciler's
  signed verdicts cited to rows through the observation, kernel event or
  claimed decision they reference. Results and strengths verbatim; a row's
  `Standing` is a fixed summary never above its citations; verdicts that
  match no row are counted, not dropped. Signed by a fifth authority
  (`LedgerSigner`), canonical order enforced at verification, offline
  verification under `LedgerTrustAnchors`. `aip-nexora` gains
  `LeafKind::AccessLedger` (0x0b), `commit_access_ledger` and
  `verify_committed_ledger`. Tests over a real probe and collector
  (`aip-ledger/tests/ledger.rs`) and over the real-engine
  `VERIFIED_EXECUTION` fixture committed to a log
  (`aip-nexora/tests/access_ledger.rs`). Three profile pins move from ten to
  eleven leaf kinds.
- IPv4 layout: the registry and the decision point's destination parser use
  the observer's layout (first four bytes of the 16-byte field), so all
  three resolve identical bytes.

### Added (RBI requirements coverage — R1)
- **`aip-registry`**: the institution's signed, versioned registry of named
  network resources (address ranges, ports, protocol, criticality). Entries
  are sorted and pairwise non-overlapping at signing, so resolving an
  observed endpoint is a total, deterministic function: exactly one
  resource, or `Unregistered` — an answer, never an inference. Verified
  offline against the institution's anchor; every downstream artefact cites
  `(registry_id, revision)` so a later edit cannot re-label past evidence.
  Depends on `aip-types` and `aip-crypto` only. 21 tests: signing, every
  post-signing edit detected, impostor key, overlap and malformation
  refusals, resolution including v4/v6 non-confusion.
- `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`: every requirement the RBI
  ecosystem places on an agent deployment, each with one disposition —
  EXISTS (code and test named), BUILD (roadmap item R1–R20 with acceptance
  test), INTEGRATE (who supplies it), or OUT OF SCOPE (named owner).

### Added (research)
- `docs/pilot/RBI_AGENT_RISK_MAP.md`: where AI agents will create failures in
  the RBI-regulated ecosystem (ten classes, from mandate violations and
  phantom work to blinded monitoring and agent-payment liability), the
  regulatory clock from CERT-In 2022 through the June 2026 MRM draft and
  fraud-liability amendment to NPCI's agent protocol, and for each class what
  this repository proves, what it does not, and which instrument it serves.
  Secondary sources flagged for primary verification before use with RBI.

### Fixed (documentation and delivery that did not match the code)
- `deploy/docker/Dockerfile` built against `aip-standalone/Cargo.toml`, which
  no longer exists; it now builds from the single root workspace and ships
  `nexora-verify` alongside `aip-service`, `aip-migrate` and `aip-verify`.
  `docker-compose.yml` fails fast when `AIP_KEY_PASSPHRASE` is unset instead
  of letting the service `exit(1)` in a restart loop.
- `release.yml` ships `nexora-verify` (the only offline verifier for Ghost
  verdicts and NEXORA proofs); release artifacts are described as
  checksummed, not signed.
- `AIP_SPEC.md` §5 documents rules R15–R18 and the three-state outcome
  (`valid` covers evaluated rules only); design-partner documents say 18
  rules, not 14. `PRODUCTION_READINESS.md`: container image, compose and
  release rows corrected from ✅ to 🟡 with the reason; the signed
  audit-export bundle row corrected from ⬜ to ✅ (it shipped).
- `aip-edge/tests/nexora.rs` pinned the NEXORA leaf list at nine; SD-10
  added the tenth (`SignedReconciliation`). The pin now says so.

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