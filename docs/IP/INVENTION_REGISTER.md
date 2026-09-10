# INVENTION REGISTER

This register isolates the mechanisms in this repository that are
technically distinctive, so that each can be found, read, tested and
argued about on its own terms. It is an **engineering** document.

**Engineering implementation is not patentable subject matter.** Whether
any entry here is novel, non-obvious and eligible is a legal question
requiring prior-art search and counsel, and nothing in this file asserts an
answer to it. Every entry therefore carries a `DISCLOSURE STATUS` that says
what has and has not been done, and none of them says "patentable".

Nothing here was invented for this register. Each entry existed in the code
first, was found by reading it, and is described as it is — not as it would
be if it were more impressive. Where a mechanism is partial, the entry says
so. Where an alternative embodiment is genuinely available, it is listed;
where the alternatives are speculative, the entry says that instead of
inventing a list.

Line ranges are given for orientation and will drift; the symbol names are
the durable reference.

---

## IR-01 — Single choke-point verdict precondition

**PROBLEM**
A system that can reach a strong verdict by more than one route has as many
security boundaries as it has routes, and hardening one of them does not
harden the others. Evidence systems accrete these routes naturally: a
convenience constructor here, a test fixture there, a "known good" fast
path for the common case.

**MECHANISM**
There is exactly one function that can produce a `Reconciliation` bearing an
engine provenance, and every strong result — `VerifiedExecution`,
`PhantomClaim`, `IdentityDivergence`, `LineageViolation` — can only arrive
through it. The type is `#[non_exhaustive]` with a crate-private
`provenance` field, so a downstream crate cannot build one with a struct
literal at all. Deserialisation produces `Provenance::Deserialized`, which
`is_engine_produced()` reports as false.

**SOURCE**
- `aip-standalone/aip-reconcile/src/reconcile.rs` — `reconcile_expectation`
  (from ~line 1218), `reconcile_lineage`
- `aip-standalone/aip-reconcile/src/result.rs` — `Reconciliation`,
  `Provenance`, `is_engine_produced`

**PROTOCOL VERSION** `RECONCILIATION_DOMAIN` = `SYNTRIASS/GHOST/RECONCILIATION/v1`

**INVARIANT**
A verdict that no engine drew is not a verdict, and cannot be made into one
by construction, deserialisation or transport.

**TESTS**
- `aip-warrant` — a hand-assembled record is refused with
  `Refusal::ReconciliationNotEngineProduced`
- `aip-nexora/tests/adversarial.rs::t_altered_verdict_cannot_prove_never_becomes_proven`
  (T4: a record that arrived over the wire warrants nothing)
- `aip-reconcile` — the default result is `CannotProve`

**TECHNICAL EFFECT**
The number of code paths that must be audited to trust a verdict is one,
and the compiler enforces it rather than a review convention.

**SECURITY EFFECT**
An attacker who controls a downstream consumer cannot manufacture a strong
finding; they can at most transport one, and transported records are
distinguishable from produced ones.

**ALTERNATIVE EMBODIMENTS**
A capability token carried inside the record and checked by consumers; a
sealed trait with a private witness type; a signed record where the engine
holds the only key. The last is strictly stronger and is not implemented —
the current mechanism is a language-level boundary, not a cryptographic
one, and is stated as such.

**CURRENT STATUS** Implemented and enforced across the workspace.

**DISCLOSURE STATUS** No prior-art search performed. No filing. Public in
this repository's history.

---

## IR-02 — Independent evidence-strength discipline

**PROBLEM**
Most detection systems collapse "how bad would this be" and "how sure are
we" into one number, and then threshold on it. A high-severity guess and a
proven fact become indistinguishable at the point where they matter.

**MECHANISM**
`EvidenceStrength` (`Heuristic`, `Correlated`, `Attested`, `Proven`) is a
separate type from severity, is not ordered against it, and is never
combined into a scalar. There is no `confidence: f32` anywhere in the
evidence path, and no arithmetic that could produce one.

**SOURCE**
- `aip-standalone/aip-reconcile/src/result.rs` — `EvidenceStrength`
- `aip-standalone/aip-warrant/src/warrant.rs` — the two axes stay separate
  through `evaluate`

**PROTOCOL VERSION** encoded by `code()` into the reconciliation domain, v1

**INVARIANT**
Severity and evidence strength are orthogonal, and no operation mixes them.

**TESTS**
- `aip-reconcile/src/result.rs::tests::no_severity_or_score_exists_in_output`
- `aip-warrant` — the HIGH×{Heuristic, Correlated, Attested, Proven} matrix

**TECHNICAL EFFECT**
The type system prevents `severity >= threshold` from being written without
consulting strength.

**SECURITY EFFECT**
A confident-sounding guess cannot cross a boundary that was meant for
proven facts.

**ALTERNATIVE EMBODIMENTS**
A lattice with an explicit join; a pair type with no comparison operators.
Both are refinements of the same idea rather than different mechanisms.

**CURRENT STATUS** Implemented.

**DISCLOSURE STATUS** No prior-art search. Ordered evidence hierarchies are
long-standing in forensics and in evidence law; the distinctive part here is
the refusal to combine, not the hierarchy. Stated so the claim is not
overreached.

---

## IR-03 — Host-authored coverage re-derivation

**PROBLEM**
If a package can state its own observation coverage, the party assembling
it decides what "we were watching" means. Absence of evidence then becomes
whatever the assembler says it is.

**MECHANISM**
A NEXORA package has **no field** in which to state coverage. The verifier
derives `ObservationCoverage` itself from the collector's *signed* health
and the reconciled record, and the five outcomes are kept separate:
`Observed`, `AvailableAndEmpty`, `Ambiguous`, `Loss`, `CannotEstablish`.
Exactly one of them — `AvailableAndEmpty` — licenses a statement about
something not having happened, and `licenses_absence_claim()` is the single
place that says so.

**SOURCE**
- `aip-standalone/aip-nexora/src/verify.rs` — `ObservationCoverage`,
  `derive_coverage` (from ~line 821)
- `aip-standalone/aip-observe/src/health.rs` — `attested_coverage`, the
  signed statement the derivation reads

**PROTOCOL VERSION** `OBSERVER_HEALTH_DOMAIN` = `SYNTRIASS/GHOST/OBSERVER_HEALTH/v1`

**INVARIANT**
Absence of evidence is never evidence of absence, and coverage is never
read from the artifact being checked.

**TESTS**
- `aip-nexora/tests/coverage.rs` — including g6_06, which asserts the
  verifier's coverage vocabulary appears nowhere in a package while the
  collector's signed statement does
- `aip-nexora/tests/adversarial.rs::s_forged_coverage_*`, `q_missing_observation_*`
- `ghost-demo/tests/live_nexora.rs::g14_04` — live, offline

**TECHNICAL EFFECT**
Coverage is a function of signed inputs, computed by the reader.

**SECURITY EFFECT**
A `PHANTOM_CLAIM` cannot be manufactured by asserting coverage that did not
exist; the only path to it runs through attested kernel-pushed coverage of
the exact window.

**ALTERNATIVE EMBODIMENTS**
A signed coverage certificate issued by the collector as a first-class
object (stronger, more machinery); a coverage bitmap over time. Neither is
implemented.

**CURRENT STATUS** Implemented.

**DISCLOSURE STATUS** No prior-art search. No filing.

---

## IR-04 — Keyless probe with off-host collector attestation

**PROBLEM**
An observer whose signing key lives on the observed host is not independent
of it: root on that host forges observations. But observation must happen
on the host, because that is where the kernel is.

**MECHANISM**
The split is between measuring and attesting. `ProcfsProbe` runs on the
observed host, reads kernel sources, and **holds no key material** — the
module says so in its first line and the type has no key field.
`CollectorSigner` holds the key and lives off-host; it registers which
mechanisms each probe is provisioned for and refuses provenance a probe was
not registered for. The verifier separately refuses an observer anchor that
is the observed agent's own key (I10).

**SOURCE**
- `aip-standalone/aip-observe/src/probe.rs` — `ProcfsProbe`
- `aip-standalone/aip-observe/src/attest.rs` — `CollectorSigner`,
  `AttestedBatch`, `register_probe`
- `aip-standalone/aip-nexora/src/verify.rs` — the I10 refusal

**PROTOCOL VERSION** `OBSERVER_HEAD_DOMAIN` = `SYNTRIASS/GHOST/OBSERVER_HEAD/v1`,
`OBSERVE_PROTOCOL_VERSION` = 8

**INVARIANT**
The observed agent cannot be the independent witness to its own execution.

**TESTS**
- `aip-observe/tests/fanotify.rs::fa07` — provenance from an unprovisioned
  probe is refused
- `aip-nexora/tests/audit.rs::a10_the_agent_may_be_neither_its_own_observer_nor_its_own_authoriser`

**TECHNICAL EFFECT**
Compromise of the observed host yields no signing capability.

**SECURITY EFFECT**
Root on the workload host can suppress or corrupt observations — which
becomes visible as loss, a gap, or a continuity break — but cannot forge
attested ones.

**LIMITATION, STATED**
Root on the host can still stop the probe. That produces
`CannotEstablish`, not a false negative dressed as a clean bill of health;
but it is a denial of evidence, and the system does not claim otherwise.

**ALTERNATIVE EMBODIMENTS**
A TPM or secure-element-held key on the host; a hardware root of trust; a
hypervisor-level collector. None is implemented, and no hardware-backed
claim is made anywhere.

**CURRENT STATUS** Implemented in software. Hardware anchoring not
implemented.

**DISCLOSURE STATUS** No prior-art search. Remote log attestation is a
well-populated field; the distinctive part here is the keyless probe plus
mechanism-scoped provisioning, and that is the only part claimed.

---

## IR-05 — Multi-axis warrant ceiling without arithmetic trust scoring

**PROBLEM**
Response engines usually compute a number and compare it to a threshold.
The number hides which input drove it, and any input can dominate.

**MECHANISM**
`aip-warrant::evaluate` maps (severity × evidence strength × policy) onto a
maximum permitted `ResponseClass` by exhaustive match, with no arithmetic
anywhere. `Heuristic` and `Correlated` cannot exceed Alert; `Attested` can
reach Constrain only under explicit operator policy; only `Proven` can
reach Contain, and then only with a warrant. Twenty-four named `Refusal`
variants say which gate closed rather than returning a lower number.

**SOURCE**
- `aip-standalone/aip-warrant/src/warrant.rs` — `evaluate` (line 181),
  `ResponseClass`, `Refusal`

**PROTOCOL VERSION** `WARRANT_DOMAIN` = `SYNTRIASS/GHOST/WARRANT/v1`

**INVARIANT**
No response class is reachable by accumulating weak signals.

**TESTS**
- `aip-warrant/tests/` — the full severity × strength matrix
- `aip-containment/tests/` — the 17 gates in `contain()`

**TECHNICAL EFFECT**
Every decision is traceable to the named rule that produced it.

**SECURITY EFFECT**
An attacker cannot reach containment by inflating one axis, because there
is no summation to inflate.

**ALTERNATIVE EMBODIMENTS**
A policy language evaluated at runtime; a decision table loaded from
configuration. Both trade auditability for flexibility.

**CURRENT STATUS** Implemented. Autonomous containment is off by default and
`ContainmentMode::Advisory` is the default mode.

**DISCLOSURE STATUS** No prior-art search. No filing.

---

## IR-06 — Independent reconciliation before enforcement

**PROBLEM**
If the party that decides what was permitted is also the party that reports
what happened, there is no comparison — only a self-report.

**MECHANISM**
Two independently signed records exist before any judgement: the decision
point's `ExpectedExecution` (what was authorised) and the collector's
`AttestedBatch` (what was observed). They are joined by `decision_id` and
`ExecutionBinding` — never by PID, address, process name or timestamp
alone — and the reconciler compares them without being either party. The
process instance is `(pid, pid_start_time_ticks, boot_id)`, so PID reuse
does not transfer identity.

**SOURCE**
- `aip-standalone/aip-authorize/src/expected.rs` — `ExpectedExecution`
- `aip-standalone/aip-observe/src/attest.rs` — `AttestedBatch`
- `aip-standalone/aip-reconcile/src/reconcile.rs` — the join
- `aip-standalone/aip-types/src/lib.rs` — `ProcessInstance`,
  `EXECUTION_BINDING_DOMAIN`

**PROTOCOL VERSION** `EXPECTED_EXECUTION_DOMAIN` = `GHOST/ExpectedExecution/v1`

**INVARIANT**
Authorisation and observation are different authorities, and neither may
impersonate the other.

**TESTS**
- `ghost-demo/tests/live.rs` — the live scenario matrix, including
  `d_wrong_process_instance_is_identity_divergence_never_verified`
- PID-reuse tests in `aip-reconcile`

**TECHNICAL EFFECT**
The verdict is a function of two independently signed inputs.

**SECURITY EFFECT**
An agent that lies about what it did contradicts the collector's record
rather than defining it.

**ALTERNATIVE EMBODIMENTS**
Three-way reconciliation including a network-side witness (partially
present: the AF_PACKET header tap corroborates but does not attribute).

**CURRENT STATUS** Implemented.

**DISCLOSURE STATUS** No prior-art search. No filing.

---

## IR-07 — Proof-layer re-derivation rather than trust of a claimed verdict

**PROBLEM**
A portable proof that carries a verdict is only as trustworthy as whoever
wrote the verdict into it. Signing the package does not help: it proves who
assembled it, not that the assembled claim follows from the evidence.

**MECHANISM**
The offline verifier ignores the carried result, strength and coverage, and
**re-runs the reconciler** over the package's own inputs under the
verifier's own anchors. It then compares digests: if the record it derived
is not the record the package carries, the package is refused with
`ClaimNotDerivable { claimed, rederived }`. The declared parameters the
original run used travel inside the signed bytes so they cannot be edited,
and the verifier applies its own bounds on what it will accept them to be
(`DeclaredParameterRefused`). A refused package reports no result and no
strength at all.

**SOURCE**
- `aip-standalone/aip-nexora/src/verify.rs` — `verify_nexora_proof`,
  `rederive` (from ~line 688), `InvalidReason`
- `aip-standalone/aip-nexora/src/bin/nexora-verify.rs` — the same, offline,
  as a process

**PROTOCOL VERSION** `PROOF_BUNDLE_DOMAIN` = `SYNTRIASS/NEXORA/PROOF_BUNDLE/v1`,
`NEXORA_PROOF_VERSION` = 1

**INVARIANT**
`CANNOT_PROVE` cannot become `PROVEN` through packaging, export, import or
transport.

**TESTS**
- `aip-nexora/tests/adversarial.rs` — the twenty cases A–T
- `ghost-demo/tests/live_nexora.rs::g14_05` — eight mutations of a *live*
  package, each refused by a separate verifier process

**TECHNICAL EFFECT**
Verification is a pure, deterministic function of a package and a set of
anchors, with no clock and no network.

**SECURITY EFFECT**
The strongest statement a package can support is bounded by its evidence,
regardless of who assembled it or what they wrote in it.

**ALTERNATIVE EMBODIMENTS**
A zero-knowledge proof of correct reconciliation (would remove the need to
ship the evidence; not implemented, and would be a different system); a
threshold of independent re-derivers.

**CURRENT STATUS** Implemented, and demonstrated end-to-end from a live run.

**DISCLOSURE STATUS** No prior-art search. No filing.

---

## IR-08 — Cryptographic continuity integrated into execution evidence

**PROBLEM**
A collector that restarts, is rolled back, forks, or loses its archive can
silently resume as though nothing happened, and its later records then
appear to cover a window they never saw.

**MECHANISM**
The collector maintains a hash-chained head across restarts and reports its
own breaks under its own key. `ContinuityBreak` names four kinds —
`Amnesia`, `RolledBack`, `Forked`, `ArchiveTruncated` — and
`ContinuityPolicy::Strict` (the default) refuses to resume rather than
resuming quietly. `SignedContinuityReport` carries the statement to a
verifier, which maps any reported break to `ContinuityStanding::Discontinuous`
and never to `Continuous`. Store corruption is `StoreError::Corrupt`, never
treated as absence.

**SOURCE**
- `aip-standalone/aip-observe/src/runtime.rs` — `CollectorRuntime`,
  `ContinuityPolicy`, `ContinuityReport`, `CONTINUITY_REPORT_DOMAIN`
- `aip-standalone/aip-observe/src/store.rs` — `CollectorStore`,
  `StoreError::Corrupt`
- `aip-standalone/aip-nexora/src/verify.rs` — `ContinuityStanding`

**PROTOCOL VERSION** `CONTINUITY_REPORT_DOMAIN` = `SYNTRIASS/GHOST/CONTINUITY_REPORT/v1`

**INVARIANT**
A break is never read as continuity, and continuity is never assumed across
a gap.

**TESTS**
- `aip-observe/tests/` — restart, rollback, fork and truncation
- `ghost-demo/tests/live_collector_restart.rs` — live
- `aip-nexora/tests/adversarial.rs::i_continuity_rollback_*` — every break
  variant, exhaustively

**TECHNICAL EFFECT**
Coverage claims are bounded by a verifiable chain rather than by a process
lifetime.

**SECURITY EFFECT**
Rolling back or restarting a collector does not launder a gap into
coverage.

**ALTERNATIVE EMBODIMENTS**
External anchoring of the collector head (would additionally defeat
truncation by a party who controls both the collector and its archive; the
NEXORA commitment layer provides the mechanism, and anchoring it externally
is an operational step this repository does not perform).

**CURRENT STATUS** Implemented. External anchoring: interface present,
not exercised against any external service.

**DISCLOSURE STATUS** No prior-art search. Hash-chained logs are extremely
well known; the distinctive part claimed here is the explicit break
taxonomy carried as signed evidence into a downstream verdict, not the
chain.

---

## IR-09 — Identity, authority, execution and observation kept separate

**PROBLEM**
Systems that conflate "who this is", "what it may do", "what ran" and "what
was seen" cannot express the interesting failures — an authorised agent
running the wrong binary, an unauthorised action by a known identity, a
process nobody can attribute.

**MECHANISM**
Four separately signed layers with separate domains and separate trust
roots: identity (`AID_SELF_SIGNATURE_DOMAIN`), authority
(`SCOPED_TOKEN_DOMAIN`, `DELEGATION_TOKEN_DOMAIN`), execution
(`EXECUTION_BINDING_DOMAIN`, content-hashed executable rather than path),
and observation (`OBSERVATION_BATCH_DOMAIN`, `KERNEL_EVENT_DOMAIN`).
Lineage is likewise split three ways — identity, authority, and
execution-process — and never synthesised from similar identifiers: an
absent edge yields `LineageStanding::Unavailable`, which
`asserts_a_link()` reports as false.

**SOURCE**
- `aip-standalone/aip-core/src/lib.rs`, `capability.rs`, `delegation.rs`
- `aip-standalone/aip-types/src/lib.rs` — `ExecutionBinding`
- `aip-standalone/aip-nexora/src/verify.rs` — `LineageReport`,
  `LineageStanding`

**PROTOCOL VERSION** 26 distinct domain tags; see
`aip-nexora/tests/audit.rs::DOMAINS`

**INVARIANT**
Forging one kind of link cannot borrow another kind's standing.

**TESTS**
- `aip-nexora/tests/audit.rs::a01` — all 26 domains distinct, namespaced,
  versioned, and non-prefixing once encoded
- `aip-nexora/tests/adversarial.rs::h_lineage_substitution_*`
- `aip-nexora/tests/lineage.rs`

**TECHNICAL EFFECT**
A signature over one semantic object is never valid over another.

**SECURITY EFFECT**
The failure modes above are expressible and distinguishable, rather than
collapsing into a single "suspicious" state.

**ALTERNATIVE EMBODIMENTS**
A single signed envelope with a type discriminator (weaker: one key
compromise spans all four layers).

**CURRENT STATUS** Implemented.

**DISCLOSURE STATUS** No prior-art search. Domain separation is standard
cryptographic practice; what is claimed here is the four-layer split with
independent trust roots and the three-way lineage taxonomy, not domain
separation itself.

---

## What this register does not claim

- No entry is asserted to be novel or non-obvious. Several build directly
  on well-established practice, and each entry says which part is the
  distinctive one.
- No entry is asserted to be patentable. That requires prior-art search and
  legal analysis, neither of which has been done.
- Nothing was added to the system in order to appear in this register.
- Post-quantum cryptography, hardware-backed key storage, kernel-resident
  eBPF/XDP sensing and field deployment appear nowhere above, because none
  of them is implemented.
