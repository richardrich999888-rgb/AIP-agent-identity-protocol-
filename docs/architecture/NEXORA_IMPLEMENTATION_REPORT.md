# NEXORA IMPLEMENTATION REPORT

Skill 10 — provenance, portable proof and offline verification.

**Baseline** `82da7a6` · **This report** `87db6da` · branch
`claude/codebase-production-readiness-wm6idp`

Every claim below is backed by a named test that runs in this repository.
Where something is not implemented, the section says so rather than
describing the design as though it were the implementation. §13 is the list
of things this system must not be said to do.

---

## 1. The exact proof object

`aip_nexora::proof::NexoraProof`, `NEXORA_PROOF_VERSION = 1`, canonical
bytes under `SYNTRIASS/NEXORA/PROOF_BUNDLE/v1`.

| field | what it carries | signed by |
|---|---|---|
| `version` | format version, inside the signed bytes | — |
| `issued_at_ms` | when the package was assembled | — |
| `subject` | the agent id, and optionally its identity document | the agent's own key, self-signed |
| `authority` | the root `ScopedToken` and the `DelegationToken` chain | each token's issuer |
| `expectation` | the `ExpectedExecution` | the decision point |
| `observer` | the `AttestedBatch`es and the `SignedSensorHealth` | the collector, off-host |
| `continuity` | a `SignedContinuityReport`, when one exists | the collector |
| `lineage` | peer expectations, identity documents, revoked token ids | each by its own issuer; the revocation list is the verifier's operator's |
| `parameters` | `DeclaredParameters` — the knobs the original reconciliation ran under | inside the signed bundle, so uneditable |
| `claim` | the `Reconciliation`, exactly as the engine produced it | — (re-derived, never trusted) |
| `warrant` | a signed `Warrant`, when one exists | the warrant authority |
| `commitment` | a `ProofObject`: inclusion proof plus signed head | the NEXORA signer |
| `envelope` | who assembled the package | the assembler |

`proof_id()` is `SHA-256` over the canonical bundle. It is stable across
export, reformatting and import (`export.rs::g10_01`, `g10_02`), and it
changes for every mutation the adversarial suites make.

**What is not in it.** There is no coverage field, no confidence, no score,
no severity, no "trusted" flag, and no field in which an assembler could
state what the package establishes. `adversarial.rs::s_forged_coverage_*`
asserts the verifier's coverage vocabulary appears nowhere in a package.

Measured size on this host: **10,284 bytes** for one authorised action with
two attested batches and two kernel events; **~2,644 bytes** per additional
batch (`perf.rs`).

---

## 2. Cryptographic model

Ed25519 for every signature, SHA-256 for every hash. No other algorithm is
implemented, and two identifiers exist in the type that are not:
`MlDsa65` and `Hybrid` are refused with an error rather than checked as
Ed25519 (`audit.rs::a07`), and a package carrying one is refused naming the
component that carried it (`audit.rs::a08`).

Every signed structure is domain-separated. Twenty-six tags across the
workspace, all distinct, all namespaced (`AIP/`, `GHOST/`, `SYNTRIASS/`),
all versioned, and none a prefix of another once `put_domain` has
length-prefixed it (`audit.rs::a01`).

Canonical encoding is injective: variable-length fields are
length-prefixed, fixed-width arrays are written raw, `Option` carries an
explicit presence byte. The `("ab","c")` / `("a","bc")` ambiguity is
exercised through the real token constructors, on the adjacent
`issuer_id`/`agent_id` pair and inside the scope, plus an interior NUL
(`audit.rs::a02`, `a03`).

**Recorded, not a vulnerability.** The shared signature envelope is
`SHA-256(algorithm ‖ signer_id ‖ timestamp ‖ nonce ‖ payload_hash)`, in
which `signer_id` is variable-length and unprefixed. It is injective — it
is the only variable-length field and exactly 56 fixed-width bytes follow
it — but by arithmetic rather than construction, and a second
variable-length field added beside it would break that silently.
`audit.rs::a04` pins the observable property. The envelope also carries a
timestamp the signer chose; it is bound so it cannot be edited, and no
verifier reads it as trusted time.

**Not implemented, and not claimed:** post-quantum signatures, hybrid
signatures, hardware-held keys, key rotation ceremonies, threshold signing.

---

## 3. Trust roots

Six, each independent, each anchored by the verifier rather than supplied
by the package:

1. **Issuers** — sign scoped tokens and delegation hops.
2. **Decision point** — signs `ExpectedExecution`. Must not be the agent
   (I1).
3. **Collector** — signs attested batches, health and continuity reports.
   Off-host; the on-host probe holds no key. Must not be the agent (I10).
4. **Warrant authority** — signs warrants.
5. **NEXORA signer** — signs commitment heads.
6. **Containment authority** — signs containment records.

`VerifierAnchors` is the whole of what a verifier trusts, and each field is
its own decision. `export_anchors`/`import_anchors` exist so a
demonstration can move them, and the anchor file carries its own warning
that a verifier taking anchors from beside the artifact has verified
nothing (`live_nexora.rs::g14_06` reads that text back).

Three things the anchor file deliberately never carries: the verifier's
declared-parameter bounds, and the verifier's present time. A package must
not tell a verifier what it will accept or what time it is
(`adversarial.rs::n_verifier_context_substitution_*`). `nexora-verify`
supplies them on its command line instead — `--max-health-age-ms`,
`--max-window-tolerance-ms`, `--now-ms` — which is the one input a package
cannot reach.

---

## 4. Commitment model

RFC 6962/9162 Merkle tree over domain-separated leaves
(`SYNTRIASS/NEXORA/LEAF/v1`, plus a leaf-kind byte and a length-prefixed
record). Inclusion proofs and consistency proofs, both verified against a
root the verifier obtained elsewhere. Heads are signed under
`SYNTRIASS/NEXORA/HEAD/v1` and chain to the previous head.

A commitment binds *one* record: a genuine, verifiable inclusion proof for
a different reconciliation is refused with
`BindingFault::CommitmentIsNotOfTheClaim`, even when the foreign log's key
is anchored (`adversarial.rs::b_commitment_substitution_*`).

**Limitation, stated.** The head is not externally anchored. A party who
controls both the log and its archive can truncate history and present a
shorter consistent chain. `HeadTracker` and `AnchorSink` exist as the
interface for external anchoring; no external anchoring service is
implemented or exercised, so truncation resistance is **not** claimed.

---

## 5. Verifier model

`verify_nexora_proof(&NexoraProof, &VerifierAnchors) -> VerifiedProof`.

Pure: no clock, no network, no filesystem, no database, no relationship to
the party that produced the package. The same bytes and the same anchors
give the same answer, and `adversarial.rs::j_proof_replay_*` asserts it.

The load-bearing property is that **the verifier does not read the claim**.
It re-runs this repository's own reconciler over the package's inputs,
under the verifier's anchors and the package's declared parameters, and
compares canonical digests. A verdict not derivable from its own evidence
is `InvalidReason::ClaimNotDerivable { claimed, rederived }`. There is no
code in the verifier that writes a `ReconciliationResult` or an
`EvidenceStrength`, so `CANNOT_PROVE` cannot become `PROVEN` — not by
policy, but because no statement exists that could.

Order of checks: version → declared-parameter bounds → structural faults →
binding faults → each carried component under the verifier's anchors →
re-derivation.

Two properties fixed during Gate 12, both found by the adversarial suite:

- **A refused package establishes nothing.** `result` and `strength` are
  emptied on any `Invalid` verdict. Previously a package with a forged
  envelope, whose evidence re-derived cleanly, reported
  `result=VerifiedExecution` beside `verdict=Invalid`, and a consumer
  reading `.result` without `.verdict` would have been fooled. The
  recomputed record remains in `rederived`, under a name that says it is a
  recomputation.
- **A carried component is never `Absent`.** Component verdicts start as
  `Unverifiable(NOT_REACHED)` when carried and `Absent` when not, so an
  early return cannot report "the package does not carry it" about
  something it does.

Measured on this host (release, median of 50): **cold verification —
parse plus verify — 629 µs**; warm 527 µs; import 39 µs; export 12 µs; six
signatures checked per verification. Debug build: 82 ms, roughly 130×
slower, because most of a verification is Ed25519 (`perf.rs`).

---

## 6. Replay semantics

The five terms directive §11 names, and who answers each:

| term | answered by |
|---|---|
| valid historical replay | the verifier — a valid proof *is* this |
| proof of a previous execution | the same, from the other side |
| stale authority | the verifier, via `AuthorityStanding`, against a present time the *verifier* supplies |
| duplicate submission | the consumer, via `ProofLedger` |
| unauthorized reuse | nobody here — see below |

`AuthorityStanding` is `NotAssessed` / `ValidNow` / `StaleSince{valid_until}`,
derived from the expectation's own window. It never enters reconciliation:
what happened does not change because time passed, and a stale authority is
not an invalid proof. `grants_authority_now()` exists to be called and to
answer `false` for every variant.

Duplicate detection is deliberately outside the verifier, because
verification is pure and a ledger is stateful. `MemoryProofLedger` and
`FileProofLedger` implement `ProofLedger`; a duplicate submission is a fact
about submissions and leaves the verdict untouched.

**Unauthorized reuse is the honest row.** NEXORA cannot detect that
somebody waved a valid proof at a system as though it were permission. What
it does is ensure there is nothing in a `VerifiedProof` that could be read
as authorisation — `adversarial.rs::j` asserts no verifier output contains
grant/permit/allow/authorise/token — and say so where a reader meets it.
`nexora-verify` closes every report with: *"This states what the package
supports about a past execution. It is not authority to act now."*

---

## 7. Lineage treatment

Three kinds, kept apart, never synthesised from similar identifiers:

- **identity** — is this agent's document descended from that one? Checked
  by the parent's signature over the child's lineage proof.
- **authority** — did the authority reach this agent by delegation?
  Checked by the verified chain, and now by revocation.
- **execution-process** — did the observed instance come from another one?
  The engine's own answer, carried across without rounding.

`LineageStanding` has six values, and `Verified` is the only one that
asserts a relationship. `Unavailable` means the package carries nothing
about that kind — `CANNOT_PROVE`, never "assumed related".

`Revoked` was added in Gate 12 case U. `derive_lineage` previously read the
authority standing off signature validity alone, so a proof reported
`authority=Verified` for a token the operator had revoked, while the
reconciler — which does honour `revoked_jtis` — drew no edge from it. A
revoked token is not a forged one (`Contradicted` overstates), and the
package did carry it (`Unavailable` is false), so it gets its own answer.
`asserts_a_link()` is false for it.

An agent cannot be its own lineage peer
(`BindingFault::LineagePeerIsTheSubject`), and two unrelated real identity
documents do not become a lineage by being carried together
(`adversarial.rs::h`).

---

## 8. Continuity treatment

The collector maintains a hash-chained head across restarts and reports its
own breaks under its own key. Four kinds — `Amnesia`, `RolledBack`,
`Forked`, `ArchiveTruncated` — and `ContinuityPolicy::Strict` (the default)
refuses to resume rather than resuming quietly. Store corruption is
`StoreError::Corrupt`, never treated as absence.

`ContinuityStanding` has four values: `Continuous`, `Discontinuous`,
`Unknown`, `CannotProve`. `Unknown` and `CannotProve` are deliberately
distinct — the first says the package carries nothing about continuity, the
second says it carries something the verifier could not establish. A
verifier that collapsed them would let an unverifiable report read as an
absent one.

Any break the collector reports maps to `Discontinuous`, exhaustively over
every variant (`adversarial.rs::i`). `asserts_unbroken()` is false for
everything but `Continuous`.

---

## 9. Warrant treatment

There is **one** warrant model, in `aip-warrant`. NEXORA references and
checks a warrant; it never recreates the logic, and it never acts on one.
`verify_warrant` under the warrant authority's anchors is the whole of
NEXORA's involvement. A warrant resting on a different reconciliation
(`WarrantForAnotherRecord`) or naming a different subject
(`WarrantForAnotherSubject`) is refused at the binding layer, before any
key is consulted.

A warrant may rest only on an engine-produced record
(`Refusal::ReconciliationNotEngineProduced`), so a record that arrived over
the wire — provenance `Deserialized` — warrants nothing
(`adversarial.rs::t`, T4).

**Autonomous containment is unreachable in v1** and this is a decided
position, not a gap. `Contain` requires a workload-targeted result at
`Proven`; the engine produces every workload-targeted class only at
`Attested`, and the one result it produces at `Proven` is
`SensorIntegrityFailure`, whose cap is `Constrain` against the *observer*.
`aip-containment/tests/reachability.rs` proves it over the engine's whole
producible set under the most permissive policy an operator could write,
and fails if the engine ever gains a `Proven` workload finding.
`CONTAINMENT_MODEL.md` §10 records the reasoning and what would change it.

---

## 10. Adversarial tests

`aip-nexora/tests/adversarial.rs` — 22 cases. Directive §12's twenty (A–T),
plus U and V from Skill 10's own thirty-item list. Every case starts from
the shared real scenario — real issuer, real delegation, real decision
point, real collector attesting kernel socket-state events, verdict drawn
by the engine — and no hand-constructed `Reconciliation` appears anywhere.

| § | attack | expected failure |
|---|---|---|
| A | proof substitution | refused; distinct `proof_id`, subject and decision |
| B | commitment substitution | `CommitmentIsNotOfTheClaim` |
| C | evidence substitution | binding fault or `ClaimNotDerivable` |
| D | identity substitution | `IdentityIsNotTheSubject` |
| E | authority substitution | `AuthorityNotTheExpectations` |
| F | expected-execution substitution | `ExpectationDecisionMismatch` |
| G | observation substitution | `CitedBatchHeadMismatch`; observer `Unverifiable`, never `Absent` |
| H | lineage substitution | `LineagePeerIsTheSubject`; no link asserted |
| I | continuity rollback | `Discontinuous` for every break variant |
| J | proof replay | verdict unchanged; `DuplicateSubmission`; no authority |
| K | cross-protocol reuse | transplanted signature → envelope `Unverifiable` |
| L | cross-agent transplantation | `SubjectNotTheExpectationsAgent` |
| M | stale proof | still `Valid`; `StaleSince`; grants nothing |
| N | verifier-context substitution | `DeclaredParameterRefused`, named |
| O | malformed package | refused; a future version named, not parsed |
| P | partial package | `ClaimCites*NotCarried` |
| Q | missing observation | `CANNOT_PROVE`, `CannotEstablish`, never `PhantomClaim` |
| R | conflicting observation | refused, not absorbed |
| S | forged coverage | no field to forge; loss cannot become coverage |
| T | altered verdict | `ClaimNotDerivable`; `CANNOT_PROVE` never becomes `PROVEN` |
| U | revoked authority | `LineageStanding::Revoked`; no link |
| V | revoked observer | `Unverifiable`, never `Absent`; coverage withdrawn |

Skill 10's thirty-item list maps onto these plus the per-gate suites:
signature replacement (K), algorithm confusion (`audit.rs::a07`, `a08`),
domain confusion (`audit.rs::a01`), version confusion (O, `audit.rs::a06`),
expired authority (M and `live_nexora.rs::g14_05`), degraded observer and
ambiguous observation (`coverage.rs`), wrong Merkle root and invalid
inclusion proof (`merkle.rs`), sequence rollback / fork / truncation (I),
warrant transplantation (`binding.rs`, `warrant_ref.rs`).

**Three defects the suites found, all fixed in the implementation:**

1. A refused package still stated a result and a strength (Gate 12).
2. A carried component the verifier never reached reported `Absent`
   (Gate 12).
3. `verify_delegation_chain` never authenticated its root token, so the
   offline verifier reported `authority Verified` for a chain resting on a
   token nobody signed (Gate 14). Four other callers happened to call
   `verify_scoped_token` first; the fix is in `aip-core`, not a fifth
   workaround.

A fourth was found in the CLI: `nexora-verify` had no way to express the
verifier's own declared-parameter bounds, so the Gate 10 protection was
unreachable from the only offline verifier anyone would run.

---

## 11. Live / offline demonstration

`ghost-demo/tests/live_nexora.rs` — six cases, on this kernel.

```
spawn a real agent
  → a real decision point authorises a real TCP connection
  → the agent makes it
  → the kernel's socket table is read under a pidfd anchor
  → a real collector attests it off-host
  → the real reconciler draws the verdict
  → NEXORA packages exactly that
  → written to disk, every runtime value dropped
  → `nexora-verify` runs as its own process with two paths and nothing else
```

The isolation is real: a separate process, no shared memory, no clock the
package chose. The test builds `nexora-verify` itself, because a stale
binary from an earlier build once accepted a package the current code
refuses while the suite reported a pass.

- `g14_01` — the live package verifies offline in another process.
- `g14_02` — it verifies from the file alone, with no runtime state.
- `g14_03` — the live evidence is **`Attested`**, and the test asserts it
  is **not `Proven`**. A socket-table read is attested metadata about a
  host's own reporting, not a recomputable fact. Inflating the carried
  strength is refused.
- `g14_04` — a live execution that did not happen is `CANNOT_PROVE`
  offline too, never `PHANTOM_CLAIM`, and cannot be promoted in transit.
- `g14_05` — eight mutations of the live package, each refused offline: the
  observed window moved by 1 ms, the authorised window widened, the root
  token's expiry extended, the subject relabelled, reported loss zeroed,
  the declared health tolerance widened, the collector's health dropped,
  the verdict raised to `Proven`.
- `g14_06` — a verifier that takes its anchors from the forger verifies
  nothing, and the anchor file says so in its own text.

---

## 12. Limitations

Each of these is a real boundary of the current implementation.

- **No external anchoring.** The commitment head is signed and chained but
  not anchored anywhere outside the log. Truncation by a party controlling
  both log and archive is not defeated.
- **No kernel-resident sensing.** Observation is procfs, kernel
  tracepoints, `AF_PACKET` headers and fanotify — read by a user-space
  probe. No eBPF, no XDP, no packet payloads.
- **Attested is the ceiling for workload actions.** Nothing in the live
  path produces `Proven` for what a workload did, which is why autonomous
  containment is unreachable (§9).
- **Root on the observed host can suppress observation.** It cannot forge
  attested records (the probe holds no key), but stopping the probe yields
  `CannotEstablish` — a denial of evidence, honestly reported and not
  papered over.
- **Software keys only.** No TPM, no secure element, no HSM.
- **One machine, one build.** Every performance figure is from a 4-vCPU
  virtual machine. Nothing is known about behaviour at scale.
- **No revocation distribution.** `revoked_jtis` is a list the verifier's
  operator supplies. There is no revocation service, no CRL, no OCSP.
- **`respond_to_challenge` signs an untagged payload.** A liveness helper
  in `aip-core` signs a bare nonce with no domain tag. It is on no path a
  NEXORA proof depends on, and repairing it is a wire change to an
  unrelated protocol. **Recorded and open**, not fixed.
- **The lineage `Revoked` standing is new.** It is checked in the verifier;
  no long-running deployment has exercised it.

---

## 13. Unsupported claims

The following must not be said about this system, because none of it is
implemented or demonstrated:

- production readiness, or readiness for field deployment
- post-quantum cryptography, or any hybrid signature scheme
- hardware-backed security, hardware attestation, or hardware roots of
  trust
- kernel-resident sensing — eBPF, XDP, or in-kernel programs of any kind
- packet capture, payload inspection, or line-rate anything
- universal observation, complete coverage, or zero event loss
- resistance to root compromise of the observed host
- externally anchored history, or truncation resistance
- autonomous containment of a misbehaving agent
- deterministic replay of any model's internal reasoning — "replay" here
  means recomputing canonical bytes, commitments, signatures and the
  reconciliation verdict, and nothing else
- any TRL, throughput figure, latency guarantee, or comparison to another
  system
- that a valid proof is authority to do anything now

---

## Validation

```
cargo fmt --all -- --check                                        clean
cargo clippy --workspace --all-targets --all-features -- -D warnings   clean
cargo test --workspace                        925 passed, 0 failed
aip-service                                    39 passed, 0 failed
```

Three consecutive clean full workspace runs were taken before each
security-relevant commit, per directive §23.

---

## NEXORA STATUS

```
[ ] NOT READY
[ ] PROTOTYPE
[ ] VALIDATED PROOF CORE
[x] VALIDATED OFFLINE PROOF
[ ] PRODUCTION HARDENING
[ ] PRODUCTION READY
```

**VALIDATED OFFLINE PROOF.**

Earned, and bounded. A real authorised execution on a real kernel is
observed, reconciled by the engine, packaged, moved to disk, and verified
by a separate process holding nothing but the file and its own anchors —
and every mutation of that live package is refused there. The verifier
re-derives rather than believes, so no packaging step can strengthen
evidence, and twenty-two adversarial cases plus a cross-crate audit say so
in tests that fail if it stops being true.

It is not **PRODUCTION HARDENING**, and the difference is not paperwork.
That would require external anchoring of the commitment head, a revocation
distribution mechanism, hardware key custody, and evidence strong enough
that the response pipeline this repository has built is actually reachable.
None of those exists yet, and §12 says so plainly.
