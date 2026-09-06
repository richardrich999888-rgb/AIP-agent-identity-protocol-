# Security Invariant Matrix

Each invariant is stated as a property the system must hold, then assessed
per branch against source, not documentation. "Holds" means the code
enforces it; "fails" means an input exists that violates it and is accepted.

Legend: **✓** holds · **✗** fails · **~** partial · **n/a** component absent

## 1. Matrix

| # | Invariant | main | prod | audit | importot | valladder | aipv4 |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|
| I-1 | A token's signature covers its expiry | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| I-2 | A delegation hop's signature covers its expiry | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| I-3 | A delegation hop's issuer is the previous hop's grantee | ✗ | **✓** | ✗ | ✗ | ✗ | ✗ |
| I-4 | A child delegation cannot outlive its parent | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| I-5 | Signing payloads are prefix-free (injective) | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| I-6 | Signing payloads are domain-separated | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| I-7 | The verifier bounds packet age against its own clock | ✗ | **~** | ✗ | ✗ | n/a | n/a |
| I-8 | A packet cannot be replayed undetected | ✗ | ✗ | ✗ | ✗ | n/a | n/a |
| I-9 | A bundle's signer key is not supplied by the bundle | ✗ | ✗ | ✗ | ✗ | n/a | n/a |
| I-10 | Private keys are not written world-readable | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| I-11 | Private key material is not accepted in request bodies | ✗ | ✗ | ✗ | ✗ | n/a | n/a |
| I-12 | The trust floor is derived, never asserted | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| I-13 | Absence of evidence yields no verdict | n/a | ✓ | n/a | n/a | n/a | n/a |
| I-14 | A positive verdict cannot be constructed outside the engine | n/a | ~ | n/a | n/a | n/a | n/a |
| I-15 | Observation content never reaches `Proven` strength | n/a | ✓ | n/a | n/a | n/a | n/a |
| I-16 | The observer's signing key is unreachable from the observed host | n/a | ✓ | n/a | n/a | n/a | n/a |
| I-17 | Coverage is re-derived, never read from the claim | n/a | ✓ | n/a | n/a | n/a | n/a |
| I-18 | Containment requires a warrant the engine can actually issue | n/a | **✗** | n/a | n/a | n/a | n/a |
| I-19 | Per-connection tracking state is bounded | n/a | n/a | n/a | n/a | **✗** | **✗** |
| I-20 | The PQC exchange has a counterparty | n/a | n/a | n/a | n/a | **✗** | **✗** |

## 2. Findings

### I-1 / I-2 / I-4 / I-5 / I-6 — signing payload integrity

**Status on prod: RESOLVED. CODE-PROVEN, TEST-PROVEN.**

`prod/aip-standalone/aip-core/src/capability.rs:221-238` and
`prod/…/delegation.rs:415-437` replace raw concatenation with the shared
prefix-free encoder and lead each payload with a domain tag
(`AIP/ScopedToken/v1`, `AIP/DelegationToken/v1`). `expires_at` is carried
with an explicit presence byte via `put_opt_u64`, so `None` and `Some(0)`
have distinct preimages.

Tests genuinely exercising the property (all passing, part of the 787):
`test_mutate_expires_at_extend_rejected`,
`test_mutate_expires_at_some_to_none_rejected`,
`test_mutate_expires_at_none_to_some_rejected`,
`test_mutate_delegation_expires_at_extend_rejected`,
`test_mutate_delegation_expires_at_some_to_none_rejected`,
`test_legitimately_signed_hop_outliving_parent_rejected`,
`test_scoped_token_signature_cannot_verify_as_delegation`,
`test_token_payload_adjacent_ids_do_not_collide`,
`test_token_payload_custom_action_interior_nul_unambiguous`.

The last of these is the one that matters most and is easy to overlook: the
old encoder terminated custom scope actions with a NUL byte, so a custom
action containing an interior NUL was ambiguous with two separate actions.
The new encoder length-prefixes, and the test pins all three confusable
arrangements apart.

`test_legitimately_signed_hop_outliving_parent_rejected` is the strongest
test in the repository's cryptographic core: it constructs a hop that is
*validly signed by the genuine delegating key* and still expires later than
its parent, and requires the chain to reject it as
`AttenuationViolation`. That is enforcement of a policy the signature cannot
express, which is the correct shape.

**Status on every other branch: OPEN.** All five branches other than prod
carry main's encoder verbatim.

### I-3 — issuer↔grantee binding

> **RESOLVED on prod, 2026-09-06** (commit `8daffe3`), after this audit was
> filed. `verify_delegation_chain` now tracks `prev_holder` — the root
> token's grantee, then each hop's grantee — and refuses a hop whose
> `issuer_id` is not the party that held the parent. The check is
> unconditional, so every caller including `aip-service` inherits it.
> Independently verified; see the AIRI extension's
> `P0_VERIFICATION_ADDENDUM.md` §1. The original finding follows.

### I-3 — issuer↔grantee binding (as filed: P0, OPEN ON ALL BRANCHES)

**CODE-PROVEN.** `prod/aip-standalone/aip-core/src/delegation.rs:179-244`.
`verify_delegation_chain` performs five checks per hop: parent JTI linkage,
depth monotonicity, scope subset, issuer signature, temporal attenuation.
It never checks that `hop.issuer_id` equals the previous hop's
`grantee_id` (or, for hop 0, the root token's `agent_id`). The chain is
linked by JTI and by depth, but the *identities* along it are not linked.

Consequence: an attacker holding any key trusted in
`issuer_public_keys` can substitute themselves as the issuer of a hop whose
`parent_jti` matches, and the chain verifies. Delegation is thereby
authenticated but not attributed.

`prod` reduced the surface (a forged expiry now fails as
`SignatureInvalid`), but the substitution itself remains accepted. The
counter is one comparison per hop; it is absent.

### I-7 — verifier clock

> **PARTLY RESOLVED on prod, 2026-09-06** (commit `fdf380c`), after this
> audit was filed. Rule **R16 VERIFICATION_TIME_BOUND** adds a
> verifier-*supplied* time — never the system clock, so offline and
> air-gapped verification stay possible — and records the rule as NOT
> EVALUATED, rather than as a pass, when no time is given.
>
> The matrix now reads **~** rather than ✓ for prod because the bound is
> opt-in and **`aip-service` does not take it**: `verification_time_ms` is
> set nowhere in the service, so `/verify` remains unbounded and its handlers
> decide on `result.valid` alone. That residual is tracked as **B-1a (P1)**.
> See `P0_VERIFICATION_ADDENDUM.md` §2. The original finding follows.

### I-7 — verifier clock (as filed: P0, OPEN ON PROD)

**CODE-PROVEN.** `check_temporal_validity`
(`prod/aip-standalone/aip-protocol/src/verification.rs:535-585`) is
byte-identical to main's — verified by extracting both bodies and comparing
SHA-256 (`dbafa0086c1b34af` on both). It compares packet-internal
timestamps against each other only: decision vs. issuance, actions vs.
expiry, actions vs. decision. `VerificationContext`
(`:29-43`) has no `now_ms` field on either branch.

Consequence: a packet whose every internal timestamp is mutually consistent
but set fifty years in the future passes all fourteen rules and reaches
`AuthorityBound` with `tampered = false`. This was demonstrated by probe in
the base audit and nothing on any branch changes it.

~~**This is the single most important unremediated finding.** R15 on prod adds
a *fifteenth* rule and still does not introduce a verifier clock.~~

**Superseded.** A *sixteenth* rule, R16, introduced exactly that bound three
commits later. What survives of this finding is its service-tier half, B-1a.

### I-8 / I-9 / I-10 / I-11 — carried forward, unremediated

All four are byte-for-byte unchanged on prod (see Report 02 §6.4, §6.5).

- **I-9**: `bundle.rs:437` verifies a manifest against
  `manifest.signer_public_key`, a field of the object under verification.
  Any party can produce a self-consistent bundle.
- **I-10**: `IdentityStore::save` (`aip-core/src/store.rs:138`) calls
  `std::fs::write` on a JSON document containing private keys, with no
  `set_permissions` call, on all six branches.
- **I-11**: `aip-service/src/evidence.rs:125,130` accept private seeds as
  hex in request bodies.

### I-13 / I-15 / I-17 — the reconciler's epistemic discipline (prod only)

**Status: HOLDS. CODE-PROVEN, TEST-PROVEN.**

- **I-13**: `ReconciliationResult::default()` is `CannotProve`
  (`aip-reconcile/src/result.rs:30-56`), asserted by
  `result::tests::default_result_is_cannot_prove`. `reconcile_expectation`
  documents `None` observer evidence as a legitimate input yielding
  `CANNOT_PROVE`, never a verdict.
- **I-15**: `precondition_holds` requires `strength == Attested` exactly for
  every content-derived verdict, with the stated rationale that procfs
  content is root-forgeable. `Proven` is reserved for signature and chain
  arithmetic a third party can recompute.
- **I-17**: `recompute_coverage`
  (`aip-reconcile/src/reconcile.rs:1060-1120`) re-derives coverage from the
  attested batches rather than reading the collector's `attested_coverage`
  field, on the stated ground that every input to that field is authored by
  the host-side probe. `PhantomClaim` cannot leave `finish` without
  `coverage_recomputed`.

This is the correct design and it is implemented as described.

### I-14 — verdict forgeability (P2, PARTIAL)

**CODE-PROVEN.** The engine applies two different levels of protection to
two parts of the same record.

*Protected:* `ActionComparison`'s positive variants require an
`ActionEvidenceSeal` whose field is private and whose constructors are
`pub(crate)` (`aip-reconcile/src/result.rs:312-322`). No caller outside the
crate can produce `ActionComparison::Match`.

*Unprotected:* `Reconciliation` itself
(`aip-reconcile/src/result.rs:679-699`) has **all fourteen fields `pub`**.
Any downstream crate can construct a `Reconciliation` literal with an
arbitrary `result` and `strength`, bypassing `finish()` and therefore
`precondition_holds` entirely.

The crate's own consumers demonstrate this: `aip-containment/tests/
containment.rs:104` defines a `record(result, strength, …)` helper that does
exactly this, and `:132` uses it to build `proven_phantom()` — a
`PhantomClaim` at `Proven` strength, which §I-18 proves the engine cannot
emit.

The asymmetry is the finding. The authors identified constructor control as
the right mechanism and applied it to the action comparison but not to the
record that carries the verdict.

### I-16 — observer key locality

**Status: HOLDS as designed, with a stated deployment obligation.
CODE-PROVEN.** `aip-observe/src/attest.rs:1-30`. `CollectorSigner` holds the
key; `crate::probe` has no key field and no signing method;
`ObservationBatch` has no signature field. `sequence` is assigned by the
collector, and `attested_at_ms` is the collector's own clock. The signed
preimage is domain-separated under
`SYNTRIASS/GHOST/OBSERVER_HEAD/v1` and the head is computed, never carried.

The module doc states plainly that the transport proving a batch came from
the registered probe is a deployment obligation, not a code property. That
is an honest and correct statement of the boundary.

### I-18 — containment reachability (P1, FAILS ON PROD)

**EXECUTION-PROVEN.** This is the principal new finding of this audit and is
traced in full in Report 04 §3. In summary:

`aip-containment/src/contain.rs` gate 3 requires
`warrant.response == ResponseClass::Contain`; gate 5 requires
`evidence_strength == Proven` (explicit match, no ordering); gate 6 requires
a workload-violation result class.

`aip-warrant/src/warrant.rs:213-223` sets `strength_cap = Contain` only for
`EvidenceStrength::Proven`, and `response = min3(result_cap, strength_cap,
severity_cap)`.

`aip-reconcile/src/reconcile.rs:89-137` caps every workload-violation class
(`UnattributedEffect`, `PhantomClaim`, `IdentityDivergence`,
`LineageViolation`) at `strength == Attested` **exactly**. The only classes
that may carry `Proven` are `SensorIntegrityFailure` and
`ContinuityFailure`, whose `result_cap` is `Constrain` and `Alert`.

Therefore no reconciliation the engine can emit yields a `Contain` warrant.
An exhaustive 32-cell sweep under a maximally permissive policy confirms it
(Report 04 §3.3): `Contain` appears in 4 cells, all 4 requiring a forged
`Reconciliation`.

Neither `aip-containment` nor `aip-warrant` ever calls
`reconcile_expectation`, `reconcile_observation`, or `reconcile_lineage` —
`grep` across both crates returns nothing. 2,286 lines of containment and
warrant tests exercise the gates against synthetic records only.

### I-19 — circuit-breaker state bound (P1, FAILS ON valladder AND aipv4)

**CODE-PROVEN.** `valladder/aegis-quantum/aegis-quantum-circuit-breaker/
src/lib.rs:32-38`. `CircuitBreaker.connections` is a
`HashMap<ConnectionKey, ConnectionState>`. `record_event` inserts on every
unseen key (`:65-72`). No method removes an entry: `reset` clears one
connection's timestamps but leaves the entry; `reset_all` clears the map but
nothing calls it on a timer or a bound. There is no LRU, no TTL eviction and
no capacity cap.

Per-key memory *is* bounded (the deque cannot exceed `threshold + 1` before
tripping), but the *number of keys* is not. An adversary varying the
connection tuple allocates one entry per tuple, without limit, in the
component whose stated purpose is to defend against a rogue agent
"hammering an endpoint in a tight loop."

**The test that appears to cover this does not.**
`stress-tests/tests/lru_exhaustion_test.rs` asserts that a
`MockLruSessionMap` evicts to capacity. `MockLruSessionMap` is defined at
`stress-tests/src/lib.rs:19` — a purpose-built mock in the test crate. The
test never constructs a `CircuitBreaker`. It proves a mock LRU works; it
proves nothing about the product.

Secondary defects in the same file:
- `new()` computes `window_ms * 1_000_000` with unchecked `u64`
  multiplication and validates neither `window_ms` nor `threshold` (P3).
  `threshold = 0` trips on the first event.
- Once `tripped`, the timestamp deque is retained indefinitely (P3).
- `timestamp_ns` is caller-supplied and assumed monotonic; nothing enforces
  it (P3).

### I-20 — PQC exchange counterparty (P1, FAILS ON valladder AND aipv4)

**CODE-PROVEN.** `valladder/aegis-quantum/aegis-quantum-userspace/src/
pqc.rs:157-165`:

```rust
pub fn process_packet_event(event: &PacketEvent) -> PqcValidationReport {
    tracing::debug!(/* logs src/dst */);
    hybrid_x25519_kyber768_key_exchange()
}
```

The event is logged and then discarded. `hybrid_x25519_kyber768_key_exchange`
(`:90-131`) generates *both* peers' X25519 secrets and the Kyber keypair in
the same process, encapsulates to a public key it just created,
decapsulates with the private half it still holds, and compares two secrets
derived from key material it owns entirely. `secrets_match` is
arithmetically always true. There is no peer, no network, no transport, and
no write to the BPF session map the module doc describes.

The doc comment is honest — it says "For TRL-4, we simulate the full
round-trip" — but the crate description states the component "performs Kyber
PQC key exchange", and the type is named `PqcValidationReport`. Read from
the outside, this is a latency benchmark presented as a security control.

The combiner itself is correctly built: `hybrid_session_hash` (`:134-142`)
is domain-separated (`AIRON-AEGIS-HYBRID-v1`) and length-prefixes both
secrets. That construction is sound. It is exercised only against itself.

**No adversarial test exists.** All 110 aegis-quantum tests pass; none
supplies a wrong ciphertext, a tampered public key, or a second party.
`test_algorithm_name_is_kyber768` asserts a string literal.
`test_100_key_exchanges_all_unique_secrets` asserts RNG non-collision, which
is a property of `getrandom`, not of this code.

Supporting defects:
- `pqcrypto-kyber = "0.8"` (resolved `0.8.1`) is a caret range, not pinned,
  in a cryptographic dependency (P2).
- The report labels its output `"Kyber-768 (ML-KEM)"`. Round-3 Kyber and
  FIPS 203 ML-KEM are not the same construction; the label conflates them
  (P3).
- `test_kyber768_performance_under_5ms` is a wall-clock assertion inside a
  unit test — nondeterministic and load-sensitive (P3).

## 3. Invariants that hold and deserve to be said plainly

Auditing is not only enumeration of defects. Four properties are enforced
correctly and are unusual enough to be worth naming:

1. **The trust floor is derived from what verified, never asserted by the
   packet** (I-12), on every branch.
2. **The default verdict is "cannot prove"** (I-13), and the type system
   enforces it through a single choke point.
3. **Content-derived facts are structurally barred from the highest
   evidence class** (I-15).
4. **Coverage claims authored by the observed host are re-derived rather
   than trusted** (I-17).

Properties 2–4 exist only on `prod`.
