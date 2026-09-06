# AIRI — Versioning and Migration Plan

## 1. Versioned surfaces

| Surface | Constant | Value | Change policy |
|---|---|---|---|
| Event structure | `AIRI_EVENT_VERSION` | `1` | Bump on any preimage layout change |
| Event domain | `AIRI_EVENT_DOMAIN` | `SYNTRIASS/AIRI/EVENT/v1` | New tag, never a redefinition |
| Commitment domain | `AIRI_PARAM_DOMAIN` | `SYNTRIASS/AIRI/PARAM_COMMITMENT/v1` | New tag, never a redefinition |
| NEXORA leaf kind | `LeafKind::AiriEvent` | `0x09` | Frozen; new kinds append |
| Adapter mapping | `FrameworkIdentity.adapter_version` | per adapter | Bump when the translation changes |
| Python package | `vanian_airi.__version__` | `0.1.0` | Semver against the Rust event version |

## 2. Rules

1. **A verifier refuses an unknown version rather than interpreting it.**
   Fields may have moved; a best-effort parse of an unknown layout is how a
   signature ends up covering something other than what a verifier reads.
2. **The domain tag carries the version.** A v2 event signs under
   `SYNTRIASS/AIRI/EVENT/v2`, so a v1 verifier cannot be tricked into
   accepting a v2 event and vice versa. The version is belt as well as braces.
3. **Leaf codes are frozen.** A leaf committed today keeps verifying.
4. **Adapter versions are recorded, not trusted.** A verifier may refuse a
   mapping it does not know; it may not grant anything on the strength of one.

## 3. Adding a field, an event kind, or a payload

| Change | Requires |
|---|---|
| New optional field | version bump; presence byte; new parity vector; substitution test |
| New event kind | new code appended; `is_externally_observable` decision (the match is exhaustive, so the compiler forces it); corroboration test |
| New payload variant | version bump; encode function; injectivity test against the neighbouring variants |
| New observable class | mapping in `observable_class_of`; a test that an unmapped class still returns `NotEvaluated` |

Every one of those also requires regenerating the Python parity vectors:

```
cargo test -p aip-airi --test parity_vectors -- --ignored --nocapture \
  > sdk/python/tests/parity_vectors.json
cd sdk/python && python3 -m unittest discover -s tests
```

A divergence must be a build failure. The parity test caught three real
defects on its first run; treating it as advisory would have shipped them.

## 4. The deferred change: AIRI as a verdict input

**Not implemented, deliberately.** Today AIRI contributes nothing to a
reconciliation verdict.

The change would add a fourth entry point to `aip-reconcile` —
`reconcile_airi_claim` — reusing `Draft`, `prologue` and, critically,
`precondition_holds`, so it goes through the same choke point as the existing
three and cannot exceed `Attested`.

It is deferred because it is a **new way to accuse**. The existing
`PHANTOM_CLAIM` path required recomputed coverage, a sealed identity
comparison and 1,419 lines of adversarial tests before it was trusted to say
"this did not happen". A second accusation path built without that depth is
how a detection system starts producing false positives and gets switched off.

Before it is built it needs:

1. A precondition at least as strict as the existing `PhantomClaim` arm:
   recomputed coverage, `IdentityComparison::NoReference`, covered
   availability, and `strength == Attested` exactly.
2. An additional AIRI-specific precondition: an intact chain, a runtime
   binding, and a mappable action class. Any of those absent must yield
   `CannotProve`.
3. An adversarial suite of comparable depth to `aip-reconcile/tests/adversarial.rs`,
   specifically covering: a lying agent that omits events, an agent that
   fabricates a binding for an instance the observer *did* see acting, and a
   vocabulary gap that must not become an accusation.
4. A false-positive budget agreed with whoever operates it, because the first
   production week decides whether the system stays switched on.

Until all four exist, `annotate()` surfaces `uncorroborated` as a counter for
policy to act on, visibly, rather than as a verdict.

## 5. Rollout

| Stage | State | Gate to the next |
|---|---|---|
| 0 | AIRI core, SDK, adapters — **done** | — |
| 1 | Adapters deployed, events collected, nothing acts on them | Corroboration rates measured against real traffic |
| 2 | `annotate()` surfaced to operators as a dashboard signal | False-positive rate of `uncorroborated` characterised |
| 3 | §4 entry point built, behind a policy flag, advisory only | Adversarial suite complete; budget agreed |
| 4 | AIRI contributes to verdicts | Forensic blockers B-1…B-10 closed |

Stage 4 is gated on the blockers, not on AIRI's own maturity: contributing to
a verdict in a system whose verifier has no clock and whose delegation chains
do not bind issuer to grantee would be building on sand.

## 6. Compatibility

* A v1 event verifies against a v1 verifier indefinitely.
* A v1 verifier refuses a v2 event with `UnsupportedVersion` — loud, not silent.
* A NEXORA package containing AIRI leaves verifies on a build without AIRI:
  the leaf kind is opaque to a verifier that does not know it, and the Merkle
  root still recomputes.
* The Python SDK and the Rust crate must ship together. The parity vectors
  are the contract; a mismatched pair is a build failure by construction.
