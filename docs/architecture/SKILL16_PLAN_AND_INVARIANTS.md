# Skill 16 — Implementation Plan and Invariant Matrix

Written **before** implementation, as the skill's workflow requires. Records
the verified starting state, the invariant each blocker must establish, the
minimum correct fix, and the adversarial test that pins it.

## 1. Verified starting state

The commissioning brief's register was checked against this tree rather than
assumed. One entry is already closed.

| Blocker | Brief | **Verified here** | Evidence |
|---|---|---|---|
| B-1a | OPEN | **OPEN** | `grep -rn 'verification_time_ms' aip-service/src/` → **0 occurrences** |
| B-3 | OPEN | **OPEN** | `grep reconcile_* aip-warrant/ aip-containment/` → no matches; no end-to-end path |
| B-4 | OPEN | **OPEN** | `bundle.rs::verify_bundle_signature` decodes `manifest.signer_public_key` — a key the verified object supplies |
| B-5 | OPEN | **OPEN** | `store.rs::save` → `fs::write`, `set_permissions` count **0** |
| B-6 | OPEN | **OPEN** | `keys.rs:133-156` — load failure logs a warning and falls through to `Self::generate()` |
| B-7 | OPEN | **OPEN** | `evidence.rs:125,131` — `agent_seed_hex`, `counterparty_seed_hex` in request bodies |
| B-8 | OPEN | **OPEN** | 16 verification rules; none is a replay rule |
| **B-9** | OPEN | **ALREADY CLOSED** | prod `30aafc6`: `Reconciliation` is `#[non_exhaustive]` + private field + `Provenance::{Engine,Deserialized}`; `warrant.rs` refuses `ReconciliationNotEngineProduced` |
| B-10 | OPEN | **OPEN** | `aip-standalone/Cargo.toml` has no `aip-service` member; it is a separate root |

**B-9 is closed by the production branch, not by this work.** It is recorded
as closed with prod's evidence and re-verified here; it is not re-implemented.

## 2. Ordering, and why

B-10 comes first because it is the *cause* of B-1a: a fix landing in
`aip-protocol` is not compiled against the service, so nobody notices the
service did not adopt it. Fixing the service tier before it is inside the
build boundary would leave the next protocol change with the same gap.

```
B-10 (build boundary)
  └─▶ B-1a (service temporal semantics)   ── now compiled and tested
  └─▶ B-6  (fail closed on key load)
  └─▶ B-7  (private seeds out of bodies)
B-5  (key file permissions)      ── independent
B-4  (bundle signer anchor)      ── independent, needs a trust-anchor design
B-8  (packet replay)             ── independent, needs a semantics decision
B-3  (engine-produced path)      ── last; the hardest, and the one the
                                    six-branch audit proved unreachable
```

## 3. Invariant matrix

Each row states the property, the minimum fix, and the adversarial test that
would fail if the property regressed.

| # | Invariant | Blocker | Minimum fix | Adversarial test |
|---|---|---|---|---|
| S16-1 | The primary build/test command compiles and tests the service tier | B-10 | Make `aip-service` a member of the workspace | A protocol-level change that breaks the service fails `cargo test --workspace` |
| S16-2 | A service verification states whether a temporal bound was applied | B-1a | Thread `verification_time_ms` + `future_tolerance_ms` into `verify_request` | A future-dated packet through the service API does not report unqualified success |
| S16-3 | A handler never decides from `valid` alone when the temporal rule was not evaluated | B-1a | Handlers consult `verification_time_checked` | Removing the check fails a test |
| S16-4 | A private key file is not readable beyond its owner | B-5 | `set_permissions(0o600)` before writing secret material; atomic replace | After `save`, mode is `0o600`; a pre-existing lax file is tightened |
| S16-5 | A service that cannot load its key does not become a different principal | B-6 | Load failure is fatal; generation only on explicit first-run intent | An unreadable key file causes a startup error, and the file is not overwritten |
| S16-6 | Private seed material is not accepted in an HTTP request body | B-7 | Reject seed-bearing request shapes at the boundary | A request carrying `agent_seed_hex` is refused |
| S16-7 | A bundle is verified against a verifier-held anchor, never the bundle's own key | B-4 | `verify_bundle_signature` takes an anchor; the manifest key is at most a hint that must match | A self-consistent bundle signed by an unanchored key is refused |
| S16-8 | A replayed packet is detectable by the verifier | B-8 | A verifier-supplied seen-set over a replay-relevant identifier, with explicit semantics | The same packet verified twice against a stateful verifier is refused the second time |
| S16-9 | A warrant may rest only on an engine-produced verdict | B-9 | *(already closed by prod)* | `ReconciliationNotEngineProduced` |
| S16-10 | There exists a test crossing reconcile → warrant → containment on engine output | B-3 | An integration test driving the real engine into the real gates | The test exists and states the true outcome, whatever it is |

## 4. Forensic rule carried into every fix

> Never convert NOT_DETERMINABLE, CANNOT_PROVE, OBSERVATION_UNAVAILABLE or
> UNTRUSTED into a successful security assertion merely to make a test pass.

Where a blocker cannot be closed without weakening the epistemic model, the
correct outcome is a **stop and report**, not a fix. This applies most
directly to **B-3**: the six-branch audit proved, by exhaustive sweep, that
`Contain` is unreachable from engine output because every workload-violation
class is capped at `Attested` while the containment gate demands `Proven`.
If that still holds, S16-10's test must record the refusal honestly rather
than manufacture a `Proven` verdict to make the path light up.

## 5. What "closed" will mean

For each blocker: exact source path, prior behaviour, invariant, the change,
adversarial tests, targeted run, full workspace run, service run, clippy, and
an evidence class. Anything short of that is reported as still open.
