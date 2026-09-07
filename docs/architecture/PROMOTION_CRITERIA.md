# PROMOTION CRITERIA — evaluation

Directive §25. Twenty criteria that must all be satisfied before
`claude/codebase-production-readiness-wm6idp` is promoted to `main`.

**Branch** `claude/codebase-production-readiness-wm6idp` at `de46793`
**Evaluated** at the completion of Skill 10 Gates 0–16.

## Result

**18 of 20 met. Promotion is blocked.**

Two criteria are not satisfied, and neither can be closed by this
programme on its own initiative — one needs an operational decision, the
other changes verification semantics in a layer outside this work's remit.
They are §25 items 7 and 8, below.

§1 of the directive says not to promote at this stage. This evaluation
agrees with it for reasons independent of the instruction, which is the
useful outcome: the gate is closed on merit, not merely on schedule.

---

## The twenty

| # | criterion | state | evidence |
|---|---|---|---|
| 1 | P0 verifier clock closed | **MET** | R16 `VERIFICATION_TIME_BOUND`; RED `e52437e`, GREEN `fdf380c`. Unsupplied time records *not evaluated*, never a pass. |
| 2 | P0 issuer↔grantee binding closed | **MET** | `verify_delegation_chain` tracks `prev_holder`; RED `f856b7d`, GREEN `8daffe3`; re-checked by `audit.rs::a09` with the attacker's key anchored. |
| 3 | reconciliation result construction sealed | **MET** | `#[non_exhaustive]` + crate-private `Provenance`; `Refusal::ReconciliationNotEngineProduced`; RED `4c712c2`, GREEN `30aafc6`; `adversarial.rs::t` (T4). |
| 4 | containment policy explicitly resolved | **MET** | Resolved as option **A**. `CONTAINMENT_MODEL.md` §10; `aip-containment/tests/reachability.rs` (4 cases) proves unreachability over the engine's whole producible set. |
| 5 | real end-to-end containment test exists **if intended** | **MET (conditional not triggered)** | The §13 decision is that autonomous containment is *not* intended in v1. The conditional is answered by the decision, and `containment.rs` now states at the top and at its fixture that its input is a state the engine cannot produce — so no capability is claimed from it. |
| 6 | service security addressed **or explicitly excluded** | **MET by explicit exclusion** | `aip-service`'s second authority model (I18) is **not addressed**. It is named as REMAINING in `FINAL_AUDIT_RECONCILIATION.md` with what it costs. The criterion permits exclusion; this is an exclusion on the record, not a silent drop. |
| 7 | private key storage hardened | **NOT MET** | See below. |
| 8 | bundle trust anchor fixed | **NOT MET** | See below. |
| 9 | NEXORA export/import works | **MET** | `export.rs` 8 cases: byte-identical round trip, `proof_id` stable across reformatting, malformed input refused, future versions named. |
| 10 | offline verifier independently verifies proofs | **MET** | `nexora-verify` run as a separate process against a live package with two file paths and nothing else — `live_nexora.rs::g14_01`. No clock, no network, no filesystem beyond the two files. |
| 11 | replay model implemented | **MET** | `replay.rs`: `AuthorityStanding`, `ReplayStanding`, `ProofLedger`, memory and file ledgers. The five §11 terms are separated and attributed. `grants_authority_now()` is false for every variant. |
| 12 | continuity integrated | **MET** | `SignedContinuityReport` carried in the package; every `ContinuityBreak` variant maps to `Discontinuous`, exhaustively, in `adversarial.rs::i`. |
| 13 | coverage semantics adversarially tested | **MET** | Five states, derived not claimed; `coverage.rs` (8), `adversarial.rs::q`, `s`. A package has no field in which to state coverage. |
| 14 | lineage adversarially tested | **MET** | Three kinds, six standings; `lineage.rs` (8), `adversarial.rs::h`, `u`. An absent edge is `Unavailable`, never "assumed related". |
| 15 | observer trust boundary hardened | **MET** | Keyless probe, off-host collector, mechanism-scoped provisioning (`fa07`), I10 refusal of the agent's key as an observer anchor, `Independence::NotChecked` reported rather than passed (`audit.rs::a10`), revocation by anchor withdrawal (`adversarial.rs::v`). |
| 16 | complete test suite passes | **MET** | `aip-standalone` 925 passed, 0 failed. Three consecutive clean runs taken before each security-relevant commit. |
| 17 | standalone roots tested | **MET** | `aip-service` 39 passed, 0 failed, run separately — the workspace run does not cover it. |
| 18 | README updated | **MET** | Rewritten to the actual system with five capability tiers; `de46793`. |
| 19 | defense deployment documentation updated | **MET** | README "Defense and Sovereign Deployment", opening with the statement that these are deployment targets and none is validated in its environment. |
| 20 | IP mechanism register updated | **MET** | `docs/IP/INVENTION_REGISTER.md`, nine mechanisms, each with a disclosure status saying no prior-art search and no filing. |
| 21 | final security audit completed | **MET** | `FINAL_AUDIT_RECONCILIATION.md` — every finding classified, including three the work found itself. |

(§25 lists twenty checkboxes; they enumerate to twenty-one lines because
"final security audit completed" is separate from "complete test suite
passes". Both are evaluated.)

---

## The two that are not met

### 7 — private key storage is not hardened

**State.** `KeyPair`'s `Debug` implementation redacts the private key, so a
log line or a panic message cannot leak it, and that is tested. At rest, in
`aip_core::store`, key material is **plaintext JSON**.

**What it costs.** Anyone who can read those files has the keys — including
the collector's signing key, which is the anchor for every attested
observation. The observer-independence guarantee (I10) assumes an attacker
on the observed host cannot reach the collector's key; it says nothing
about an attacker who can read the collector host's filesystem.

**Why this programme did not close it.** Hardening key storage means
choosing a mechanism — OS keyring, passphrase-wrapped file, TPM-sealed
blob, HSM, or an external KMS — and each choice has operational
consequences for provisioning, backup, rotation, disaster recovery and
which platforms are supported. Picking one silently inside a proof-layer
programme would put an operational decision into a security commit where
nobody would look for it, and adding `zeroize` to in-memory buffers while
the file on disk stays plaintext would be exactly the security theatre the
correctness skill forbids.

**What closing it needs:** a decision on the custody mechanism, then an
implementation with migration for existing stores.

### 8 — the bundle trust anchor is not fixed

**State.** `verify_bundle_signature` checks the manifest against
`manifest.signer_public_key` — a key carried inside the bundle. That is not
a trust anchor and cannot be one: a forger ships their own.

**What is not wrong with it.** The code does not overstate: the failure
message says "manifest not signed by the **embedded** key", the report
shows `authority chain verified: Not in this report` when no `--trust`
anchors are given, and the overall result degrades to *NOT FULLY VERIFIED*.
The security-relevant checks are on the evidence *inside* the bundle, under
caller-supplied anchors, so the wrapper is a container-integrity check
rather than a security boundary — the same role JSON plays for a NEXORA
proof.

**What is still wrong with it.** A reader who stops at
`BUNDLE_SIGNATURE: Pass` learns less than the word "signature" suggests.
The bundle answers "this manifest matches this key" and never "this
manifest came from anyone in particular". `verify_zip` already receives a
`VerificationContext` carrying the anchors the caller trusts, and does not
compare the signer against them.

**The fix, which is small and deliberately not applied here.** Add a
distinct `SIGNER_ANCHORED` check: if the embedded signer key matches one of
the caller-supplied anchors, pass and name it; otherwise warn, saying the
signature establishes internal consistency and not authorship. It is
perhaps thirty lines.

It is not applied because it changes bundle verification semantics — a
bundle that reports `Pass` today would report `Warning` — in
`aip-protocol`, a layer outside this programme's remit, and the directive
is explicit that verification semantics must not be altered silently and
that a wire or reporting change is a deliberate act rather than a
convenience. It should be its own change, with its own RED test and its own
review of who consumes `BundleVerification::overall`.

---

## What this evaluation does not establish

That the eighteen met criteria are the right eighteen, or that satisfying
all twenty would make the system production-ready. §25 is a gate for
promoting a branch, not a definition of readiness — and
`NEXORA_IMPLEMENTATION_REPORT.md` §12 lists seven boundaries that remain
open regardless of promotion, including the absence of external anchoring,
kernel-resident sensing, and any evidence strong enough to make the
response pipeline reachable.

**No promotion action has been taken.** `main` is untouched.
