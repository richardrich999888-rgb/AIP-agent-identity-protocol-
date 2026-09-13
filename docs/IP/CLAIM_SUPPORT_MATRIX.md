# Claim support matrix — what the code reduces to practice

**Status** ENGINEERING ASSESSMENT — not a legal opinion, not a novelty opinion
**Date** 2026-09-13
**Assessed head** `claude/vanian-audit-maturity-addendum-n5ysvd`, which carries the
production branch at `12767ea` plus the Sniffer Dog 3.0 tiers
**Occasion** a strategy brief dated 2026-09-13 recommending three provisional
filings "now"

---

## 0. What this document is for, and its lane

A patent claim describes a method. This document answers one narrow,
checkable question for each proposed claim: **does the code in this
repository actually perform the method as drafted?**

It does **not** assess novelty, non-obviousness, eligibility, or freedom to
operate. The brief is right that a professional FTO and novelty search is
mandatory, and nothing here substitutes for one. `docs/IP/INVENTION_REGISTER.md`
already states that no prior-art search has been performed and that no entry
is asserted to be patentable.

The reason this document exists is narrower and more urgent: **one of the
three proposed claims describes a state this implementation cannot reach**,
and an internal forensic audit saying so already exists in the repository. A
filing that claims a method your own audit says is unreachable is a diligence
liability, not an asset.

---

## 1. Three corrections to the brief, verified against source

The brief is strong on the market and the standards landscape. It is wrong
about this codebase in three places, each of which changes a recommendation.

### 1.1 The evidence ladder has four levels, not three

The brief repeatedly describes "Indicator → Corroborated → Proof" and calls
the "two-axis Severity × Strength model" with "quarantine only on Proof" the
most defensible claim available.

The actual type (`aip-reconcile/src/result.rs:93`):

```rust
pub enum EvidenceStrength { Heuristic, Correlated, Attested, Proven }
```

Four levels. `Attested` — the one the brief's three-level ladder has no slot
for — is where **every** content-derived workload verdict is pinned. Any
claim drafted against a three-level ladder does not read on this system.

### 1.2 Proof-gated containment describes an empty set

This is the finding that should stop the filing as drafted.

`aip-reconcile/src/reconcile.rs`, `precondition_holds` — every
workload-directed verdict requires **equality**, not a floor:

| verdict | required strength |
|---|---|
| `VerifiedExecution` | `strength == EvidenceStrength::Attested` |
| `UnattributedEffect` | `strength == EvidenceStrength::Attested` |
| `PhantomClaim` | `strength == EvidenceStrength::Attested` |
| `IdentityDivergence` | `strength == EvidenceStrength::Attested` |
| `LineageViolation` | `strength == EvidenceStrength::Attested` |
| `SensorIntegrityFailure` / `ContinuityFailure` | `strength >= EvidenceStrength::Attested` |

`aip-containment/src/contain.rs` gate 5 refuses everything below `Proven`:

```rust
other @ (EvidenceStrength::Heuristic
       | EvidenceStrength::Correlated
       | EvidenceStrength::Attested) => return Err(Refusal::StrengthBelowProven(other)),
```

Gate 6 then requires a *workload* violation class. The two verdict classes
that may carry `Proven` are observer-directed and are refused by gates 4 and
6. **The set of engine-producible records that can reach containment is
empty.** The forensic audit proved this by exhaustive 32-cell sweep
(Report 04 §3, EXECUTION-PROVEN) and recorded it as blocker **B-3**;
`FINAL_AUDIT_RECONCILIATION.md` §13 classifies it **ACCEPTED / JUSTIFIED** —
a deliberate design position, not an unfixed bug.

The code states its reason, and the reason is good:

> *"the content is procfs-read and can never be `Proven`"*

`Proven` is reserved for facts a third party can recompute from held bytes.
That is why `classify_observer_error` grants `Proven` for signature
arithmetic and refuses it for a bad local trust anchor.

**Consequence for the filing.** The brief's claim 1 — *"initiating automated
containment … only when the classification reaches cryptographic proof that
the observed effect diverges from a cryptographically sealed prior
authorization"* — is a method this implementation cannot perform, for a
principled reason it has written down. See §3 for what to do about it.

### 1.3 There is no post-quantum cryptography in this codebase

The brief spends a section on ML-DSA-87 signing latency, rejection-sampling
variance, and batch-signing Merkle roots, and lists "post-quantum by design
(ML-DSA-87)" among the claimed differentiators to de-prioritise.

There is nothing to de-prioritise. No Cargo manifest in the workspace pulls
`pqcrypto`, `fips204`, `liboqs`, or any ML-DSA implementation.
`AlgorithmId::MlDsa65` exists as a **wire enum variant with no implementation
behind it**, and its only appearances in `aip-crypto` are inside a *negative*
test asserting that an Ed25519 signature mislabelled `MlDsa65` must **not**
verify. The six-branch audit reached the same conclusion independently
(Report 05 §6: *"No branch of AIP proper (main, prod) contains any
post-quantum code"*), and `INVENTION_REGISTER.md` says post-quantum
cryptography "appears nowhere above, because none of [it] is implemented."

The brief's engineering advice is sound and should be kept on file for when
PQC is built. It is currently advice about a system that does not exist, and
**"post-quantum stack" must not appear in procurement or investor material**
until it does.

### 1.4 Minor: the TRL figure

The brief says third-party validation is "absent at current TRL 6." The
code-verified assessment in `docs/ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md`
is **≈ TRL 5 overall**, with physical autonomous-system accountability at
**2–3**. TRL 6 would require demonstration in a relevant environment, which
for anything physical has not been entered. Use 5.

---

## 2. The matrix

| # | Claim as the brief drafts it | Reduced to practice here? | Where |
|---|---|---|---|
| 1 | Containment initiated **only** on cryptographic proof of divergence from sealed authorization | **NO — unreachable.** Gate requires `Proven`; every workload verdict is pinned at `== Attested` | `contain.rs` gate 5 vs `reconcile.rs` `precondition_holds`; audit B-3 |
| 1a | *The evidence-strength ladder itself*, with `Proven` defined as third-party-recomputable and equality rather than threshold comparison | **YES** | `result.rs` `EvidenceStrength`; `precondition_holds`; `classify_observer_error` |
| 1b | Two-axis severity × strength ceiling with **no arithmetic composition** (`min3` of independent caps, no `confidence: f32` anywhere) | **YES** | `aip-warrant/src/warrant.rs::evaluate`; IR-05 |
| 2 | Reconciling a kernel-observed effect against a hash-chained sealed intent produced **before** the action; divergence when no sealed intent corresponds | **YES** | `aip-authorize` `ExpectedExecution` (signed, pre-action) + `aip-observe` `AttestedBatch` + `aip-reconcile`; IR-06 |
| 2a | Coverage **re-derived** by the verifier rather than read from the artifact under judgement | **YES** — and this is stronger than the brief's framing | `recompute_coverage`; NEXORA `derive_coverage`; IR-03 |
| 2b | Offline re-derivation of the verdict, refusing a package whose claim is not derivable from its own evidence | **YES** | `aip-nexora/src/verify.rs` `rederive`, `ClaimNotDerivable`; IR-07 |
| 3 | **DID**-to-kernel-process binding | **PARTIAL.** The binding is real; the identifier is not a W3C DID | `ExecutionBinding` → `ProcessInstance {pid, start ticks, boot id}`; identity is `derive_aip_id`, a Base58 key-derived AIP-ID |
| 4 | Captured-approval-artifact vs kernel-observed effect ("shown-vs-executed") | **PARTIAL — the shown-vs-*authorized* half now exists**; the shown-vs-*executed* half needs the reconciler gate | `aip-approval` (new); §3.2 |
| 5 | Observer that reports its own blindness and fails closed | **YES**, and it is stronger evidence than the brief credits — a reproduced attack plus a shipped mitigation | `ObserverState::IntegrityUnknown`; sealed validation runs; `12767ea` |

**Row 5 is underweighted by the brief.** The observation-integrity work is
the only item in this repository where an attack on the accountability system
itself was reproduced deterministically, mitigated in production, and
re-verified against the reproduction. The brief mentions the eBPF-rootkit
blinding threat abstractly and recommends TEE attestation; it does not
notice that a weaker, much more common version of that threat — *any
co-resident eBPF program on a sampled tracepoint* — was already found,
reproduced with a two-instruction BPF program, and closed. That is a
reduction to practice with sealed evidence behind it.

---

## 3. What to do about claim 1

Three options. One is recommended.

### Option A — file as drafted
**Rejected.** The specification would describe a method the accompanying
implementation cannot perform, and an internal audit establishing that fact
is already in the repository and will surface in technical diligence. The
audit's own IP-1 finding says this in terms:

> *"A claim describing an end-to-end system that observes, reconciles,
> warrants and contains would not be supported by a reduction to practice,
> because the fourth stage cannot be entered from the third."*

### Option B — narrow the claim to `Constrain`
Draft against the response class the engine **can** actually reach at
`Attested`. Honest, immediately supported, and weaker — `Constrain` is a
smaller commercial story than autonomous containment.

### Option C — make the claim non-empty first, then file *(recommended)*

The reason nothing reaches `Proven` is that every divergence class the engine
has is **content-derived** — it rests on bytes read from the observed host,
which root can forge. That is a property of those classes, not of the ladder.

A divergence between **two signed artifacts** is not content-derived. It is
arithmetic over held bytes, recomputable by a third party offline — the exact
property `classify_observer_error` already accepts as `Proven` for signature
arithmetic.

**Shown-versus-authorized is such a divergence.** The approval surface signs
what it showed a human; the decision point signs what it sealed; the
comparison is a digest equality over two verified documents. Nothing is read
from the observed host.

So the brief's own Stage 2 item is the **enabling precondition for its Stage 1
claim 1**, not an independent second-priority upgrade. The dependency runs the
other way from how the brief orders it.

`aip-approval` (this commit) builds the comparison and marks its basis
(`Basis::Recomputable`). It deliberately does **not** wire a verdict, because
that is a new way to accuse and is gated — see ADR-009 §4 and the four
preconditions in the crate's module docs. What it establishes today:

- a signed, domain-separated approval artifact the agent cannot manufacture
  (refused when the surface anchor is the agent's own key);
- a pure comparison against a *verified* `ExpectedExecution`;
- the Replit class caught as `ParametersDiffer` at `Basis::Recomputable`;
- absence, a different decision, and an unverifiable expectation all
  resolving to `NotEvaluated`, never to an accusation.

**Recommended filing posture:** draft claim 1 around the *evidence-strength
architecture* (1a + 1b, both reduced to practice), and draft the
containment-trigger limitation around **a divergence whose basis is
third-party recomputation from signed artifacts** — which `aip-approval`
supports today and which the reconciler gate would consume. That is a claim
the implementation can grow into along a path already written down, rather
than one it contradicts.

---

## 4. Prior-art exposure the brief identifies, restated as an engineering task

The brief's most useful IP observation is that the heaviest prior art for the
two most valuable concepts is **public preprints and vendor blogs**, not
patents. Two consequences it does not draw out:

1. **This repository is itself a disclosure.** It is proprietary and
   unpublished, but `README.md` states an intent to open-source the spec and
   core crates, and `docs/idex_open_challenge/` was prepared for an external
   submission. Any public release starts a clock. Sequence the filing before
   the publication, not after.
2. **IETF SPICE `draft-mw-spice-intent-chain` is the closest neighbour** and
   should be read as an interop target rather than a competitor, exactly as
   the brief says. Note the actual relationship: SPICE chains *content
   provenance*; this system reconciles *sealed intent against independently
   observed execution*. The layer above is the part to claim.

---

## 5. What this document does not establish

- That any claim here is novel, non-obvious, or eligible. No prior-art search
  has been performed by this assessment or by the repository.
- That the brief's patent numbers, assignees, or funding figures are correct.
  They were not verified here, and the brief itself flags the assignees as
  inferred.
- That `aip-approval` closes claim 4. It closes the shown-versus-*authorized*
  half. The shown-versus-*executed* half requires joining to the observer,
  which is a reconciler change and is gated.
- That containment should be made reachable. §3 recommends making a
  *divergence class* eligible; whether containment should then fire on it is
  a separate operator decision, and B-3 remains ACCEPTED/JUSTIFIED until
  someone takes it.
