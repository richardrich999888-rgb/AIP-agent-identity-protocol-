# ADR-017 — AIBOM: Standing Is Derived, Never Declared

**Status** ACCEPTED
**Date** 2026-10-25
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `65eb9e6`
**Related** ADR-003 (observation-class boundary), ADR-014 (conformance program),
`docs/architecture/AIBOM_ARCHITECTURE.md` (the design this decides)

---

## Context

An AI Agent Bill of Materials is an inventory of what an agent is and what it
is authorised to do. Every AIBOM proposal in circulation lets the document say,
per field, whether the field is "declared", "discovered" or "verified". That is
the defect. A manifest that can write `"verified"` next to a permission is a
manifest that can lie about it, and the reader has no way to tell the
difference from the bytes alone.

This repository already holds the machinery that *can* tell the difference:
identity derivation (`validate_aid`), delegation-chain verification
(`verify_delegation_chain`), decision-point verification
(`verify_expected_execution`), and an offline verifier that re-derives verdicts
from carried evidence (`verify_nexora_proof`). What it lacks is an inventory
that consumes them.

## Decision 1 — the manifest carries no standing at all

The input manifest has **no field** in which a standing can be written. A field
may *cite* evidence by artifact id; it may not assert what that evidence
establishes. `#[serde(deny_unknown_fields)]` makes an attempt to add one a
parse failure rather than an ignored key a human might misread.

## Decision 2 — every standing is the output of an existing core verifier

`aip-aibom` defines no verification of its own. A field reaches `Verified` only
when a core verifier accepts a carried artifact and that artifact supports the
field as declared; it reaches `Observed` only when `verify_nexora_proof` accepts
a proof, and then at exactly the strength NEXORA re-derived. The crate reuses
`aip_reconcile::EvidenceStrength` rather than defining a strength of its own.

## Decision 3 — trust inputs come from the assessor, never from the bundle

The evidence bundle is supplied by the party being assessed. Issuer keys,
decision-point anchors, NEXORA verifier anchors, revocations and the present
time come only from the assessor's context. A bundle that omits a revocation
cannot thereby un-revoke a token, because the bundle has no revocation field.

## Decision 4 — the output vocabulary cannot express an overclaim

`Standing` has no `Assumed`, `Trusted`, `Compliant` or `Mitigated` variant.
`Assessment` is `Serialize` and not `Deserialize`, for the reason
`VerifiedProof` is not: an assessment that could be read back from bytes is an
assessment an author could write.

## Decision 5 — the seal is detached and establishes authorship only

The manifest does not contain its own digest. A seal is a separate object over
the manifest's canonical digest, and its meaning is *"this publisher issued this
inventory, unaltered"*. It never upgrades any field — the same rule
`ProofAssembler` follows.

## Decision 6 — some fields are unknowable, and the product says so

A hosted model's identity is `Unknowable(N-3)`; that specific weights were
loaded is `Unknowable(N-4)`; a post-quantum claim is `Unknowable(N-10)`. These
are not gaps to be closed by better evidence. They are the limits
`AIRI_LIMITATIONS.md` already records, surfaced per field.

## Decision 7 — consume the newer verifiers; do not re-derive what they say

`aip-ledger`'s own documentation draws the line this crate sits on: the
inventory *"is the entity's: it names owners, business purposes, model
vendors and approval dates, none of which this system knows or should
invent"*, and its `InventoryEntry` is the evidence attachment. The AIBOM
manifest is that declaration; the assessment reconciles it, field by field,
against the attachment and the other verifiers:

- **C6** — `AccessLedger::verify`. A resource the ledger shows reached is
  `Verified { AccessLedger }`; its access mode stays the author's word; an
  adverse row is critical; a resource reached and not declared is high.
- **C4** — `verify_tool_receipt`. A forwarded call is
  `Verified { ToolGateway }`; a refused one is reported and not credited; a
  tool used at the gateway and not declared is high. The effect remains
  `Unknowable(N-2)`: the receipt says what the gateway received.
- **C5 gates** — `verify_artifact` and `compare_shown_to_authorized`. A
  divergence is critical. Agreeing approvals are counted, and the gate is
  still `SelfReported`, because no expectation carries an amount.

Each of those verifiers refuses an anchor equal to the agent's own key; the
assessor passes `AssessorContext::agent_public_key` to every one.

## Alternatives rejected

**A `basis` field in the manifest, validated by the assessor.** Rejected: it
leaves an attacker-writable word next to every field, and the report then has
to explain why its own input disagrees with it.

**A new evidence hierarchy for inventory claims.** Rejected: there are already
three (`EvidenceCeiling`, `EvidenceStrength`, `EvidenceClass`), each with a
precise scope. A fourth would be a second source of truth.

**Reconciling execution inside the assessor.** Rejected: NEXORA is the
authoritative verifier. The assessor reads `VerifiedProof`; it never calls
`reconcile_*`. A structural test enforces it.

**Treating a ledger row's `Verified` standing as this crate's `Verified`.**
Rejected: they answer different questions. The ledger's row standing
summarises reconciliation verdicts about an access; this crate's standing is
about whether the *declaration* is backed. A row of any standing backs "the
agent reaches R". An adverse row is reported as its own finding, verbatim.

**Inferring amount limits from tokens.** Rejected: `CapabilityScope` carries no
amounts. A limit is `SelfReported` and the report says where it would have to be
enforced. Pretending otherwise is the $1,000 / $5,000 demo that fails.
*Amended by ADR-018:* a per-action limit is now verifiable — not from a token,
but from an institution-signed spend policy the decision point enforces. The
rejection of inference stands.

## Consequences

The product's headline output is not an inventory. It is, per field, *who says
so*: a core verifier, an independent observer through NEXORA, a discovery the
assessor ran itself, or only the manifest's author — and, where no mechanism can
answer, which non-establishment says so.

## A finding in the core, surfaced while building this

**`AgentIdentityDocument::expires_at` is not covered by the identity's
self-signature, and `validate_aid` does not check it.**
`aip_core::canonical_encode_aid` — the bytes the self-signature covers —
encodes the magic, version, flags, id, creation time, primary key, provenance,
status, sequence, lineage depth and the two Merkle roots. It does not encode
`expires_at`. A holder of the document can extend or delete its expiry and
`validate_aid` still accepts it. `tests/assess_identity.rs::
an_unsigned_identity_expiry_is_reported_and_not_relied_on` demonstrates this
against the current core.

**What this crate does about it:** relies only on signed fields. Identity
liveness is read from `status`, which *is* signed; `expires_at` is never read,
and its presence is reported as `UnsignedIdentityExpiry`.

**What this crate does not do:** fix it. Covering `expires_at` changes the
self-signature payload — a wire-contract change to `aip-core` that invalidates
every existing identity document, and belongs under the
`aip-protocol-change-guard` discipline with a version bump, not inside a
product build.

A second suspicion was checked and **withdrawn**: `validate_aid` does refuse a
document with no self-signature (`MissingRequiredField`). An earlier reading
of the code missed the `else` branch; the test written to demonstrate the
defect failed, and the claim was dropped rather than reported.
