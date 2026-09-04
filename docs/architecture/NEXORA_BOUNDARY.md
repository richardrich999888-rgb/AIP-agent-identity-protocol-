# NEXORA_BOUNDARY

## 1. Current state

`NEXORA = MISSING` from production. Verified: zero occurrences of `nexora`
(case-insensitive) in any production Rust file at `377d5fc`.

NEXORA source exists **only** on `origin/import/orbitaltrust-accountability-layer`
(PR #3), which is **not merged** — ahead 1, behind 5 — and whose tree
(`orbitaltrust-accountability/`) is **absent from HEAD**. Per **I17** it is not
production capability. It is legitimate design input and nothing more.

What that branch actually contains, for reference: a hash-chained lifecycle
anchor format (`NexoraAnchorType`, 8 milestone variants), a browser IndexedDB
writer, and a Rust reader in `ot-verifier`. It is a *format*, not a service.

## 2. What NEXORA must be — and must not be

Per the skill's §17, NEXORA is the **portable commitment layer**. It must not
duplicate:

| Must not duplicate | Because |
|---|---|
| AIP identity | `derive_aip_id` is already single-implementation and spec-exact (**I18**) |
| AIP authorization | duplicating it is exactly the `aip-service` mistake already in-tree (§5 of `CURRENT_SYSTEM.md`) |
| Kernel sensing | that is the observer's job |
| Policy enforcement | that is the warrant engine's job (**I19**) |

Its sole responsibility: given a verified execution history, produce a
**portable cryptographic commitment** that a third party can check offline,
without access to the running system, and that detects truncation, reordering
and rollback of that history.

## 3. What AIP already offers it

| Artifact | Location | Usable as |
|---|---|---|
| `packet_hash: [u8;32]` | `evidence_packet.rs:210-246` | commitment leaf |
| `decision_id`, `packet_id` | `:85`, `:210` | stable identifiers |
| `agent_sig`, per-action sigs, receipt countersig | `:111`, `:325` | authenticity of leaves |
| `VerificationReport` (JSON) | `verification_report.rs` | per-rule verdicts + derived floor |
| Signed bundle + per-file SHA-256 manifest | `bundle.rs:69-163` | an existing portable export format |
| `merkle_leaf` / `merkle_internal` | `aip-crypto/src/lib.rs:211,217` | correct, domain-separated (0x00/0x01) primitives |

## 4. What is missing for a real commitment layer

| Missing | Evidence |
|---|---|
| Merkle **tree** builder | none — only the two node helpers exist |
| Root over an actual set | none — production roots are all `merkle_empty()` (`aip-core/src/lib.rs:62,63,647`) |
| Inclusion proof + verifier | none |
| Cross-packet sequence numbers | none — packets carry no ordering relative to each other |
| Anchoring of a chain head | none — `authority_journal`-style head publication does not exist in production |
| Replay/uniqueness | none — the same packet verifies identically forever (`VerificationContext` has no seen-set) |

Per **I15**, having `merkle_leaf` and `merkle_internal` is *not* having a
commitment protocol. The gap between the two is the whole of NEXORA.

## 5. Boundary contract (design only)

```
   AIP Authorization  (ExpectedExecution, signed by the decision point)
 + Observed Execution (ObservedExecution, signed by the observer)
 + ExecutionBinding   (agent ↔ process instance)
 + Continuity         (observer health chain)
 + Evidence           (EvidencePacket + VerificationReport)
            ↓
   NEXORA commitment:  ordered, append-only, externally anchorable
```

Minimum interface, not implemented:

```rust
trait CommitmentLog {
    /// Append one verified execution record; returns its position.
    fn append(&mut self, record: &VerifiedExecution) -> Result<u64, CommitError>;
    /// Root over all records to date. Must be over a REAL set, never empty-by-default.
    fn root(&self) -> [u8; 32];
    /// Proof that `position` is included under `root`.
    fn inclusion_proof(&self, position: u64) -> Result<InclusionProof, CommitError>;
    /// Head for external anchoring — without this, truncation is undetectable.
    fn signed_head(&self) -> SignedHead;
}
```

`signed_head` is the load-bearing part. An unanchored append-only log detects
edits but **not** truncation: a prefix of a hash chain verifies exactly as well
as the whole chain. This is already demonstrably true of
`aip-core/src/scoped_audit.rs` (`verify_chain:217-251` checks only internal
consistency), which is why that module cannot be promoted into NEXORA as-is.

## 6. Sequencing

NEXORA is **step 10** in the skill's §23 order and should stay there. Building
it earlier produces a cryptographic commitment over evidence that is itself
self-attested — a portable proof of an unverified claim, which is worse than no
proof because it looks authoritative.

Precondition for starting NEXORA: `VERIFIED_EXECUTION` must be producible, i.e.
the decision point, execution binding, observer and reconciler all exist.
