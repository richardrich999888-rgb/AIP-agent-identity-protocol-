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
| Merkle **tree** builder | **CLOSED (Gate 6, `aip-nexora::merkle`)** — RFC 6962 tree over domain-separated leaves |
| Root over an actual set | **CLOSED (Gate 6)** — `MerkleTree::root` / `root_of`; `merkle_empty()` is the root of the empty tree only. The `aip-core` placeholders at `lib.rs:62,63,647` are unchanged and still not commitments |
| Inclusion proof + verifier | **CLOSED (Gate 6)** — `inclusion_proof` / `verify_inclusion` (RFC 9162 §2.1.3.2), bound to index and tree size; `consistency_proof` / `verify_consistency` (§2.1.4.2), forward only |
| Cross-packet sequence numbers | **CLOSED (Gate 7)** — a record's position in a `CommitmentLog` is its order; heads chain by `prev_head` |
| Anchoring of a chain head | **PARTIAL (Gate 7)** — `SignedHead` under `SYNTRIASS/NEXORA/HEAD/v1`, `AnchorSink` / `MemoryAnchor`, `HeadTracker` (rollback, fork, broken chain refused). The *externality* of the anchor is a deployment: no anchor outside this process exists in the repository |
| Replay/uniqueness | **PARTIAL (Gate 7)** — a proof object is bound to a head of one size; a tracker treats a repeated head as `Same`, not an advance. The packet verifier's own seen-set is unchanged (the `aip-protocol` P1 gap) |

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

## PR #3 review note (post-audit)

`OT_SENTINEL_HARVEST_AUDIT.md` reviewed the import's NEXORA material
(TypeScript anchors, delegation graph, verifier; Rust lifecycle anchors).
Disposition: design input for Skill 10 only — anchors are hash-chained JSON
without a signature or an external anchor (I15), on a second encoding (I14).
`NEXORA = MISSING` is unchanged.

## Gate 6 note — the commitment exists; the anchor does not yet

`aip-nexora::merkle` (RED `e8e42db`, GREEN `533e44b`) closes the first
three rows of §4: an append-only RFC 6962 tree whose leaves are
`merkle_leaf(SYNTRIASS/NEXORA/LEAF/v1 ‖ kind ‖ record)` — a reconciliation
record, an attested batch, a signed health record, a warrant and an
expectation are five kinds that never collide — with inclusion proofs bound
to an index and a size and consistency proofs that run forward only. The
adversarial cases named by the mandate are each one test in
`aip-nexora/tests/merkle.rs`: changed, swapped, omitted and duplicated
leaves; changed root; transplantation; cross-domain; rollback (a refusal);
fork (two roots at one size that no proof reconciles); replay (a proof is
bound to its size). §5's warning stands unchanged: a tree in memory is a
commitment nobody else can rely on until a **signed head** exists and is
**anchored outside** the party that holds the tree — a prefix of the
history verifies exactly as well as the whole. That is Gate 7.

## Gate 7 note — the proof layer

`aip-nexora::commitment` (RED `b6868de`, GREEN `e405d96`) puts
the rest of §5's interface over the Gate 6 tree: `CommitmentLog::append`
(position = order), `head` (a `SignedHead` chained by `prev_head` under
NEXORA's own key and domain), `proof_for` (a `ProofObject`: head, kind,
record bytes, inclusion path), `verify_proof` (offline: anchors only;
yields where bytes of this digest were committed and nothing else),
`HeadTracker` (an offline party's memory: forward only, with a consistency
proof; rollback, fork, broken chain, missing or wrong proof and another
log's head are named refusals; the same head twice is `Same`), and
`AnchorSink` (`MemoryAnchor` in-tree). Tests `aip-nexora/tests/nexora.rs`
x01–x15, including a real `Reconciliation` committed by its canonical
bytes and read back by its own digest.

What it is not, restated: a committed record's own claims are untouched by
commitment (a committed `CANNOT_PROVE` is exactly as committed as a
committed `VERIFIED_EXECUTION`); nothing here authorizes, observes,
reconciles or contains; no "replay" of any execution is claimed — the
bytes are what was committed. And the anchor is only as external as its
deployment: `MemoryAnchor` is the shape, not the independence. Wiring the
reconciler's output and the collector's batches into a log as they are
produced, and durable storage of logs and heads, are not done.
