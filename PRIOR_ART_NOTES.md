# Prior-art notes — signed per-tool-call receipts (ToolReceipt)

> **Purpose.** The task gates Phase 2 (the ToolReceipt gateway plugin, blocker
> B10) on this review, and the register requires it before any patent filing.
> This is a first-pass developer review from public descriptions, **not a
> freedom-to-operate opinion**. It exists so the Phase-2 work is not built, and
> nothing is filed, in ignorance of the three projects that occupy this space.
> A qualified patent attorney must review before any filing; the claims below
> are what a searcher finds, not a legal conclusion.

## The space: cryptographically signed audit of each AI tool call

| Project | What it claims (from public docs) | Overlap with our `ToolReceipt` | Distinguishing line to check with counsel |
|---------|-----------------------------------|-------------------------------|-------------------------------------------|
| **MCPKernel** (`github.com/piyushptiwari1/mcpkernel`) | "Deterministic Execution Envelopes (DEE) — every execution is hashed and Sigstore-signed for replay"; Sigstore audit for every tool call | Direct: signed, replayable per-call envelope | Ours binds the receipt to an **independently kernel-observed execution** and reconciles the two; MCPKernel signs the call, not an independent observation of the effect. The novelty, if any, is the *reconciliation against out-of-band kernel evidence*, not the signed receipt itself. |
| **HELM AI Kernel** | "every ALLOW/DENY/ESCALATE decision produces a cryptographically signed receipt, bundled into an offline-verifiable EvidencePack" | Direct: signed decision receipt + offline-verifiable bundle | Same distinguishing line: HELM signs the *decision*; ours reconciles the decision and the receipt against a *separate observer that does not trust the gateway*. |
| **Etch** | Merkle-chained signed audit, hybrid Ed25519 envelope, **post-quantum** (FIPS 205 SLH-DSA) | Merkle-chained signed audit overlaps our NEXORA log | **PQC is out of scope for us** — cite Etch as prior art only; do not adopt its envelope. Our chain is Ed25519 + SHA-256 by deliberate choice. |

## What this means for Phase 2

1. **The signed per-tool-call receipt is not novel on its own.** At least three
   projects ship it. Any framing that rests on "we sign tool calls" is weak and
   should not be filed.
2. **Where our design may still be distinctive** is the *combination the rest of
   this repository already builds*: a gateway receipt that commits over the
   canonical body, reconciled against an **independent kernel observer that does
   not trust the gateway or the agent**, with the divergence between claimed and
   observed becoming a typed verdict (`UNATTRIBUTED_EFFECT` / `PHANTOM_CLAIM`).
   That reconciliation-across-independent-authorities is the thing to examine,
   not the receipt.
3. **Build Phase 2 as integration, not invention.** The ContextForge plugin
   should reuse the existing `ToolReceipt` / `compare_tool_boundary` shapes in
   `aip-airi`; it is wiring an existing verifier to a real gateway, not a new
   cryptographic construction.

## Open items for counsel

- Freedom to operate against MCPKernel's "Deterministic Execution Envelope" and
  HELM's "EvidencePack" — both are close enough in wording to warrant a real
  search of any filed/pending claims.
- Whether the reconciliation-against-independent-observation combination is
  itself claimable or is anticipated by prior multi-source audit art.
