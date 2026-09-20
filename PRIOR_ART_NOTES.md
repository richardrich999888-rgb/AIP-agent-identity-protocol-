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

---

# Name collisions — "AIP" and "AIRI"

> **Added 2026-09-20 after a search that should have happened earlier.** These
> are **name** findings, not technical-overlap findings. Same first-pass
> developer-review caveat as above: what a searcher finds, not a legal
> conclusion, and counsel must review before any filing or public launch.
>
> **Verification limit, stated plainly:** `arxiv.org` and `www.ietf.org` are
> both blocked by this environment's egress proxy. Everything below about the
> two documents comes from **search-result metadata and abstracts**, not from
> reading them. Nobody may treat the technical distinction drawn here as
> established until someone has read both in full.

## 1. "AIP / Agent Identity Protocol" — taken, by a paper *and* an IETF draft

| | Ours | The collision |
|---|---|---|
| Name | AIP — Agent Identity Protocol | **AIP — Agent Identity Protocol** |
| Artefact | this repository | arXiv **2603.24775**, submitted 27 Mar 2026, author **Sunil Prakash**; and an IETF Internet-Draft **`draft-prakash-aip-00`** |
| Subtitle | — | "Verifiable Delegation Across MCP and A2A" |

This is the more serious of the two, because an Internet-Draft is a
standards-track claim on **both the name and the problem space**, not merely a
paper. A regulator, an assessor or an investor searching "Agent Identity
Protocol" finds that draft, not us.

**Apparent technical distinction, from the abstract only.** The collision is
about *authorisation and delegation*: Invocation-Bound Capability Tokens
fusing identity, attenuated authority and provenance into an append-only token
chain, in two wire formats (a signed JWT for single hop, a Biscuit token with
Datalog policies for multi-hop), with Python and Rust reference
implementations. On the abstract's evidence it makes **no claim about runtime
or kernel observation, about establishing whether an authorised action
actually executed, or about reconciling the two** — which is the whole of what
this repository is for.

If that holds on a full read, the overlap is **the name and the delegation
layer**, not the observation layer. Our delegation model would then be
duplicative of published work and our observer would not be. That is a
survivable finding, and it is a very different conversation from discovering
it in a room.

**What must happen, in order:**

1. **Read both documents in full.** Nothing below is decidable without that,
   and neither is reachable from this environment.
2. **Decide the name.** Continuing to call the protocol "AIP" while an IETF
   draft of the same name and abbreviation exists is a choice that needs to be
   made deliberately, with counsel, not by default. The RBI submission uses
   "Sniffer Dog / AIP" throughout.
3. **Re-examine the delegation claims in `docs/IP/INVENTION_REGISTER.md`**
   against the IBCT construction. The register's observation and
   reconciliation claims are unlikely to be touched; the attenuating-delegation
   claims may be.
4. **Consider citing it.** If the distinction above survives a full read, the
   strongest position is to cite the draft in the technical brief and state
   the boundary ourselves — the same posture that has served every other
   withdrawn claim in this submission.

## 2. "AIRI" — taken by an active MIT-licensed project

Ours: `aip-airi`, "the Vanian Autonomous Intelligence Runtime Interface" — the
crate holding an agent's *self-reported* claims.

Theirs: **Project AIRI** by `moeru-ai`, an MIT-licensed open-source platform
for self-hosted AI virtual characters / VTubers. Actively developed, with its
own package suite (`xsai`, `unspeech`, MCP Launcher) and MCP support.

**No technical overlap** — a VTuber platform and an agent self-report schema
are not the same thing, and there is no plausible confusion in a BFSI context.
It is a **discoverability and search-collision** problem, one degree less
serious than the AIP finding. `aip-airi` is an internal crate name that appears
in the technical brief; renaming it is cheap now and expensive later.

## 3. "Sniffer Dog" — no collision found

A search for "Sniffer Dog" as an AI-agent runtime-monitoring or security
product returned nothing. "Sniffer" is a legacy trademark of the Network
General protocol analyser — a different product category and long superseded —
and a CES entry uses "digital sniffer dog" for an olfactory sensing system,
which is unrelated. **This is a weak negative**: absence in one search is not
a trademark clearance, and a search is not a registry check. A proper
class-9/class-42 trademark search is counsel's job and has not been done.
