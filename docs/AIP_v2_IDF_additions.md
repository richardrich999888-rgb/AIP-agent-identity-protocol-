# AIP v2 — IDF Additions: Three Novel Mechanisms

**Document type:** Invention Disclosure Form (IDF) Supplement
**Subject:** Agent Identity Protocol v2 — Novel Mechanisms NM-A1, NM-A2, NM-A3
**Filing basis:** Continuation of AIP v0.3.0 (PATENT_DOSSIER_CCVL_AIP.md)
**Prepared for:** Prometheus IP (attorney's review)

---

## Novel Mechanism NM-A1: Scope Intersection Enforcement in Delegation

### What It Does

In multi-agent AI systems, agents frequently delegate tasks to sub-agents. A critical security requirement is that a sub-agent can never receive *more* authority than the delegating agent holds. NM-A1 defines a formal algebraic mechanism — borrowed from lattice theory — that enforces this constraint at the protocol level, making scope escalation through delegation cryptographically impossible.

When an agent holding scope S₁ delegates to a sub-agent requesting scope S₂, the protocol computes `effective = S₁ ∩ S₂` (the lattice MEET operation). If the intersection is empty (⊥), the delegation is rejected outright. The effective scope is the intersection: only actions permitted by *both* the parent and the child's requested scope are granted. The sub-agent's signed token encodes only this intersection — there is no path by which a clever attacker could request a scope that exceeds what the parent holds.

Four named scopes are defined in a strict hierarchy (`ADMIN ⊇ ORCHESTRATOR ⊇ AUDIT_READER ⊇ SUBMITTER`), plus a `Custom(String)` variant for application-specific named capabilities. This hierarchy, combined with the intersection operation, means the system has a fully-specified partial order — any scope is comparable to any other, and the lattice is always well-defined.

### Why It Is Novel

Prior art (OAuth 2.0, SPIFFE, ZCAP-LD) defines capability scopes as opaque string sets. Intersection is either undefined or performed by the application layer, not enforced by the identity protocol itself. AIP v2 is the first agent identity protocol to encode the MEET operation directly into the token issuance and delegation functions, making privilege escalation through delegation a protocol-level impossibility rather than an application-level responsibility. The combination of (1) provenance-bound identity (NM-10 from v0.3.0), (2) lattice-typed scopes, and (3) intersection enforcement at issuance time constitutes a novel and non-obvious composition.

**Representative claim element:** "a delegation engine configured to compute the lattice meet of a parent scope and a child requested scope, and to reject the delegation when the meet is empty."

---

## Novel Mechanism NM-A2: Cryptographic Delegation Chain Traversal

### What It Does

A single delegation hop (parent → child) is straightforward. NM-A2 extends this to arbitrary-depth chains: agent A delegates to B, B sub-delegates to C, C sub-delegates to D, and so on up to a maximum depth of 8. Any external verifier can traverse this chain and determine the effective scope at the leaf node, with full cryptographic assurance that every hop is valid.

The `verify_delegation_chain` function takes the root token, a sequence of `DelegationToken` structs (the chain), and a map of public keys. It verifies: (1) each hop's Ed25519 signature against its issuer's public key, (2) the JTI linkage (`chain[i].parent_jti == chain[i-1].jti`), (3) the depth monotonicity (`chain[i].depth == i + 1`), and (4) the scope subset relation (`chain[i].scope ⊆ chain[i-1].scope`). If every check passes, the function returns the leaf node's effective scope — the most attenuated scope in the chain, which is guaranteed to be ⊆ every ancestor's scope by construction.

This enables a verifier to answer the question "what can agent D actually do?" with a single function call that requires no network access, no service availability, and no trust in any intermediary — only the root issuer's public key.

### Why It Is Novel

Existing delegation protocols (SPIFFE SVID delegation chains, ZCAP-LD, Verifiable Credentials delegation profiles) either: (a) require a centralised registry to validate each hop, (b) do not enforce scope attenuation across hops, or (c) are defined for human-to-service delegation and assume a small fixed depth. AIP v2's chain traversal is specifically designed for AI-agent-to-AI-agent delegation in adversarial, high-throughput environments where: the chain depth is variable and bounded, the verifier may be offline or in a different trust domain, and the scope at each hop must be mathematically constrained. No existing protocol combines all three properties in a single function that operates on a serialisable data structure without external service calls.

**Representative claim element:** "a chain verification function that, given a root token and an ordered sequence of delegation tokens, cryptographically verifies each hop's signature, JTI linkage, depth monotonicity, and scope subset relation, and returns the effective scope at the leaf node."

---

## Novel Mechanism NM-A3: Cascade Revocation Across the Delegation Tree

### What It Does

When a compromised or misbehaving agent is revoked, all capabilities it delegated downstream must also be revoked immediately. NM-A3 implements this as a graph-walk operation over the delegation tree: when a token with `cascade=true` is revoked, the revocation engine queries the `DelegationLog` for all tokens whose `parent_jti` (or any ancestor JTI) traces back to the revoked token, and inserts a revocation entry for each descendant. The entire cascade is logged as separate entries in the append-only `RevocationLog`, with each entry hashed to form a tamper-evident chain. Every child revocation entry records the cause (the parent's JTI) so the audit trail is complete.

The cascade is atomic from the caller's perspective: the `revoke()` function returns a `Vec<RevocationEntry>` containing all revocations (primary + all descendants) performed in the operation. After this call, any call to `is_revoked(jti)` for any token in the subtree returns `true` in O(1) via a HashMap index. The RevocationLog also supports file-backed persistence, so the revocation state survives process restarts.

### Why It Is Novel

OAuth 2.0 token revocation (RFC 7009) is point-revocation: it revokes exactly one token and provides no mechanism for cascading to derived tokens. ZCAP-LD and W3C Verifiable Credentials have no standardised revocation mechanism at all. Certificate revocation lists (CRLs) and OCSP apply to PKI certificates, not to capability tokens in dynamic multi-agent systems. The specific composition of (1) an append-only, hash-chained revocation log, (2) a BFS walk over the delegation tree, (3) atomic cascade semantics, and (4) O(1) revocation status check — applied specifically to multi-agent AI capability tokens — is novel and non-obvious. The cascade operation is the mechanism that makes AIP safe to deploy in production multi-agent pipelines where a single compromised agent could otherwise maintain live delegations to downstream agents indefinitely.

**Representative claim element:** "a revocation engine configured to, upon receiving a cascade revocation request for a first token, traverse a delegation graph to identify all tokens whose provenance traces to the first token, and insert a cryptographically-chained revocation entry for each identified token in an append-only log."

---

## Combined Claim Scope (Continuation Application)

The three mechanisms together constitute a patentable composition: a "cryptographically-enforced capability delegation protocol for multi-agent AI systems, comprising: scope-intersection enforcement at delegation issuance (NM-A1); multi-hop chain traversal with per-hop scope attenuation verification (NM-A2); and cascade revocation with append-only audit trail (NM-A3)."

This composition is not disclosed in any prior art found in the prior art search (Section 12 of PATENT_DOSSIER_CCVL_AIP.md). The three mechanisms are mutually reinforcing: NM-A1 prevents escalation at creation time, NM-A2 allows any verifier to confirm the chain is valid, and NM-A3 ensures that revocation propagates immediately to all dependent tokens. None of the three is independently new in all aspects, but no prior art system combines all three in a single coherent protocol for AI agent identity.

---

*Filed by AIRON project — Prometheus IP filing reference pending.*
