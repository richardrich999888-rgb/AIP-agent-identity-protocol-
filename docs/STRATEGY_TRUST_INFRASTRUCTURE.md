# AIP — Board-Level Strategic Report
## From "Identity for AI Agents" to Trust Infrastructure for Autonomous Systems

**Prepared:** 2026-06-16 · **Classification:** Board / founder strategy
**Source of truth:** the code in this repository at commit `9fcfbcd`, not prior narratives.

> **Premise correction, up front.** The brief states the Accountability layer
> is "currently weak or incomplete." As of the last two work sessions that is
> **no longer true**: `aip-protocol` implements EvidencePacket v1, a 14-rule
> verification engine, and a per-action accountability graph, with 214 passing
> tests and a working end-to-end demo. The strategic problem is different and
> sharper: **the only deployable artifact (`aip-service`) shares zero code
> with the valuable crates (`aip-core`, `aip-protocol`).** The crown jewels
> are a library; the product is a demo that doesn't use them. That gap — not
> the absence of an accountability layer — is the company's central issue.

---

## TASK 1 — Repository classification (code as source of truth)

| Crate | LOC | Classification | Reasoning |
|---|---:|---|---|
| `aip-protocol` (EvidencePacket, verifier, accountability graph) | 2,253 | **STRATEGIC CORE** | The only thing here that is novel *and* enterprise-relevant. Tamper-evident, offline-verifiable, authority-bound action evidence. This is the company. |
| `aip-core` (delegation lattice, capability MEET, revocation, scoped audit) | 5,046 | **STRATEGIC CORE** | The authority engine the core depends on. Per-hop signed delegation, mathematical attenuation, cascade revocation. Without it the EvidencePacket has nothing to bind to. |
| `aip-crypto` | 269 | **Important supporting infra** | Correct, tight Ed25519/SHA-256/Base58. Necessary, not differentiating — commodity primitives assembled well. |
| `aip-types` | 616 | **Important supporting infra** | Shared wire structures. Will need versioning discipline as the format becomes a standard. |
| `aip-real-tests` | 1,771 | **Important supporting infra** | Adversarial/property/stress suite. Strategic as *credibility evidence* — the thing that makes the core believable in diligence. |
| `aip-test` | 332 | Supporting | Integration tests. Fine. |
| `banking_demo` | 233 | Supporting (high leverage) | The sales/pilot artifact. Tiny code, outsized commercial value. Keep and grow into vertical demos. |
| `aip-cli` | 314 | **Commodity** | Local utility. Useful for devs, no strategic weight. |
| `aip-service` | 2,057 | **DELETE / REWRITE CANDIDATE** | A parallel JWT minter with **no auth, single-node file state, and no dependency on `aip-core` or `aip-protocol`** (verified). It does not issue EvidencePackets and cannot enforce the lattice. It is technical debt masquerading as the product. |

**The uncomfortable headline:** ~7,300 LOC of strategic core exists only as
libraries; the 2,057-LOC "service" that would be deployed embodies none of
it. Step one of the company is not "build more" — it is **make the product
the core.**

---

## TASK 2 — Migration matrix: Identity → Authority → Accountability

The three-layer model already maps onto existing code. Mapping honestly:

| Layer | Existing component | Current capability | Future role | Gap |
|---|---|---|---|---|
| **Identity** | `aip-core` identity, `aip-crypto` AIP-ID | Create/validate agent identity; provenance-commitment binding; lifecycle state machine | Layer-1 identity issuance | Provenance is a *caller-supplied hash*, not verified model attestation. Real attestation is a gap. |
| **Identity** | `aip-core::revocation`, service revocation | Cascade revocation, O(1) lookup | Revocation across all layers | Two divergent implementations (core vs service); must unify on one. |
| **Authority** | `aip-core::capability` (scope MEET, subset) | Lattice scope intersection/attenuation | Layer-2 authority algebra | Solid. Custom-scope namespace governance is thin. |
| **Authority** | `aip-core::delegation` | N-hop signed delegation, depth limit, chain verify | Layer-2 delegation chains | Solid in library; **not exposed by the service**. |
| **Authority** | `aip-protocol::accountability_graph` | Per-packet Human→…→Receipt graph + connectivity check | Layer-2 authority graph (per-action) | **Not persistent or queryable across packets** — see Task 4. |
| **Accountability** | `aip-protocol::evidence_packet` | EvidencePacket v1: identity+authority+decision+actions+receipt, signed, tamper-evident | Layer-3 core artifact | Missing explicit **Resource**, **ModelInfo**, structured **ToolCalls** — see Task 3. |
| **Accountability** | `aip-protocol::verification` | 14-rule engine, derived trust floor, tamper classification | Layer-3 verification | Strong. Needs a stable, versioned report schema for regulators. |
| **Accountability** | `aip-core::scoped_audit` | Hash-chained, scope-bound audit entries | Layer-3 persistent audit | Not yet wired to EvidencePacket emission or to a store. |

**Conclusion:** Identity and Authority are **largely built**. Accountability
is **built at the artifact level** but **not persisted, not queryable, and
not emitted by any running service.** The migration is mostly *integration
and exposure*, not greenfield invention. That is good news — and it means the
roadmap is about wiring, hardening, and storage, not research.

---

## TASK 3 — Accountability Layer: EvidencePacket v2 design

EvidencePacket **v1 exists** (`aip-protocol/src/evidence_packet.rs`). The
brief's required field list reveals three genuine gaps: **Resource**,
**Model Information**, and structured **Tool Calls**. Below is the v2 delta —
additive, version-gated, backward-compatible with v1 canonical encoding by
bumping `version` to 2 and appending new length-prefixed fields.

```rust
// NEW in v2 — explicit resource the action targeted.
pub struct ResourceRef {
    /// Stable resource type, reverse-DNS, e.g. "ledger.payment", "isr.track".
    pub resource_type: String,
    /// Opaque resource identifier within that type.
    pub resource_id: String,
    /// Optional tenancy / domain qualifier (org, mission, security domain).
    pub domain: Option<String>,
    /// SHA-256 of the resource's pre-action state, when captured (for diffing).
    pub prior_state_hash: Option<[u8; 32]>,
}

// NEW in v2 — human-readable model provenance ALONGSIDE the existing
// cryptographic provenance commitment in AgentIdentitySummary.
// (The commitment proves "this exact build"; this describes it for auditors.)
pub struct ModelInfo {
    pub family: String,          // e.g. "claude", "internal-llm"
    pub version: String,         // e.g. "opus-4.8"
    pub provider: String,        // e.g. "anthropic", "on-prem"
    /// MUST equal agent.provenance.model_commitment — verifier cross-checks.
    pub model_commitment: [u8; 32],
    pub params: Vec<(String, String)>, // temperature, system-prompt hash, etc.
}

// NEW in v2 — structured tool/function calls the agent made, each bound to
// the decision and individually hashable. Replaces ad-hoc free-text actions
// for tool-using agents (ActionAttestation is retained for non-tool actions).
pub struct ToolCall {
    pub tool_name: String,                 // e.g. "mcp:filesystem.write"
    pub call_id: [u8; 16],
    pub arguments_hash: [u8; 32],          // SHA-256 of canonical arguments
    pub result_hash: Option<[u8; 32]>,     // SHA-256 of tool result, if any
    pub invoked_at: u64,
    pub resource: Option<ResourceRef>,     // what the tool touched
}

// NEW in v2 — pointer to the verification that was performed, so a stored
// packet carries a breadcrumb to its (separately stored) VerificationReport.
pub struct VerificationMetadata {
    pub spec_version: String,              // AIP_SPEC version verified against
    pub verified_by: Option<String>,       // verifier identity, if attested
    pub report_hash: Option<[u8; 32]>,     // SHA-256 of the VerificationReport
    pub verified_at: Option<u64>,
}

// EvidencePacket v2 = v1 fields (unchanged) + the following, appended to the
// canonical byte stream in this order so v1 readers reject v2 by version.
pub struct EvidencePacketV2Additions {
    pub resource: Option<ResourceRef>,         // the primary resource acted on
    pub model_info: Option<ModelInfo>,         // human-readable provenance
    pub tool_calls: Vec<ToolCall>,             // structured tool invocations
    pub verification_metadata: Option<VerificationMetadata>,
    pub decision_hash: [u8; 32],               // single canonical hash over
                                               // (input_hash ‖ rationale_hash ‖
                                               //  resource ‖ tool_calls)
}
```

**Field-coverage check against the brief's required list:**

| Required field | v1 | v2 |
|---|---|---|
| Human Principal | ✅ `root_authority.principal_id`/`display_role` | ✅ |
| Root Authority | ✅ `root_authority.root_token` | ✅ |
| Agent ID | ✅ `agent.aip_id` | ✅ |
| Delegation Chain | ✅ `delegation_chain` | ✅ |
| Action | ✅ `actions[]` | ✅ + `tool_calls[]` |
| Resource | ❌ | ✅ `ResourceRef` |
| Timestamp | ✅ `created_at`/`decided_at`/`performed_at` | ✅ |
| Model Information | ⚠️ commitment only | ✅ `ModelInfo` |
| Tool Calls | ⚠️ generic actions | ✅ `ToolCall` |
| Decision Hash | ⚠️ split input/rationale | ✅ single `decision_hash` |
| Signature | ✅ `agent_sig` + per-action | ✅ |
| Verification Metadata | ⚠️ `claimed_trust_floor` only | ✅ `VerificationMetadata` |

**Effort:** ~1 engineer-week for the structs + canonical encoding + version
gate + verifier rules (ModelInfo↔commitment cross-check, tool-call scope
check). Additive; v1 packets remain verifiable.

---

## TASK 4 — Authority Graph (the genuine new design)

`accountability_graph.rs` builds a graph **per packet** and checks
connectivity. What does **not** exist — and is the real Layer-2 gap — is a
**persistent, queryable Authority Graph across many packets and tokens**,
able to answer "show every action ever taken under authority delegated from
Commander X" or "what is the live blast radius if we revoke token Y."

### Structures

```rust
/// Node identity in the persistent authority graph.
pub enum AuthorityNodeId {
    Principal(String),          // human/org AIP-ID
    Token([u8; 16]),            // scoped root token JTI
    Delegation([u8; 16]),       // delegation JTI
    Agent(String),              // agent AIP-ID
    Action([u8; 16]),           // action_id from an EvidencePacket
    Packet([u8; 16]),           // packet_id
}

pub struct AuthorityNode {
    pub id: AuthorityNodeId,
    pub created_at: u64,
    pub revoked_at: Option<u64>,         // for tokens/delegations
    pub scope_digest: Option<[u8; 32]>,  // effective scope hash at this node
    pub label: String,
}

pub enum AuthorityEdge {
    Issues   { from: AuthorityNodeId, to: AuthorityNodeId },  // principal→token
    Delegates{ from: AuthorityNodeId, to: AuthorityNodeId, depth: u8 },
    ActsUnder{ agent: String, token_or_delegation: AuthorityNodeId },
    Performed{ agent: String, action: [u8; 16], packet: [u8; 16] },
}

pub struct AuthorityGraph {
    nodes: HashMap<AuthorityNodeId, AuthorityNode>,
    out_edges: HashMap<AuthorityNodeId, Vec<AuthorityEdge>>,
    in_edges: HashMap<AuthorityNodeId, Vec<AuthorityEdge>>,
}
```

### Storage design

- **Source of truth = the append-only EvidencePacket + delegation/revocation
  logs.** The graph is a **derived, rebuildable index**, never the
  authority of record. This is critical: the cryptographic artifacts remain
  canonical; the graph is a cache for queries.
- **v1 storage:** embedded KV (e.g. `redb`/RocksDB) keyed by node id, with
  secondary indexes `principal → [token]`, `token → [delegation]`,
  `agent → [action]`. Rebuildable by replaying the logs.
- **Scale path:** a graph store (Neo4j/Memgraph) or a relational adjacency
  schema behind the same trait. Define an `AuthorityGraphStore` trait now so
  the backend is swappable; do **not** marry a database in v1.
- **Multi-tenant:** every node carries a tenant/domain key; queries are
  tenant-scoped by construction.

### Verification logic

The graph is an index, so it MUST NOT be trusted blind. Query results are
**re-verified against the underlying signed artifacts** before being
presented as evidence:

1. `who_authorized(action_id)` → walk `Performed`→`ActsUnder`→`Delegates*`→
   `Issues` to the principal; then **re-run `verify_packet`** on the packet
   and **re-verify each delegation hop** before returning. The graph
   accelerates the lookup; cryptography confirms it.
2. `revocation_blast_radius(token_jti)` → BFS the `Delegates` subtree
   (reusing the existing cascade logic) to list every downstream delegation
   and every action performed under them.
3. `authority_path(action_id)` → returns the chain + a freshly computed
   `VerificationReport`, suitable for an audit export.

**Effort:** ~3–4 engineer-weeks for the trait, embedded-KV backend, replay
builder, and the three verified queries. This is the highest-leverage net-new
build because it turns a pile of packets into an **auditable system of
record**.

---

## TASK 5 — Enterprise integration architecture (design only)

AIP should be an **evidence sink and an authority source**, not yet another
agent platform. Two integration planes:

```
            ┌──────────────────────── PRODUCERS ───────────────────────┐
 MCP middleware   LangGraph cb   OpenAI Agents   Claude SDK   CrewAI
        │             │              │              │            │
        └──── emit signed EvidencePackets via a thin AIP SDK ────┘
                                   │
                          ┌────────▼─────────┐
                          │  AIP Ingest API  │  (authn, tenant, schema)
                          └────────┬─────────┘
                    ┌──────────────┼───────────────┐
            verify_packet   AuthorityGraph index   Evidence store (append-only)
                    └──────────────┼───────────────┘
            ┌──────────────────────── CONSUMERS ───────────────────────┐
 OpenTelemetry   Datadog   Splunk   CloudTrail correlation   Regulator export
```

**Design principles:**

1. **Adapters, not couplings.** Each producer has a small adapter that
   converts native traces/tool-calls into EvidencePacket fields. The agent's
   key signs; AIP never holds agent private keys.
2. **OpenTelemetry is the carrier, not the trust.** Map `trace_id`/spans into
   `TraceBinding`; AIP adds the cryptographic layer OTel lacks. Datadog/Splunk
   ingest the *VerificationReport* as enrichment, not as the source of truth.
3. **CloudTrail/SIEM = correlation, not authority.** Cross-reference cloud
   events to packets by resource + timestamp; flag actions with no
   corresponding EvidencePacket ("unaccounted autonomy").
4. **MCP first.** An MCP middleware that auto-emits a packet per tool call is
   the highest-leverage integration: it sits exactly where authority meets
   action, and the ecosystem has no native accountability story.
5. **Pull, don't push, for regulators.** A read API that produces signed
   evidence bundles on demand; never stream raw evidence outward.

No implementation here, per the brief. Sequencing in Task 6.

---

## TASK 6 — Phased roadmap

> Effort assumes a small team; "wk" = engineer-weeks. Risk is delivery risk.

### Phase 1 — Identity Infrastructure (consolidation)
- **Code changes:** unify the **two** revocation/delegation implementations
  (core vs service) onto `aip-core`. Delete the service's parallel logic.
- **New crates:** none.
- **Refactors:** make `aip-service` depend on `aip-core`.
- **Effort:** 2–3 wk. **Risk:** Low. **Why first:** stops the divergence
  bleeding before building on top.

### Phase 2 — Authority Infrastructure (expose + persist)
- **Code changes:** expose `aip-core` delegation/scope through the service;
  build the **persistent Authority Graph** (Task 4).
- **New crates:** `aip-authority-graph`.
- **Refactors:** service endpoints issue scoped/delegated tokens via core.
- **Effort:** 4–6 wk. **Risk:** Medium (storage choice, query verification).

### Phase 3 — Accountability Infrastructure (make the product the core)
- **Code changes:** EvidencePacket **v2** (Task 3); a **hardened, authenticated
  ingest+verify service** that *replaces* today's `aip-service` and actually
  emits/verifies packets; wire `scoped_audit` to emission.
- **New crates:** `aip-evidence-service`.
- **Refactors:** retire the legacy JWT service.
- **Effort:** 6–8 wk. **Risk:** Medium-High (this is the real product;
  security must be right — authn, tenant isolation, KMS).

### Phase 4 — Evidence Vault (the thing customers buy)
- **Code changes:** durable append-only evidence store; search by
  principal/agent/resource/decision; retention; signed **regulatory export
  bundles**; transparency-log anchoring of packet hashes.
- **New crates:** `aip-vault`.
- **Effort:** 8–12 wk. **Risk:** Medium. **Why it matters:** first revenue
  surface; first switching cost (accumulated, anchored history).

### Phase 5 — Industry Standard
- **Code changes:** freeze `AIP_SPEC` v1.0; cross-language **conformance test
  vectors**; reference verifiers (WASM, TS, Python); submit to a neutral body.
- **New crates:** `aip-conformance`.
- **Effort:** ongoing. **Risk:** High (adoption, not engineering). **Payoff:**
  the only durable moat (below).

---

## TASK 7 — Founder-level assessment (brutal)

**1. Single most valuable component.**
`aip-protocol::scoped_audit`/`evidence_packet` + the verification engine —
tamper-evident, offline-verifiable, authority-bound action evidence. Nothing
else here is both novel and saleable. It is ~5% of the LOC and ~90% of the
enterprise value.

**2. What should be deleted.**
The current `aip-service` (parallel, unauthenticated, doesn't touch the
core). Also: stop maintaining the reputation, hardware-attestation (string-
matching stub), and liveness modules as if they were product — they are
research and already flagged EXPERIMENTAL. Delete the AIRON/AEGIS narrative
entirely from anything customer-facing.

**3. What should be rewritten.**
The service, as `aip-evidence-service`, built **on** `aip-core` +
`aip-protocol`, with authentication, tenant isolation, and KMS-backed keys.
This is the difference between a demo and a company.

**4. The moat.**
Not the code (3–5 engineers replicate the core in a quarter). The moat is
**(a)** an **open, adopted EvidencePacket standard** that other tools verify,
plus **(b)** an **Evidence Vault holding anchored, immutable history** that
cannot be retroactively reconstructed elsewhere. Format ubiquity + accumulated
witnessed evidence. Everything in the roadmap serves these two.

**5. Network effects.**
Cross-party verification: when Org A's agent transacts with Org B's, a shared
evidence format is worth more than either's private one — every integration
recruits the counterparty. And **auditor-side adoption**: once auditors/
regulators *ask for* AIP-format evidence, every audited entity must produce
it. That is the deepest, least-contested effect; pursue it deliberately.

**6. Enterprise lock-in.**
Years of anchored evidence whose hash chain breaks if migrated; AIP-format
evidence written into audit procedures and vendor contracts; SDKs embedded in
every agent workflow. Lock-in compounds in *evidence* in a way it never does
in software — you can re-platform code, you cannot re-witness history.

**7. To become category-defining.**
Three moves, in order: **(i)** make the product the core (kill the parallel
service); **(ii)** ship the MCP/framework SDK that auto-emits packets, to win
developers; **(iii)** land one regulated design partner whose **auditor
accepts an AIP evidence bundle**. That third event converts the category from
vitamin to painkiller and starts the standards flywheel.

---

## Bottom line for the board

The repository already contains a tested Identity layer, a tested Authority
layer, and — contrary to the brief — a tested Accountability **artifact**.
The company is **not** blocked on invention. It is blocked on three things,
all executional:

1. **The product is not the core.** The deployable service ignores the
   valuable crates. Fix this before anything else.
2. **Evidence is not yet persisted or queryable.** The Authority Graph and
   Evidence Vault turn a pile of packets into a system of record — that is
   what an enterprise actually buys.
3. **There is no distribution and no design partner.** The moat is a standard
   plus accumulated evidence; neither exists until developers emit packets and
   one auditor accepts a bundle.

Spend the next two quarters making the product the core, persisting evidence,
and getting one regulated auditor to say "we accept this." That is the whole
game. The cryptography is done; the company is not.
