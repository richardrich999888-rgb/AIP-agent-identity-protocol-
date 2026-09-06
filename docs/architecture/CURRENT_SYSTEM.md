# CURRENT_SYSTEM — what the AIP repository actually implements

**Discovery run:** `ghost-architecture-engineer`
**Commit:** `377d5fc874f21b5ce046dc9879a912bdbf6c4a3c`
**Branch:** `claude/codebase-production-readiness-wm6idp` · working tree clean
**Method:** source, tests and build artifacts only. Documentation, patents,
diagrams, branch names and other skills were treated as claims, not evidence.

> **Status (PR3).** This is the discovery baseline and is kept verbatim.
> Statements such as "NO DECISION POINT EXISTS" describe `377d5fc`; the
> current state per stage is in `AIP_CORRECTNESS_REPORT.md`,
> `EXECUTION_BINDING_IMPLEMENTATION_REPORT.md`,
> `DECISION_POINT_IMPLEMENTATION_REPORT.md`, `OBSERVER_IMPLEMENTATION_REPORT.md`,
> `SNIFFER_DOG_IMPLEMENTATION_REPORT.md` and `PR3_GAP_REVIEW.md`. §6 remains
> true of `aip-service` (the generate endpoint is still a signing oracle);
> a library decision point now exists in `aip-authorize`.

---

## 1. Production surface

"Production" = reachable from `HEAD`. Two Cargo workspaces:

| Crate | LOC | Role | Classification |
|---|---:|---|---|
| `aip-types` | 619 | wire structs, error enum, no crypto, **0 tests** | IMPLEMENTED / VERIFIED |
| `aip-crypto` | 309 | Ed25519, SHA-256, Base58 AIP-ID, Merkle *helpers* | IMPLEMENTED / VERIFIED |
| `aip-core` | 5,179 | delegation, capability, revocation, nonce, scoped_audit, runtime, store, wellknown, simulation | MIXED — see §4 |
| `aip-protocol` | 2,395 | canonical encoder, EvidencePacket, 14-rule verifier, accountability graph, bundle | IMPLEMENTED / VERIFIED |
| `aip-cli` | 335 | 6 subcommands, **0 tests** | IMPLEMENTED / UNVERIFIED |
| `aip-verify` | 208 | offline verifier binary, **0 tests** | IMPLEMENTED / UNVERIFIED |
| `aip-test`, `aip-real-tests` | 2,150 | test crates | — |
| `banking_demo` | ~400 | bin-only demo, no dependents | DEMO |
| `aip-service` | 4,201 | axum HTTP service | MIXED — see §5 |

Build/test evidence at this commit:
`aip-standalone` — 223 passed, 0 failed, 3 ignored.
`aip-service` — 38 passed default; 41 passed / 1 ignored with `--features postgres`.
`cargo clippy -D warnings` and `cargo fmt --check` clean in both.

## 2. The AIP lifecycle as implemented

```
Agent Identity   aip_crypto::derive_aip_id            aip-crypto/src/lib.rs:49
      ↓          SHA-256(pubkey ‖ provenance)[0..26], base58, +checksum
Key Material     generate_ed25519_keypair (OsRng)     aip-crypto/src/lib.rs:8
      ↓
Authentication   — NOT PRESENT as a distinct step. Identity is self-asserted;
      ↓            possession of the key is the only authentication.
Authority        issue_scoped_token → ScopedToken     aip-core/capability.rs:130
      ↓          signs canonical_token_payload         aip-core/capability.rs:208
Delegation       create_delegation / _sub_delegation   aip-core/delegation.rs:51,103
      ↓          verify_delegation_chain               aip-core/delegation.rs:169
Authorization    — NO DECISION POINT EXISTS. See §6.
      ↓
Action           ActionAttestation::create             aip-protocol/evidence_packet.rs:117
      ↓          signs decision_id ‖ action fields
Evidence         EvidencePacketBuilder::build_and_sign aip-protocol/evidence_packet.rs:455
      ↓          packet_hash = SHA-256(canonical_bytes)
Verification     verify_packet → 14 rules              aip-protocol/verification.rs:92
```

## 3. What is genuinely strong

- **One identity derivation, no duplicates.** Every call site imports
  `aip_crypto::derive_aip_id`. No divergent re-implementation in Rust, TS,
  Python, SQL or shell. Matches `AIP_SPEC.md:34-35` semantically.
- **The packet canonical encoder is injective.** `aip-protocol/src/canonical.rs`
  length-prefixes every variable-length field (`put_bytes:23`), tags every
  `Option`, counts every collection.
- **Verification is pure and offline.** No network, DB or filesystem in
  `verification.rs`; the single clock read (`:319`) feeds only `verified_at`
  and no rule.
- **Trust anchors are external in the CLI.** `aip-verify` sources issuer and
  counterparty keys only from `--trust` / `--counterparty`
  (`aip-verify/src/main.rs:77-78`), never from the artifact. Fail-closed:
  `None => false` at `verification.rs:169`.
- **The trust floor is derived, not asserted.** `verification.rs:266-285`.
- **Adversarial tests model a re-signing insider**, not just naive edits —
  `aip-protocol/tests/evidence_packet.rs:235,276,335,387,411`.

## 4. `aip-core` — implemented but unwired

| Module | State | Evidence |
|---|---|---|
| `scoped_audit.rs` | **IMPLEMENTED / UNWIRED** | `pub struct ScopedAuditLog { pub entries: Vec<_> }` (`:154-156`); no persistence API; **no caller outside its own tests** |
| `runtime.rs` | **PARTIAL / UNWIRED** | computed then only `println!`'d by `aip-cli/src/main.rs:127,137`; never enters evidence |
| `revocation.rs` | **IMPLEMENTED / UNWIRED** | `check_token_valid` / `check_delegation_valid` have zero callers repo-wide |
| `nonce.rs` | **IMPLEMENTED / UNWIRED** | `NonceTracker` not used by `delegation.rs` or `aip-protocol` |
| `simulation.rs` | **IMPLEMENTED / SHIPPED** | declared "not for production" at `lib.rs:11-14`, yet exposed as `aip-cli simulate` (`main.rs:76-80,285`) |
| Merkle roots | **UNUSED** | all three production roots are `merkle_empty()` (`lib.rs:62,63,647`) |

## 5. `aip-service` — two security models in one binary

Evidence path **shares** the audited core:
`derive_aip_id` (`evidence.rs:228`), `verify_packet` (`:329,421`),
`build_zip`/`verify_zip`.

Identity path **duplicates** it with weaker guarantees:

| | `aip-core` | `aip-service` |
|---|---|---|
| Delegation type | `DelegationToken` with `issuer_sig: Signature` (`aip-types:296-306`) | `DelegationToken` with **no signature field** (`delegation.rs:23-40`) |
| Ids | `[u8;16]` | `String` |
| Depth | `u8`, rejects `>= 8` | `u32`, rejects `> 8` — off by one |
| Timestamps | `u64` ms | ISO-8601 `String` |
| Action enum | `Read/Write/Delete/Admin/Execute/Delegate` (`aip-types:224-231`) | `EvaluateContent/SubmitAuditEntry/IssueSubDelegation/ReadAuditLog/RevokeToken/Custom` (`capability.rs:18-25`) |
| Integrity | Ed25519 per hop | unkeyed SHA3-256 over a `format!` string that **omits `scope` and `expires_at`** (`delegation.rs:58-62`) |
| Attenuation at issuance | enforced (`delegation.rs:63-69`) | **not enforced** (`handlers.rs:219-225`) |

Violates invariant **I18**.

## 6. The finding that governs the Ghost programme

**There is no authorization decision point anywhere in production.**

`POST /v1/evidence/generate` → `generate_packet`
(`aip-service/src/evidence.rs:220-300`) is a **signing oracle**, not an
authorizer. The caller supplies, in the request body:

- `agent_seed_hex` — *"32-byte hex seed of the acting agent's Ed25519 key"*
  (`evidence.rs:130`) — **the agent's private key**
- `counterparty_seed_hex` — the counterparty's private key (`:124`)
- `root_token: ScopedToken` — *"already signed by the principal"* (`:136`)
- `delegation_chain` — *"each hop pre-signed"* (`:139`)
- `decision.*` and `actions[]` — free-text summary, input, rationale, payloads

`generate_packet` **verifies none of it**. It does not check the root token
signature, does not verify the delegation chain, does not test the decision's
`action_kind` against the effective scope, and does not confirm the agent is
the chain's leaf grantee. It seals whatever it is told.

`POST /v1/evidence/verify` then accepts caller-supplied trust anchors —
`VerifyRequest.trusted_issuers` (`evidence.rs:161`) inserted into
`ctx.issuer_public_keys` (`:307-309`). The code comment at `:363-365` is
honest that this is "a pure function of the packet and caller-supplied keys".

**Consequence:** a caller can generate a keypair, self-issue a root token,
POST it to `/generate`, then POST the result to `/verify` naming its own public
key as the trusted issuer, and receive `valid: true` at `AUTHORITY_BOUND`.
End to end, the agent is the sole authority for attesting its own execution —
a direct violation of invariant **I1**, and the exact condition the Ghost
architecture exists to break.

This is not a bug in the verifier. `verify_packet` is correct: given a trusted
issuer key it answers a well-posed question. The gap is that **nothing in the
system decides what an agent is allowed to do before it does it**, so there is
no authorized-execution record to reconcile observation against.

## 7. Out-of-tree work (verified by ancestry, not branch name)

| Branch | Merged into HEAD? | Tree present in HEAD? |
|---|---|---|
| `origin/import/orbitaltrust-accountability-layer` (ot-sentinel, NEXORA) | **NO** — ahead 1, behind 5 | `orbitaltrust-accountability/` **ABSENT** |
| `origin/codex/val-ladder-sync` (aegis-quantum eBPF/XDP) | **NO** — ahead 29, behind 22 | `aegis-quantum/` **ABSENT** |
| `origin/codex/aip-v4-accountability` | **NO** — ahead 7, behind 22 | **ABSENT** |

Per invariant **I17**, none of this is production capability. It may be
harvested as design input; it must not be cited as implemented.

## 8. Ghost programme state (added after Stages 0–7c, Skill 8 and the PR #3 harvest)

§1–§7 describe the repository at `377d5fc` and are kept for traceability.
Since then the following are **PRODUCTION in `aip-standalone`** (each with a
report under `docs/architecture/`): corrected AIP authority (Skill 3),
`ExecutionBinding` (Skill 4), `aip-authorize` decision point (Skill 5),
`aip-observe` probe/collector observer with kernel-pushed sources, provenance
gating, loss accounting and restart-continuity audit (Skills 6/6.5, Stages
7b/7c, PR #3 harvest), `aip-reconcile` with `CANNOT_PROVE` default and three
verified action classes (Skill 7, Stages 7–7c, Gate 3), `aip-agent` identity /
profile / lineage / delegation graph (Sniffer Dog 2.0 Phases B–D),
`aip-warrant` (Skill 8), `reconcile_lineage` / `LINEAGE_VIOLATION` (Gate 1
of the completion mandate) and the `AF_PACKET` device-layer tap with wire
corroboration on record v5 (Gate 2; `OBSERVATION_MODEL.md` §5). Still
**MISSING**: containment (Skill 9), NEXORA
(Skill 10), signed reconciliation records, experience ledger, profile API,
`aip-service` integration of any of the above (the service still carries its
own authority model, §5). The out-of-tree inventory in §7 is superseded by
`OUT_OF_TREE_HARVEST_REVIEW.md` and `OT_SENTINEL_HARVEST_AUDIT.md`.
