# AIBOM — Architecture, Invariants and Plan

**Baseline** `65eb9e6` (ported from `3e51fae`) · **Crate** `aip-standalone/aip-aibom` · **Binary** `aibom`
**Decision record** ADR-017
**Written before implementation**, as the governing discipline requires.

---

## 1. What the product is

An evidence-gap assessor for AI agents. It reads an agent's declared inventory
(the AIBOM manifest), the evidence the deployment can produce, and the
assessor's own trust context, and reports **per field, who says so**.

It is not an inventory dashboard. Inventory is a commodity; the hyperscalers
will ship it free. The finding nobody else produces is the gap between what an
agent's manifest claims and what any independent mechanism can establish.

## 2. Thirteen components

The twelve in common use plus the one they all omit.

| # | component | what can raise it above `SelfReported` |
|---|---|---|
| C1 | Agent identity | `validate_aid` over a carried `AgentIdentityDocument` |
| C2 | Model inventory | **nothing** — hosted: `Unknowable(N-3)`; weights loaded: `Unknowable(N-4)` |
| C3 | Framework dependencies | nothing in M1 (lockfile discovery is M2) |
| C4 | Tool inventory | the assessor's own discovery run (MCP client config); a gateway-countersigned receipt (`aip_airi::verify_tool_receipt`) |
| C5 | Permissions | `verify_delegation_chain` + `CapabilityScope::contains`; window and revocation from the assessor. Approval gates: approvals *counted* through `aip_approval::{verify_artifact, compare_shown_to_authorized}`, the gate itself never raised |
| C6 | Data access | the signed access ledger (`aip_ledger::AccessLedger::verify`): the resource was reached, as the institution's registry names it. Access mode: nothing |
| C7 | Execution environment | `verify_expected_execution` (authorised binary); `verify_nexora_proof` (observed binary, at NEXORA's strength) |
| C8 | Agent relationships | holders named in a verified delegation chain; `validate_aid_with_parent` |
| C9 | Security controls | nothing — and every one claimed is a finding |
| C10 | Cryptographic posture | identity-key algorithm from a validated identity; PQ claims `Unknowable(N-10)` |
| C11 | Supply-chain provenance | nothing beyond the agent binary in C7 |
| C12 | Governance metadata | nothing (metadata, not a control) |
| **C13** | **Validity and revocation** | the manifest's own window; each authority's window from its signed tokens; revocations from the assessor |

## 3. Standing — the output vocabulary

| standing | meaning | produced by |
|---|---|---|
| `Verified{verifier}` | a core verifier accepted a cited artifact and it supports the field | `aip-core`, `aip-authorize` |
| `Observed{strength}` | NEXORA accepted a proof whose re-derived identity matches, at NEXORA's strength | `aip-nexora` |
| `Verified{ToolGateway}` | the institution's gateway, not the agent, signed that it received and forwarded a call for this tool | `aip-airi` |
| `Verified{AccessLedger}` | a signed ledger over attested observation records the agent reaching this resource | `aip-ledger` |
| `Discovered{source}` | found by a discovery the assessor itself ran | `adapters::mcp_config` |
| `SelfReported` | the manifest author's word | default |
| `Unknowable{N-x}` | no mechanism can establish it | field type |
| `Lapsed{why}` | authority verified, and expired or revoked at the assessor's present | C5, C13 |
| `Contradicted{reason}` | evidence verified **and** disagrees with the declaration | C1, C5, C7, C8, C10 |
| `EvidenceRejected{reason}` | cited evidence failed its core verifier | any |

**Precedence when several artifacts bear on one field**, fail-closed at the
top: `EvidenceRejected` > `Contradicted` > `Observed` > `Verified` > `Lapsed` >
`Discovered` > `SelfReported`. A bad artifact is never outvoted by a good one.
`Lapsed` ranks below `Verified` because two grants are two facts, not two
accounts of one fact: an expired grant beside a live one is no evidence
against the live one.

**Absence is never contradiction.** `Contradicted` requires verified evidence
that positively disagrees — a scope that explicitly denies a declared action, a
decision point that authorised a different binary. A declared permission no
offered chain grants is `SelfReported`, with a finding; the bundle may simply
not contain the grant.

There is no `Assumed`, `Trusted`, `Compliant` or `Mitigated`.

## 4. Hexagonal layout

```
aip-aibom/src/
  lib.rs                  crate contract, version constants, re-exports
  model/                  CORE · pure data, the manifest (input)
    mod.rs                Manifest, validation entry point
    identity.rs           C1
    inventory.rs          C2 C3 C4 C6 C7
    authority.rs          C5 C8 C13, Amount
    controls.rs           C9 C10 C11 C12
    limits.rs             bounds as named constants
  canonical.rs            CORE · injective, domain-tagged, order-independent encoding
  standing.rs             CORE · output vocabulary (Serialize only)
  evidence.rs             CORE · EvidenceBundle (untrusted) and AssessorContext (trusted)
  assess/                 CORE · pure functions, one per component group
    mod.rs                assess(manifest, bundle, ctx, discoveries) -> Assessment
    identity.rs  authority.rs  execution.rs  inventory.rs  controls.rs
    tools.rs      C4: discovery and gateway receipts
    approvals.rs  C5 gates: the approval tier
    access.rs     C6: the signed access ledger
  finding.rs              CORE · findings and their fixed priority mapping
  diff.rs                 CORE · change detection between two manifests
  seal.rs                 CORE · detached authorship seal
  report.rs               INTERFACE · deterministic JSON / CSV / text
  ports.rs                PORT · DiscoverySource
  adapters/mcp_config.rs  ADAPTER · IO at the edge, pure parser inside
  bin/aibom.rs            INTERFACE · CLI, no logic of its own
```

No module under CORE reads a file, a clock, an environment variable or the
network. Time enters as `AssessorContext::present_time_ms`. The adapter reads
one file, bounded in size, and hands bytes to a pure parser.

## 5. Invariant matrix

| id | invariant | enforced by |
|---|---|---|
| A1 | the manifest cannot express a standing | type: no field; `deny_unknown_fields`; test |
| A2 | no standing above `SelfReported` without a core verifier accepting an artifact | assess with empty bundle yields none; test |
| A3 | trust inputs come only from `AssessorContext` | type: `EvidenceBundle` has no key, anchor, revocation or clock field |
| A4 | `Observed` strength is NEXORA's, never raised | read from `VerifiedProof::strength`; test |
| A5 | a rejected artifact is never outvoted | precedence; test |
| A6 | the assessor never reconciles | structural test: no `reconcile_` call in `src/` |
| A7 | the crate defines no verdict, ceiling, strength or observation class | structural test |
| A8 | `Assessment` cannot be deserialised | type; compile-fail is not available, so a structural test |
| A9 | the canonical digest is order-independent over sets and injective over fields | test |
| A10 | the seal never changes a field's standing | test |
| A11 | discovery never stores a secret value | type: no value field; serialised-output test |
| A12 | assessment is deterministic | test: twice, byte-identical |
| A13 | amounts are integers with explicit currency and exponent | type: `u64` + validation |
| A14 | nothing in the workspace depends on `aip-aibom` | structural test |
| A15 | a gateway, approval surface or observer anchored under the agent's own key is refused | the producing crates' verifiers, given `AssessorContext::agent_public_key`; tests |
| A16 | an approval gate is never raised above `SelfReported` | no amount is carried by any expectation; test |

## 6. Plan

1. Model and validation, canonical encoding, digest.
2. Evidence and context types; standing vocabulary.
3. Assessment engine, one module per component group.
4. Findings with a fixed priority mapping.
5. Seal.
6. MCP config discovery.
7. Diff.
8. Report rendering and CLI.
9. Worked treasury example — the honest version of the $1,000 / $5,000 story.
10. Structural guards; full workspace validation; evidence report.

## 7. Ported onto `65eb9e6`

The crate was first built on `3e51fae`, 85 commits behind the integration
line. On the newer line three components could be raised by verifiers that
did not exist on the old base, and the old build reported them as never
verifiable — claims that were false on the newer code. The port consumes
them: gateway receipts (C4), the approval tier (C5 gates), the signed access
ledger (C6). The hybrid ML-DSA path does not change C10: it signs evidence
artefacts, and production has no hybrid verifier for identity documents.

## 8. Out of scope for M1, stated

- Lockfile discovery (C3, C11). M2.
- Framework-specific discovery (LangChain, CrewAI, AutoGen code scanning). M2.
- CycloneDX export. M2 — after the internal schema stabilises, so the mapping is
  to a fixed target rather than a moving one.
- Private-key handling in the CLI. Sealing is a library API in M1; key custody
  through a CLI is a security surface that deserves its own review (cf. B-6).
- Any runtime observation. That is NEXORA's input, not the assessor's.
