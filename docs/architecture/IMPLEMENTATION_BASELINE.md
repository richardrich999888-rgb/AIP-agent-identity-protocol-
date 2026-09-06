# IMPLEMENTATION BASELINE

Recorded before any production code change under Skill 3
(`syntriass-aip-correctness`). This file is a snapshot, not a status page;
later progress is recorded in `AIP_CORRECTNESS_REPORT.md`.

## Commit

- Baseline production HEAD: `1d1a984` (last commit touching only
  `.claude/skills/`; production code last changed at `377d5fc` and earlier).
- Invariant normalization `45e5702` verified present as an ancestor of HEAD.
- Working tree clean at the time of the baseline test run.

## Branch

`claude/codebase-production-readiness-wm6idp`

## Workspace state

Two independent Cargo workspaces:

| Workspace | Crates | Version |
|---|---|---|
| `aip-standalone/` | aip-types, aip-crypto, aip-core, aip-protocol, aip-cli, aip-verify, aip-test, aip-real-tests, banking_demo | 0.4.0 |
| `aip-service/` | aip-service (axum HTTP service) | 0.2.0 |

Dependency direction relevant to this phase:

```
aip-types  <-  aip-crypto  <-  aip-core  <-  aip-protocol
```

`aip-protocol/src/canonical.rs` (the injective length-prefixed encoder) is
`pub(crate)` and lives *downstream* of `aip-core`. `aip-core` therefore cannot
reuse it without either relocating the helpers upstream or duplicating them.
This is a constraint on the Phase 1 fix, recorded here so the choice is
explicit later.

## Test baseline (`cargo test --workspace` in `aip-standalone/`)

| Target | Passed | Failed | Ignored |
|---|---|---|---|
| aip-core (unit) | 109 | 0 | 0 |
| aip-crypto (unit) | 7 | 0 | 0 |
| aip-protocol (unit) | 4 | 0 | 0 |
| aip-protocol tests/bundle.rs | 6 | 0 | 1 |
| aip-protocol tests/evidence_packet.rs | 17 | 0 | 0 |
| aip-real-tests | 67 | 0 | 2 |
| aip-test | 13 | 0 | 0 |
| aip-cli / aip-verify / aip-types / banking_demo | 0 | 0 | 0 |
| **Total** | **223** | **0** | **3** |

`aip-service` workspace: not part of this baseline run; it is exercised in
Phase 1 only where §16/§17 of Skill 3 require inspection.

## Known failures

None. The suite is green. Note that "green" here includes the defect below:
no existing test mutates `expires_at` on a validly signed token, so the
vulnerability is invisible to the baseline suite.

## Relevant crates and code paths (verified against source, not the audit)

| Concern | Location | Observed behaviour |
|---|---|---|
| ScopedToken signing payload | `aip-core/src/capability.rs` `canonical_token_payload` | raw concat of `jti ‖ issuer_id ‖ agent_id ‖ allowed ‖ 0xFF ‖ denied ‖ issued_at`; **`expires_at` absent**; no length prefixes; no domain tag |
| ScopedToken verification | `aip-core/src/capability.rs` `verify_scoped_token` | recomputes payload, compares `payload_hash`, then `verify_ed25519`; never reads `expires_at` |
| DelegationToken signing payload | `aip-core/src/delegation.rs` `canonical_delegation_payload` | raw concat; **`expires_at` absent**; no length prefixes; no domain tag |
| Delegation chain verification | `aip-core/src/delegation.rs` `verify_delegation_chain` | checks parent_jti, depth, scope subset, signature; never reads `expires_at`, never checks child ≤ parent expiry |
| `Custom(s)` scope action encoding | both files, `encode_scope_action` | `0x01 ‖ s ‖ 0x00` — NUL-terminated, not length-prefixed |
| Packet canonical bytes | `aip-protocol/src/evidence_packet.rs` | includes `expires_at` via `put_opt_u64` (packet-hash covered, issuer-sig NOT covered) |
| Temporal rule R10 | `aip-protocol/src/verification.rs` `check_temporal_validity` | reads `expires_at` from the packet's *unsigned-by-issuer* field |
| Signature preimage | `aip-crypto/src/lib.rs` `sign_ed25519` | `SHA-256(0x01 ‖ signer_id ‖ ts ‖ nonce ‖ sha256(payload))`; no domain tag |
| Correct Option encoding already in tree | `aip-core/src/lib.rs` `canonical_encode_capability_grant` | `expires_at` encoded with presence tag — the pattern to reuse |
| Length-prefixed encoder | `aip-protocol/src/canonical.rs` | `put_str`, `put_opt_u64`, `encode_scope`, … all `pub(crate)` |
| `PACKET_VERSION` | `aip-protocol/src/evidence_packet.rs` | `1` |
| `validate_aip_id` | `aip-crypto/src/lib.rs` | byte-index slicing; non-ASCII input can panic |
| `KeyPair` | `aip-types/src/lib.rs` | derives `Debug, Serialize`; private key printable/serializable |

## Intended phase

Skill 3 / Stage 0 — AIP authority correctness only.

Explicitly out of scope for this phase: ExecutionBinding, Decision Point,
Observer, Reconciliation, Warrant, Containment, NEXORA, PQC, eBPF/XDP.
