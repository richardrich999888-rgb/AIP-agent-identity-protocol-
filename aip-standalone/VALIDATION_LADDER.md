# AIP Validation Ladder

This ladder converts the Agent Identity Protocol from a collection of Rust crates
and service handlers into a repeatable evidence trail for technical review,
RDI/TDB diligence, and release gates.

## Current Validation State

| Layer | Gate | Evidence | Status |
| --- | --- | --- | --- |
| L0 | Repository hygiene | `cargo check` for `aip-standalone` workspace and `aip-service` | PASS |
| L1 | Cryptographic identity | Ed25519 key generation, AIP-ID derivation, sign/verify, tamper rejection | PASS |
| L2 | Provenance and replay controls | Provenance-bound identity, runtime binding, nonce freshness, stale/future replay rejection | PASS |
| L3 | Delegation lattice | Scope MEET, child cannot exceed parent, chain depth enforcement, audit hash binding | PASS |
| L4 | EvidencePacket discipline | Session/decision binding, evidence graph validation, overclaim rejection, policy floor checks | PASS |
| L5 | Terminal non-repudiation verifier | `airon-verify` rejects toxic packets if assembler, agent, trace, receipt, counterparty, or external digest checks fail | PASS |
| L6 | Adversarial/property/stress | Forgery, key substitution, lineage forgery, sybil, replay, 10K sign/verify, 100K nonce tracking | PASS |
| L7 | Service contract | JWT issue/verify, JWKS discovery, delegation, cascade revocation, mean verify latency guard | PASS |
| L8 | CI evidence pack | GitHub Actions report artifact from `.github/workflows/aip-validation.yml` | READY |

## Reproducible Commands

From the repository root:

```bash
make aip-ci-local
```

This executes:

```bash
cargo check --manifest-path aip-standalone/Cargo.toml --workspace
cargo check --manifest-path aip-service/Cargo.toml
cargo test --manifest-path aip-standalone/Cargo.toml --workspace
cargo test --manifest-path aip-service/Cargo.toml
python3 scripts/generate_aip_validation_report.py --output aip_validation_report.json
```

Current local baseline:

| Surface | Tests | Result |
| --- | ---: | --- |
| `aip-standalone` protocol workspace | 232 | PASS |
| `aip-service` Axum service | 22 | PASS |
| **Total AIP tests** | **254** | **PASS** |

## Test Coverage Map

| Area | What Is Verified |
| --- | --- |
| Cryptographic identity | Ed25519 signing, verification, tamper rejection, cross-key rejection, malformed key rejection |
| AIP-ID provenance | Deterministic IDs, uniqueness across keys, rejection when public key/provenance no longer binds to ID |
| Lifecycle state machine | Pending, active, suspended, revoked, terminal revocation behavior |
| Capability lattice | Scope subset checks, denied-scope precedence, MEET commutativity/idempotence, constrained delegation |
| Delegation chains | Parent token validation, chain depth limit, child scope cannot exceed parent scope |
| Revocation | Single-token revocation, cascade revocation, persisted revocation log integrity |
| Evidence packets | Session ID binding, decision ID binding, signed receipts, trace roundtrip, graph validation |
| Terminal verification | `airon-verify` verifies assembler authority, agent decision/action signatures, counterparty signatures, trace authority, receipt authority, and external receipt digest |
| Adversarial resistance | Signature forgery, key substitution, lineage forgery, liveness impersonation, sybil duplicate key, replay |
| Stress/property checks | 10K sign/verify, 100K nonce tracking, 1K identity creation, 1MB payload signing, score bounds |
| Service behavior | JWT issue/verify, token expiry, wrong algorithm/key rejection, JWKS x-coordinate validity, verify latency |

## Cryptography Bill of Materials

| Component | Primitive | Implementation Detail |
| --- | --- | --- |
| Agent identity signatures | Ed25519 / EdDSA | Rust-native `aip-crypto`; service tokens use EdDSA JWT verification |
| Provenance fingerprints | SHA-256 | AIP-ID derivation binds public key and provenance triple |
| Delegation/revocation logs | SHA3-256 | Append-only entry hashes for audit-grade chain evidence |
| Replay protection | CSPRNG nonce + timestamp window | Signer-scoped nonce tracking with eviction and stale/future rejection |
| Algorithm agility | ML-DSA-ready verifier interface | Non-Ed25519 algorithms require explicit external verifier before acceptance |

## CI Artifact

The AIP workflow produces `aip-validation-report` containing
`aip_validation_report.json`. The report is generated from the current Rust test
graph after checks and tests pass, so the submitted artifact reflects the code
under review rather than a stale benchmark snapshot.

The terminal verifier is invoked as:

```bash
cargo run --manifest-path aip-standalone/Cargo.toml --package airon-verify -- \
  --packet evidence_packet.json \
  --keyring verification_keyring.json \
  --receipt-digest-hex <external-receipt-sha256> \
  --report airon_verify_report.json
```

The keyring JSON contains `assembler`, `agent`, `trace_authority`,
`receipt_authority`, and optional `counterparties` keyed by tool reference. The
command exits `0` only for `PASS`; toxic packets exit non-zero and include the
failed check names in the report.

## Next Validation Milestones

| Milestone | Goal | Priority |
| --- | --- | --- |
| HTTP smoke harness | Run the service in CI and exercise `/.well-known`, issue, verify, delegate, revoke over real HTTP | High |
| Docker build gate | Add `docker build` for `aip-service/Dockerfile` to prove deploy packaging | High |
| Fuzzing | Add fuzz targets for token parsing, canonical encoders, and evidence graph ingestion | Medium |
| OpenAPI contract | Publish machine-readable API schema and validate examples in CI | Medium |
| Performance report | Persist verify/sign latency histograms as CI artifacts, not only unit assertions | Medium |
| External audit pack | Map tests to patent claims, DPDP accountability controls, and STQC non-repudiation evidence | High |
| ML-DSA implementation | Replace the current ML-DSA-ready verifier interface with a FIPS 204 implementation when product scope requires PQ signatures | High |
