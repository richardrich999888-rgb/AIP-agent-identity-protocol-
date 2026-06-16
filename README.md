# AIP — Accountability Infrastructure for Autonomous AI

**Prove what the agent did and who authorized it.**

AIP is the flight recorder for AI agents. When an autonomous agent acts —
approves a payment, files a claim, executes a trade — AIP produces an
**EvidencePacket**: a self-contained, cryptographically signed, tamper-evident
record binding the action to the human authority that permitted it, through
every delegation hop in between.

```text
Human CFO ──issues──▶ Scoped Token ──delegates──▶ Payments Agent
                                                      │ decides
                                                      ▼
                       EvidencePacket ◀──seals── Payment Approval
                        │                             │ performs
                        │ binds                       ▼
                        ▼                        Ledger Entry
        agent identity · delegation chain        (countersigned
        decision · signed actions · receipt        by the ledger)
```

Modify one byte of a sealed packet — the amount, the scope, the authority —
and verification fails on a named cryptographic rule. Recompute the hash to
cover your tracks and the agent's signature catches it.

## Why

Agent logs are not evidence. Observability tells you *what happened*;
identity systems control *who can act*. Neither proves, after the fact and
to a skeptical third party, **which delegated authority an autonomous action
descended from** — the question auditors, regulators, and counterparties ask
when something goes wrong. AIP answers it with cryptography instead of trust.

## See it in 60 seconds

```bash
cd aip-standalone
cargo run -p banking-demo
```

The demo builds the full CFO → delegation → payment → countersigned-ledger
flow, verifies the packet at the `COUNTERPARTY_SIGNED` trust floor, then
tampers with the payment amount (twice — the second attacker also fixes the
hash) and shows verification failing on the exact rules that caught it.
Every check is real Ed25519/SHA-256; the demo exits non-zero if any honest
check fails or any tamper goes undetected.

## What's in the box

| Crate | What it is | Maturity |
|---|---|---|
| **`aip-protocol`** | **EvidencePacket v1**, the 14-rule verification engine, the accountability graph (Human→Authority→Agent→Decision→Action→Receipt) | MVP, tested |
| `aip-core` | Delegation chains (per-hop signatures, lattice scope attenuation, depth limits), capability scopes, cascade revocation, hash-chained scoped audit | MVP, tested |
| `aip-crypto` | Ed25519, SHA-256, Base58 AIP-ID derivation with checksum | Stable |
| `aip-types` | Wire-format data structures | Stable |
| `banking_demo` | End-to-end design-partner demo with tamper detection | Demo |
| `aip-cli` | Local identity/signing utilities | Prototype |
| `aip-service` | Reference HTTP prototype — **no auth, single-node; not for production** | Prototype |
| reputation / hardware-attestation / liveness modules | **Experimental** — see `AUDIT_CORRECTIONS.md` | Experimental |

## Core guarantees (implemented and tested)

1. **Tamper evidence.** `packet_hash = SHA-256(canonical bytes)`; the agent
   signs it. Any post-sealing modification — including of embedded
   delegation signatures — is detected.
2. **Authority binding.** The delegation chain verifies per hop: signature,
   parent linkage, depth, and scope attenuation (a child scope can never
   exceed its parent — lattice MEET).
3. **Scope enforcement.** The decision and every action must fall inside the
   effective (most-attenuated) scope, or verification fails.
4. **Bilateral evidence.** External systems countersign receipts, bound to
   the specific decision — evidence both sides can rely on in a dispute.
5. **Derived trust.** Verifiers compute the trust floor
   (`UNVERIFIED → AGENT_SIGNED → AUTHORITY_BOUND → COUNTERPARTY_SIGNED`)
   from the evidence; claims above the evidence fail.

## Using the library

```rust
use aip_protocol::{EvidencePacketBuilder, VerificationContext, verify_packet};

// Agent side: seal evidence for an action it just performed.
let packet = EvidencePacketBuilder::new(agent_identity, root_authority)
    .delegation_chain(chain)
    .decision(decision)
    .action(signed_action)
    .receipt(countersigned_receipt)
    .claimed_trust_floor(TrustFloor::CounterpartySigned)
    .build_and_sign(&agent_private_key)?;

// Auditor side: verify against keys *you* trust.
let ctx = VerificationContext::new()
    .trust_issuer(&cfo_id, &cfo_public_key)
    .trust_issuer(&orchestrator_id, &orch_public_key)
    .trust_counterparty("ledger.example-bank.com", &ledger_public_key);
let report = verify_packet(&packet, &ctx);

assert!(report.valid);
println!("{}", report.to_json()?); // {"valid":true,"trust_floor":"COUNTERPARTY_SIGNED",...}
```

## Build & test

```bash
cd aip-standalone
cargo build --workspace
cargo test  --workspace            # full suite
cargo test  --workspace --release  # includes wall-clock throughput gates
cargo run   -p banking-demo
```

## Documents

- [`AIP_SPEC.md`](AIP_SPEC.md) — the open EvidencePacket specification
  (format, verification rules, delegation semantics, trust floors).
- [`ROADMAP.md`](ROADMAP.md) — console, SDKs, framework integrations,
  Evidence Vault.
- [`AUDIT_CORRECTIONS.md`](AUDIT_CORRECTIONS.md) — what this repository
  previously overstated and what was done about it. Trust is a product
  feature; read this first if you're doing diligence.

## Status, honestly

This is an MVP accountability layer with a tested cryptographic core. It is
not yet: a hosted service, an SDK ecosystem, or an enterprise product. The
spec is v0.1-draft and the APIs will change. What it *is*: every claim in
this README is backed by code you can run and tests you can read.

## License

Core protocol and reference implementation: proprietary
(Vanian Technologies Private Limited) — **open-sourcing of the spec and core
crates is planned**; see `ROADMAP.md`. Patent matters: provisional filings
exist covering delegation-bound audit binding; see `reports_and_patents/`
(attorney working documents).

© 2025–2026 Vanian Technologies Private Limited.
