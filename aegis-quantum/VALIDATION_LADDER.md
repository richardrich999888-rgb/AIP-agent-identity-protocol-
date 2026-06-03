# AEGIS Quantum Validation Ladder

This document separates validated lab evidence from the next gates required for
kernel/live-fire and pilot-readiness claims.

## Current Evidence

### Gate 1: Rust Lab Tests

Command:

```bash
cargo test --workspace
```

Current scope:

- 30 circuit-breaker tests for thresholds, sliding windows, resets, and scale.
- 28 common ABI tests for kernel/userspace struct sizes, alignment, offsets, and map names.
- 29 PQC userspace tests for Kyber-768 / ML-KEM simulated roundtrips, X25519 + Kyber-768 hybrid session establishment, key sizes, entropy, and timing.
- 19 integration-simulation tests for rogue detection, blocklist expiry, session values, packet events, and full pipeline simulation.
- 4 stress-harness tests for LRU session-map saturation and circuit-breaker noisy-neighbor isolation.

Status: 110/110 passing on the local development host.

### Gate 2: Dry-Run XDP Validation

Command:

```bash
python3 validation/validate_xdp.py --dry-run
```

Current scope:

- Single SYN pass.
- Below-threshold burst pass.
- Above-threshold burst expected drop.
- Legitimate traffic unaffected after block.
- Non-TCP passthrough.
- IPv6 passthrough.

Status: 6/6 passing in simulated mode.

### Gate 3: eBPF Bytecode Build

Command:

```bash
make check-ebpf
make build-ebpf
```

Requirements:

- Rust nightly.
- `rust-src` for nightly.
- `bpfel-unknown-none` with `-Z build-std=core`.

Status: wired into Makefile and GitHub Actions. This gate proves the excluded
`aegis-quantum-ebpf` crate compiles as BPF bytecode, but it does not prove the
program loads into a kernel or passes live traffic.

## Cryptography Bill of Materials

This CBOM records what is implemented today and what belongs to the RDI
hardening roadmap. It should be updated whenever cryptographic primitives,
protocol bindings, or kernel enforcement assumptions change.

| Component | Standard / Primitive | Current Implementation | RDI Hardening Target |
| --- | --- | --- | --- |
| PQC exchange | X25519 + Kyber-768 / ML-KEM family | Rust userspace hybrid roundtrip combines X25519 Diffie-Hellman with `pqcrypto_kyber::kyber768`; the final 32-byte session hash is stored as session material. | Align naming, test vectors, and compliance notes with NIST FIPS 203 ML-KEM; validate hybrid key establishment in live traffic. |
| Session hash | Domain-separated SHA-256 | `sha2::Sha256` over `AIRON-AEGIS-HYBRID-v1`, the X25519 shared secret, and the Kyber shared secret for `SessionValue.shared_secret_hash`. | Add full transcript binding, replay-resistant session identifiers, and AIP token/delegation binding. |
| Runtime enforcement | Linux eBPF / XDP | Indigenous XDP program using `AQ_EVENTS`, `AQ_BLOCKLIST`, `AQ_SESSIONS`, and `AQ_COUNTERS` maps. | Kernel verifier evidence, live-fire counter evidence, AF_XDP validation, and map-pressure testing. |
| Agent identity binding | AIP Ed25519/JWT stack | Not enforced by AEGIS yet; AEGIS currently keys by TCP connection tuple. | Bind enforcement to AIP `agent_id`, `tenant_id`, capability, delegation, and revocation state. |
| Delegation signatures | Ed25519 + ML-DSA-65 EvidencePacket path | AIP standalone EvidencePackets can carry optional Dilithium3-backed ML-DSA-65 assembler signatures; AIP service tokens remain Ed25519/JWT for compatibility. | Extend service-token and delegation-certificate issuance to hybrid signatures after pilot API compatibility review. |
| Evidence export | JSON validation report | `validation/validate_xdp.py --output validation_report.json` writes a machine-readable test report. CI also emits SHA-256 bundle manifests; public repos get GitHub provenance attestations and private repos can emit GPG detached signatures via `CI_GPG_PRIVATE_KEY_B64`. | Attach CI artifacts, signed reports, and AIP EvidencePackets for regulator/auditor review. |

## Next Evidence Gates

### Gate 4: Chaos and Stress Harness

Commands:

```bash
make stress-test
make chaos-local
make stress-bench
```

Current scope:

- Deterministic LRU saturation of a mock `AQ_SESSIONS` table using the shared `ConnectionKey` and `SessionValue` ABI types.
- Circuit-breaker isolation under a 10,000-event rogue burst while a legitimate connection continues to process independently.
- Criterion stress benches for LRU saturation and noisy-neighbor isolation.
- `stress-tests/run_chaos_suite.py` emits `pilot-results/chaos_stress_report.json`; dry-run mode marks `stress-ng` and `bpftool` checks as `SKIP_LOCAL_SCOPE` rather than claiming live kernel proof.

Status: wired for local and CI-compatible execution. Live resource-starvation and map-telemetry proof still requires Linux with root, `stress-ng`, `bpftool`, and a loaded AEGIS XDP program.

### Gate 5: BPF Verifier and Map Load

Target environment: Linux 5.15+ with `bpftool`, CAP_BPF, and CAP_NET_ADMIN.

Required proof:

- eBPF program loads successfully.
- `AQ_EVENTS`, `AQ_BLOCKLIST`, `AQ_SESSIONS`, and `AQ_COUNTERS` maps are visible through `bpftool`.
- XDP program attaches to a real interface.

### Gate 6: Live-Fire Packet Validation

Command:

```bash
sudo python3 validation/validate_xdp.py --live-fire --iface <interface>
```

Required proof:

- Real SYN packets are passed below threshold.
- Rogue burst causes blocklist insertion.
- Blocked packets are dropped by XDP, not by simulated logic.
- Legitimate traffic from a different connection remains unaffected.
- Kernel counters change as expected.

### Gate 7: Performance and Pilot Benchmarks

Required proof:

- p50/p95/p99 latency with AEGIS disabled and enabled.
- PQC key exchange timing separated from XDP pass/drop timing.
- AF_XDP redirect timing separated from ring-buffer timing.
- Sustained load behavior under many distinct connection keys.
- Memory/map pressure behavior under blocklist/session churn.

### Gate 8: AIP-Controlled Enforcement

Required proof:

- AEGIS enforcement can key policy by AIP `agent_id`, `tenant_id`, capability, and revocation state.
- AEGIS events are written into AIP EvidencePackets.
- An auditor can reconstruct the enforcement decision from AIP artifacts.

## Claim Boundary

Current evidence supports: lab-validated AEGIS prototype with passing Rust unit,
integration, PQC simulation, deterministic stress harness, and dry-run
validation.

Current evidence does not yet support: production deployment, wire-speed PQC,
TRL-7/8 readiness, or live kernel enforcement claims.
