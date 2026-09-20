# Aegis-Quantum (AQ-1) — Indigenous eBPF-Powered Post-Quantum Proxy & Agentic AI Circuit Breaker

**TRL-4: Technology Validated in Laboratory**

[![Status: TRL-4](https://img.shields.io/badge/TRL-4%20Lab%20Validated-blue.svg)]()
[![Patent: Pending](https://img.shields.io/badge/Patent-Pending-orange.svg)]()
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)]()

---

## What is Aegis-Quantum?

Aegis-Quantum is a **sovereign deep-tech infrastructure layer** designed to neutralize the dual existential threats of the 2026 digital landscape:

1. **Quantum Decryption (Harvest Now, Decrypt Later)** — Adversaries intercepting encrypted data today to decrypt it with future quantum computers.
2. **Agentic AI Cascade Failures** — Autonomous AI agents entering runaway loops that overwhelm enterprise APIs at machine speed.

It is a stateless, inline cryptographic proxy designed to run at the **Linux kernel level via eBPF/XDP**, so that protection sits on the packet path rather than behind a user-space hop.

> ### Validation status — read this before quoting any number below
>
> **TRL-4: validated in the laboratory.** What that means here, precisely:
>
> | | |
> |---|---|
> | **110/110 Rust tests pass** | circuit breaker, ABI, PQC, integration-simulation, stress |
> | **Post-quantum cryptography is real** | `pqcrypto-kyber 0.8`; genuine Kyber-768 keypair / encapsulate / decapsulate, hybridised with X25519 |
> | **The XDP program compiles to BPF bytecode** | Gate 3 |
> | **It has never been loaded into a kernel** | Gate 5, open |
> | **It has never passed live traffic** | Gate 6, open |
> | **No performance figure has been measured** | Gate 7, open |
>
> "Simulation" in this repository refers to the **pipeline** — synthetic packet
> events rather than a live NIC. It does **not** mean the cryptography is
> simulated; the Kyber-768 exchange is real.
>
> The authoritative record is [`VALIDATION_LADDER.md`](VALIDATION_LADDER.md).
> Where this README and that document ever disagree, the ladder is correct.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        AEGIS-QUANTUM (AQ-1)                             │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                    KERNEL SPACE (eBPF/XDP)                      │     │
│  │                                                                  │     │
│  │  [NIC] ──► [XDP Hook] ──► [Header Parse] ──► [Blocklist Check] │     │
│  │                │                                    │            │     │
│  │                │                              PASS / DROP        │     │
│  │                │                                                 │     │
│  │                ▼                                                 │     │
│  │        [Ring Buffer] ──────────────────────────────────────┐     │     │
│  │        [Session Map] ◄────────────────────────────────┐   │     │     │
│  │        [Blocklist Map] ◄──────────────────────────┐   │   │     │     │
│  └───────────────────────────────────────────────────┼───┼───┼─────┘     │
│                                                       │   │   │           │
│  ┌───────────────────────────────────────────────────┼───┼───┼─────┐     │
│  │                    USER SPACE                      │   │   │     │     │
│  │                                                    │   │   │     │     │
│  │  [Ring Buffer Reader] ◄────────────────────────────┘   │   │     │     │
│  │         │                                              │   │     │     │
│  │         ▼                                              │   │     │     │
│  │  [PQC Engine (X25519 + Kyber-768)] ─ Session Key ──────────┘     │     │
│  │         │                                                  │     │     │
│  │         ▼                                                  │     │     │
│  │  [Circuit Breaker] ──── Block Signal ──────────────────────┘     │     │
│  │                                                                  │     │
│  └──────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Performance: design targets — NOT measured

**None of the figures in this section has been measured.** They are the design
targets that motivate a kernel-path implementation, quoted from the published
characteristics of XDP versus a user-space proxy hop. Gate 7 of the validation
ladder — p50/p95/p99 latency with AEGIS disabled and enabled — is **open**, and
until it closes AQ-1 has no measured performance claim of its own.

They are kept here because they state what the architecture is *for*. They must
not be presented as results, in a submission or anywhere else.

| Metric | Typical user-space proxy | AQ-1 **design target** | Measured? |
|--------|--------------------------|------------------------|-----------|
| Packet latency | 180–450 µs | 8–15 µs | **No — Gate 7** |
| CPU cycles/packet | 4,500–6,000 | 150–300 | **No — Gate 7** |
| Context switches | 2 per hop | 0 on the fast path | **No — Gate 5/6** |
| Throughput | ~2.5 Gbps | 10 Gbps+ | **No — Gate 7** |
| Memory | dynamic heap | zero-copy ring buffer | Design property; unmeasured under load |

To close Gate 7: load the program (Gate 5), pass live traffic (Gate 6), then
benchmark with AEGIS disabled and enabled on the same host and interface.

---

## Repository Structure

```
aegis-quantum/
├── Cargo.toml                      # Workspace root
├── aegis-quantum-common/           # Shared types (no_std compatible)
│   └── src/lib.rs                  # PacketEvent, ConnectionKey, Maps
├── aegis-quantum-ebpf/             # Kernel-space XDP program (standalone)
│   └── src/main.rs                 # eBPF packet parser + blocklist + ring buffer
├── aegis-quantum-userspace/        # User-space controller
│   └── src/
│       ├── main.rs                 # Entry point (TRL-4 validation mode)
│       ├── pqc.rs                  # X25519 + Kyber-768 hybrid PQC engine with timing
│       └── controller.rs           # Circuit breaker integration
├── aegis-quantum-circuit-breaker/  # Sliding window loop detector
│   └── src/lib.rs                  # O(1) amortized event tracking
├── benchmarks/                     # Criterion.rs performance suite
│   └── benches/
│       ├── pqc_bench.rs            # Kyber-512/768/1024 latency
│       └── circuit_breaker_bench.rs # Event throughput + scaling
└── validation/
    └── validate_xdp.py             # Scapy-based XDP test runner
```

---

## Quick Start

```bash
# Build the workspace (common + userspace + circuit-breaker + benchmarks)
cd aegis-quantum/
cargo build --workspace

# Run all unit tests
cargo test --workspace

# Run TRL-4 validation
cargo run --package aegis-quantum-userspace

# Run performance benchmarks
cargo bench --package aegis-quantum-benchmarks

# Run XDP validation (dry-run mode for macOS)
python3 validation/validate_xdp.py --dry-run
```

---

## Intellectual Property

**Patent Status:** Provisional Filed  
**IP Owner:** Vanian Technologies Private Limited  
**TDB Application:** TRL-4 Laboratory Validation Complete  

**© 2025–2026 Vanian Technologies Private Limited. All rights reserved.**
