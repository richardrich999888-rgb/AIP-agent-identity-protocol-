# AIRON Banking Pilot Playbook

This playbook explains what a bank, infrastructure partner, or TDB/STQC-style
technical reviewer can pilot from this repository today, and which latency
histograms must be collected before claiming production-grade banking readiness.

The benchmark names in this document are acceptance targets for pilot evidence.
External certification, statutory, or regulator-specific labels should be
validated against the buyer's current compliance checklist before submission.

## Product Services

### AIP: Identity and Accountability Plane

AIP provides cryptographic agent identity, scoped delegation, revocation, and
portable evidence packets.

| Service | Repo Surface | What It Provides |
| --- | --- | --- |
| Token issuance | `POST /v1/identity/issue` in `aip-service` | Ed25519/EdDSA JWTs for human, AI model, and service identities |
| Token verification | `POST /v1/identity/verify` | Signature, expiry, algorithm, and revocation checks |
| Public key discovery | `GET /v1/identity/public-key`, `GET /.well-known/jwks.json` | Offline verification material and JWKS integration |
| Scoped delegation | `POST /v1/identity/delegate` | Child capability scopes that cannot exceed the parent |
| Chain verification | `POST /v1/identity/verify-chain` | Ordered delegation-chain validation and effective scope calculation |
| Revocation | `POST /v1/identity/revoke` | Single-token or cascade revocation of descendant delegations |
| Revocation lookup | `GET /v1/identity/revocation-status/:jti` | O(1) revocation-state lookup |
| EvidencePacket | `aip-standalone/aip-protocol` | Decision, trace, receipt, attestation, graph, and assembler signature binding |

### AEGIS: Enforcement and Network Plane

AEGIS provides the kernel/data-plane enforcement layer for post-quantum
handshakes, eBPF/XDP telemetry, session maps, blocklists, and circuit breaking.

| Service | Repo Surface | What It Provides |
| --- | --- | --- |
| XDP ingress hook | `aegis-quantum-ebpf` | Packet parsing and fast-path blocklist checks at driver ingress |
| Kernel maps | `AQ_SESSIONS`, `AQ_BLOCKLIST`, `AQ_EVENTS` | Session trust cache, drop list, and ring-buffer telemetry |
| PQC engine | `aegis-quantum-userspace/src/pqc.rs` | Kyber/ML-KEM key exchange validation and session-key hashing |
| Circuit breaker | `aegis-quantum-circuit-breaker` | Sliding-window rogue-loop detection |
| Userspace controller | `aegis-quantum-userspace` | Ring-buffer event processing and map updates |
| Validation harness | `aegis-quantum/validation/validate_xdp.py` | Dry-run and live-fire XDP validation scenarios |

## Pilot Modes

### 1. Evidence-Only Pilot

Use this mode when the evaluator wants reproducible engineering evidence without
deploying a gateway.

```bash
make aip-ci-local
cd aegis-quantum
make ci-local
```

Expected proof:

| Component | Evidence |
| --- | --- |
| AIP | 246 Rust tests, JSON validation report, service contract checks |
| AEGIS | 104 Rust tests, XDP dry-run scenarios, eBPF bytecode CI build |

### 2. AIP Service Pilot

Use this mode when the evaluator wants to integrate agent identity and
delegation into a test service.

```bash
mkdir -p /tmp/airon-aip

AIP_PORT=8081 \
AIP_KEY_PATH=/tmp/airon-aip/signing.key \
AIP_DELEGATION_LOG_PATH=/tmp/airon-aip/delegation.jsonl \
AIP_REVOCATION_LOG_PATH=/tmp/airon-aip/revocation.jsonl \
AIP_ISSUER_URL=http://127.0.0.1:8081 \
cargo run --manifest-path aip-service/Cargo.toml
```

Smoke checks:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/.well-known/aip-configuration
curl http://127.0.0.1:8081/.well-known/jwks.json
```

### 3. AEGIS Lab Pilot

Use this mode for eBPF/XDP validation and PQC/circuit-breaker timing.

```bash
cd aegis-quantum
make ci-local
make validation-report
make bench
```

Linux runner or bare-metal host:

```bash
cd aegis-quantum
make build-ebpf
```

Bare-metal line-rate claims require a Linux NIC testbed with traffic generation.
The repository CI proves buildability and dry-run correctness; it does not
substitute for a 10 Gbps hardware test.

## Banking Latency Gates

The pilot must collect histograms, not only averages. The evidence gate is p99
unless noted otherwise.

| Zone | Metric | Target |
| --- | --- | ---: |
| Invisible kernel enforcement | AEGIS ingress hook latency | p99 < 15 us |
| Invisible kernel enforcement | Circuit breaker detonation | p99 < 50 us |
| Invisible kernel enforcement | Throughput | minimum measured >= 10 Gbps |
| PQC identity handshake | ML-KEM/Kyber handshake | p99 < 2.5 ms |
| PQC identity handshake | Signature verification | p99 < 500 us |
| PQC identity handshake | Trust-cache injection into `SESSION_MAP` | p99 < 100 us |
| Accountability evidence | EvidencePacket assembly | p99 < 150 ms |
| Accountability evidence | Audit export latency | p99 < 1,000 ms |
| Accountability evidence | Storage overhead | p99 < 50 KB per action |
| End-to-end RTT | AIRON-active vs baseline | p99 delta <= 3% |

## Histogram Report

Create a sample JSON file with measured values:

```json
{
  "metadata": {
    "pilot": "bank-lab-01",
    "host": "ubuntu-24.04 bare-metal",
    "nic": "10gbe",
    "sample_count_goal": 10000
  },
  "samples": {
    "baseline_transaction_rtt_ms": [],
    "airon_active_transaction_rtt_ms": [],
    "aegis_ingress_hook_us": [],
    "aegis_circuit_breaker_detonation_us": [],
    "aegis_throughput_gbps": [],
    "ml_kem_handshake_ms": [],
    "signature_verification_us": [],
    "trust_cache_injection_us": [],
    "evidence_packet_assembly_ms": [],
    "audit_export_ms": [],
    "storage_overhead_kb": []
  }
}
```

Generate the report:

```bash
python3 scripts/generate_airon_latency_histogram.py \
  --samples pilot_latency_samples.json \
  --output airon_latency_report.json
```

The script computes min, p50, p95, p99, max, pass/fail per metric, and the
baseline-vs-AIRON p99 RTT delta. Missing metrics are marked `NOT_MEASURED`.
Local developer measurements that hit the numeric gate are marked
`PASS_LOCAL_SCOPE`; only `banking_pilot`, `bare_metal`, or `production_like`
measurement scopes are treated as full banking evidence.

## Local Pre-Pitch Pilot

Before approaching outside pilot partners, run the local screening pass:

```bash
make pilot-local
```

This starts the AIP service, exercises issue/verify/delegate/verify-chain/revoke
over HTTP, measures in-process AIP signature verification, measures AIP
EvidencePacket assembly/export/storage overhead, and measures AEGIS local
Kyber/circuit-breaker timing. Performance binaries run in Rust `--release`
mode; debug-mode latency is not acceptable pilot evidence.

Artifacts are written under `pilot-results/`:

| Artifact | Purpose |
| --- | --- |
| `local_pilot_summary.json` | Pass/fail summary and list of remaining unmeasured metrics |
| `local_pilot_http_smoke.json` | AIP service endpoint smoke evidence |
| `local_pilot_samples.json` | Raw latency samples |
| `local_pilot_latency_report.json` | Histogram report with p50/p95/p99/max and scope labels |

## Current Readiness Boundary

Ready today:

- AIP validation CI and service API pilot.
- AEGIS eBPF bytecode build CI, dry-run XDP validation, PQC/circuit-breaker benchmarks.
- A combined latency report format for pilot evidence packs.

Still required before a banking LOI claim:

- Bare-metal 10 Gbps traffic run with AEGIS attached.
- Real kernel hook timing under load, not only dry-run validation.
- AIP-to-AEGIS trust-cache injection timing in the integrated gateway path.
- HTTP audit export endpoint or vault adapter for EvidencePacket retrieval.
- Long-run p99/p999 stability under burst traffic.
