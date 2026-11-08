# Buyer questionnaire (W8.4)

Each answer is **Available** (evidence exists and is cited), **Partial**
(some evidence, with gaps stated) or **Planned** (no evidence yet). The
products are the four in `SECURITY_NOTES.md`.

| # | Question | Status | Answer and evidence |
|---|---|---|---|
| 1 | Does any demo need the internet? | Partial | Install, verification, `pq` and `quantum` ran in a namespace with no route out (`demos/kit/evidence/2026-11-07-9fe94a0/`). The security mode needs the host network namespace, so its offline behaviour is not shown by that test. Model modes are not ready |
| 2 | Can we verify what we were given? | Available | `kit/verify.sh` checks 177 files against `SHA256SUMS`; one flipped byte is refused. `MANIFEST.json` names both commits and every binary's sha256 |
| 3 | SBOM? | Available | CycloneDX 1.6, scoped to the shipped binaries' dependency trees: AIP 77 components, overlay 150 (`demos/evidence-pack/out/sbom-*.cdx.json`) |
| 4 | Licences? | Partial | Third-party: all permissive or with a permissive option (`sbom-*.licences.json`). AIP's own 8 crates are `LicenseRef-Proprietary`, with no LICENSE file in the repository. The overlay is `MIT OR Apache-2.0`. Not a legal review |
| 5 | CBOM of what we receive? | Partial | Three sources: kit files (0 assets), binary constants (SHA-256, AES, MD5), the overlay's self-inventory (9 algorithms). The binary scan misses most algorithms actually used, so there is no complete per-binary inventory |
| 6 | AIBOM? | Partial | The kit's only agent, the scripted test agent, is assessed with `aibom`: 0 of 15 fields independently backed, which is expected for a test fixture (`aibom-scripted-agent.txt`). No AI model ships in the kit |
| 7 | Which cryptography is quantum-vulnerable? | Partial | Overlay: X25519 and Ed25519 are, and are paired with ML-KEM-768 and ML-DSA-65 in its handshake (per source). Sniffer Dog: Ed25519 signatures and a `Noise_NK_25519_ChaChaPoly_SHA256` transport, whose X25519 and Ed25519 are classical |
| 8 | Is tampering with evidence detected? | Available | One-byte change to signed evidence rejected in every run (`demos/lying-agent/evidence/`) |
| 9 | What happens when a component is down? | Partial | auditd down: the cross-check is missing and the batch FAILs, kept as such. Overlay with identity removed: nothing delivered, but the app gets no error |
| 10 | Does the PQ overlay downgrade? | Available (in the tested cases) | Identity removed, fallback key offered, plaintext peer, impostor: none delivered (OVERLAY `demos/pq-switch/evidence/`) |
| 11 | Performance overhead? | Partial | Overlay: +13.2 KB per connection; time within noise at n=20. Sniffer Dog: not measured |
| 12 | Hardware needed? | Partial | One machine measured (`SIZING.md`); a second machine is required before giving guidance |
| 13 | Tested on more than one OS or kernel? | Planned | One kernel, one host |
| 14 | Independent test or certification? | Planned | None. No FIPS, Common Criteria or similar claim is made |
| 15 | Can we reproduce the benchmark? | Partial | The published table recomputes from recorded files (`demos/benchmark/REPRODUCE.md`); a fresh rerun is blocked on staged models |
| 16 | Do you learn from our data automatically? | Available (answer: no) | Capabilities are taught: an expert validates and approves them; no model weights change (`docs/intelligence-runtime/LEARNING_BENCHMARK.md`) |
| 17 | Has it run against real agents, real estates or customer data? | Planned | Only scripted agents and synthetic samples so far |
