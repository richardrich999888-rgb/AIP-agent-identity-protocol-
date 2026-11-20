# Third-party licences — adversarial validation program

External tools and licences, with exact versions recorded for verified setups.
Entries still marked `TODO` are not validated installations. Reproduce pinned
revisions and dependency locks rather than selecting current releases. Licences
must be re-verified at fetch time (several PoCs have ambiguous licensing).

## Already in the tree (built + tested)

| Component | Licence | Notes |
|-----------|---------|-------|
| `orbitaltrust-accountability/` (imported) | LicenseRef-Proprietary (same as workspace) | `ot-accountability-core`, `ot-sentinel` wired; manifest verified 112/114 byte-identical |

## Phase 1 — agent framework (installed, pinned, executed)

Full pinned set in `integrations/agents/requirements.lock` (38 packages).

| Tool | Licence | Pin |
|------|---------|-----|
| LangGraph | MIT | `1.2.11` |
| langchain-core | MIT | `1.6.3` |
| langgraph-checkpoint / -prebuilt / -sdk | MIT | `4.2.0 / 1.1.0 / 0.4.4` |

## Cryptography in the shipped build (compiled, tested)

Runtime dependencies of `aip-crypto`, which every signed artefact depends on.
These are pinned in `Cargo.lock`; the exact-version pin below is in the
manifest itself.

| Crate | Licence | Pin | Notes |
|-------|---------|-----|-------|
| `ed25519-dalek` | BSD-3-Clause | `2.1` | Every signature shipped today. Mature, widely reviewed. |
| `ml-dsa` | Apache-2.0 OR MIT | `=0.1.1` | FIPS-204 ML-DSA-65, RustCrypto. **Used only in the hybrid path** (`aip_crypto::hybrid`), never alone. **Pre-1.0 and not independently audited** — which is precisely why the construction verifies the mature half too, so a defect here cannot on its own produce a signature that verifies. Pinned exactly (`=`) rather than caret, because a pre-1.0 crate's patch releases may change behaviour. |
| `sha2` | Apache-2.0 OR MIT | `0.10` | SHA-256 throughout. |
| `argon2`, `chacha20poly1305`, `zeroize` | Apache-2.0 OR MIT | `0.5`, `0.10`, `1.8` | Phase A key custody at rest. |
| `bs58` | Apache-2.0 OR MIT | `0.5` | AIP-ID encoding. |

## Phase 2 — MCP gateway (pinned source and locked runtime installed)

| Tool | Licence | Pin |
|------|---------|-----|
| IBM ContextForge (`mcp-context-forge`) | Apache-2.0 | `ff6a566a4b5c098093db90bbb4d5df483e108026` (1.1.0); dependency lock SHA-256 `76ef83096d34d7a95aca91407cbf085c3da1e0c937616d86da393b9549117f0c` |
| ContextForge Plugin Extensions (`cpex`) | Apache-2.0 | `0.1.4`, from pinned upstream `uv.lock` |
| Official MCP Python SDK / types | MIT | `2.3.0` / `2.3.0`, from pinned upstream `uv.lock`; protocol `2026-07-28` client exercised |
| Lasso MCP Gateway (fallback) | open-source (confirm exact) | `TODO at setup` |

## Phase 4 — ATT&CK corpus (not yet fetched)

| Tool | Licence | Pin |
|------|---------|-----|
| SPIRE (spiffe/spire) | Apache-2.0 | v1.15.3, built from the Go module proxy with checksum verification; used in `validation/external/spiffe/` |
| go-spiffe | Apache-2.0 | v2.8.2, pinned in `validation/external/spiffe/workload/go.sum` |
| Atomic Red Team | MIT | referenced by stable ATT&CK technique layout (`atomics/<ID>/`) in `adversarial/atomic/coverage.tsv`; corpus not vendored, no atomic executed |
| MITRE Caldera (optional) | Apache-2.0 | `TODO at setup` |
| Stratus Red Team (optional, containers) | Apache-2.0 | `TODO at setup` |

## Phase 5 — rootkits (SOURCE REVIEW ONLY; run only in the VM)

| Tool | Licence (verify at repo) | Notes |
|------|--------------------------|-------|
| TripleCross | GPLv3 (RawTCP_Lib MIT) | |
| ebpfkit | verify at repo | graded control: `--disable-bpf-obfuscation` |
| bad-bpf | verify at repo (DEF CON 29 educational) | `pidhide` targets pidfd anchoring |
| Boopkit | verify at repo | |
| pamspy | verify at repo | out-of-scope surface (documented) |
| Singularity | verify at repo | |

## Prior art (cited only — not dependencies)

MCPKernel, HELM AI Kernel, Etch. See `PRIOR_ART_NOTES.md`.
