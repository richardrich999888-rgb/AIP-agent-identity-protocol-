# Third-party licences — adversarial validation program

Every external tool the program uses, with its licence as stated by the
project. **Versions are pinned at setup time**, not here, because none of these
has been fetched into the build environment yet; record the exact version
beside each when it is cloned/installed. Licences must be re-verified at the
repo at fetch time (several PoCs are research code with ambiguous licensing).

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

## Phase 2 — MCP gateway (not yet fetched)

| Tool | Licence | Pin |
|------|---------|-----|
| IBM ContextForge (`mcp-context-forge`) | Apache-2.0 | `TODO at setup` |
| Lasso MCP Gateway (fallback) | open-source (confirm exact) | `TODO at setup` |

## Phase 4 — ATT&CK corpus (not yet fetched)

| Tool | Licence | Pin |
|------|---------|-----|
| Atomic Red Team | MIT | `TODO at setup` |
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
