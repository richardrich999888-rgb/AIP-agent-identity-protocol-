# Adversarial validation — program map and safety rules

This tree holds the hostile-validation program for the pre-RBI technical
evaluation. **Phase 0 (cross-sensor blinding detection) is built, tested and
committed in the Rust workspace** (`aip-observe::divergence`,
`aip-collector/src/sink.rs`, `docs/security/BLINDING_RESILIENCE.md`). What is
under `adversarial/` and `integrations/` is the rest of the program as
**runbooks and harnesses**, most of which require infrastructure not present
in the build environment (network installs, kernel capabilities, and — for
Tier 2 — a dedicated VM). Each directory says plainly what has been executed
and what has not. See `STATUS.md` at the repository root for the register.

## NON-NEGOTIABLE SAFETY RULES

1. **Never build, load, or run any eBPF rootkit** (TripleCross, ebpfkit,
   bad-bpf, Boopkit, pamspy, Singularity) on the development host, in CI, or
   in a container on this machine. Only in a dedicated, snapshotted,
   network-isolated VM, by a human, per `rootkit-runbooks/README.md`.
2. Repos may be cloned into `vendored/` for **source review only**; that
   directory carries a `DO_NOT_RUN_ON_HOST` marker.
3. **Never weaken a verdict or a fail-closed path to make a test pass.** A
   FALSE-PROVEN result is a real defect to report, not to paper over.
4. Pin every dependency to an exact version; record licences in
   `THIRD_PARTY_LICENSES.md`.
5. Anything needing CAP_BPF / CAP_SYS_ADMIN / CAP_NET_RAW or a specific kernel
   is stated and stopped for a human to run — never a silent `sudo`.

## Layout

| Path | Phase | Status |
|------|-------|--------|
| `../aip-standalone/aip-observe/src/divergence.rs` | 0 | **built + tested** |
| `../docs/security/BLINDING_RESILIENCE.md` | 0 | **written** |
| `../integrations/agents/` | 1 | **executed + sealed**; real LangGraph run observed end-to-end, verified offline (`results/sealed/`) |
| `../integrations/mcp-gateway/` | 2 | **built + tested**; `aip-mcp-gateway` signs a `ToolReceipt` per `tools/call`; ContextForge adapter shells to it |
| `atomic/` | 4 | **built + tested**; Navigator layer generated from an ATT&CK coverage map (no atomic executed on host) |
| `rootkit-runbooks/` | 5 | **document-only**; the output-parsing harness is built + fixture-tested |
| `../validation/external/corroborate/` | 10a | **executed + sealed**; bpftrace + auditd corroboration, no AIP blind spot |
| `vendored/` | 2,5 | source review only; `DO_NOT_RUN_ON_HOST` |
