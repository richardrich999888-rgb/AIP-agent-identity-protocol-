# P0-048-A — dependency matrix

Baseline: `4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
Review date: 12 November 2026 (Asia/Kolkata).

No new dependency is declared mandatory or installed by this iteration.
The native probe, collector, AIP authorization/reconciliation and offline
verifier remain the product. Third-party identity, policy, tracing and comparison
tools are optional integrations or evaluation instruments.

## What is required, and for which profile

| Component | Requirement | Pin/license evidence | Classification and qualification limit |
|---|---|---|---|
| Native Rust code and transitive crates | Required at build time for selected native binaries; no Cargo download at runtime | [root manifest](../../Cargo.toml), [lock](../../Cargo.lock), [policy](../../deny.toml), [license inventory](../../THIRD_PARTY_LICENSES.md) | IMPLEMENTED. Root lock contains 322 packages, 264 registry packages, all with checksums; no Git-source package. Lockfile alone is not an offline vendor bundle or reproducible toolchain. |
| Compatible Linux kernel, procfs, sensor facilities and capabilities | Required for the particular native observation profile, not for pure offline verification | [systemd probe](../../deploy/pilot/systemd/aip-probe.service), [runtime](../../aip-standalone/aip-observe/src/runtime.rs) | PARTIALLY VERIFIED. `connector` needs initial network namespace; perf, fanotify, packet and cgroup requirements differ. Missing facilities withdraw coverage. macOS component tests do not validate Linux sensing. |
| Python/systemd/libc | Required by existing Linux install/control scripts and dynamically linked artifacts as applicable | [offline procedure](../../deploy/enterprise/airgap/README.md), [package implementation](../../deploy/enterprise/linux/package.py) | PARTIALLY VERIFIED. Destination OS dependency/SBOM closure is not supplied by the package script. |
| SPIRE / SPIFFE | Optional institution workload identity | [source pins/license hashes](../../integrations/interoperability/upstreams.lock.json): SPIRE inspected revision `a33d43d3c1cd734b6eca0c6ec6582353a5d35eb0`; Apache-2.0. Live CLI harness targets 1.15.3. | PARTIALLY VERIFIED. Inspection revision, binary release and native comparison are distinct facts; do not equate them without provenance. |
| PyJWT / httpx | Required only by the optional Python interoperability adapter | [pyproject](../../integrations/interoperability/pyproject.toml), [uv lock](../../integrations/interoperability/uv.lock): PyJWT 2.10.1, httpx 0.28.1, transitive package hashes | PARTIALLY VERIFIED. Operator-pinned trust, configured tenant/audience and issuer profile remain required. |
| OpenTelemetry SDK / Collector | Optional supporting controller telemetry; not an execution witness | [other-branch lock](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/ab161597ea05d52813619d9962f8956811d2daf1/integrations/governance/otel.lock.json): SDK 1.45.2, conventions package 0.66b2, Collector Contrib 0.164.0; platform archive and binary SHA-256 recorded | PARTIALLY VERIFIED on other branch. Versions/hashes are repository-retained pins, not freshly downloaded verification. No complete GenAI schema mapping is demonstrated. |
| GenAI semantic conventions | Optional schema contract for P0-048-D | [inspected upstream lock](../../integrations/interoperability/upstreams.lock.json): `51a0f580f8a6ad804ca4de5e033683c6fbbe5906`, Apache-2.0/license hash | IMPLEMENTED source inventory only; MISSING end-to-end pinned schema conformity in the inspected telemetry profile. Do not treat SDK package version as the GenAI repository revision. |
| OPA | Optional policy adapter; cannot replace AIP signed authority | Baseline [upstream inventory](../../integrations/interoperability/upstreams.lock.json): `ca660665cc95b0fce665b71192aac938889719c9`. Newer [runtime lock](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/ab161597ea05d52813619d9962f8956811d2daf1/integrations/governance/opa.lock.json): 1.22.0, `d4c8d0c8812290c3e3715ca4cf958f75283f6ec4`, artifact/license hashes; Apache-2.0 | PARTIALLY VERIFIED, two distinct profiles. OPA allow/decision metadata is not collector-signed execution. |
| ContextForge / MCP | Optional gateway and evidence-client profiles | [runtime lock](../../integrations/mcp-gateway/contextforge.lock.json): ContextForge 1.1.0 at `ff6a566a4b5c098093db90bbb4d5df483e108026`, cpex 0.1.4, MCP 2.3.0, upstream uv-lock SHA-256; Apache-2.0 | PARTIALLY VERIFIED. Separate inspected ContextForge revision in the broad upstream inventory is not this runtime pin. Preserve native signed receipts and policy negatives. |
| ADK / A2A | Optional framework/transport adapters | [pyproject](../../integrations/interoperability/pyproject.toml): google-adk 2.13.0, a2a-sdk 1.3.0; [upstream licenses/revisions](../../integrations/interoperability/upstreams.lock.json) | PARTIALLY VERIFIED. Experimental A2A profiles and own task acceptance; no full conformance claim. |
| Microsoft governance / ACS | Optional policy evidence adapter | [upstream/runtime inventory](../../integrations/interoperability/upstreams.lock.json), [validation](../interoperability/VALIDATION_REPORT.md): compatibility SDK 0.4.0b0, ACS alpha.4 | PARTIALLY VERIFIED. Versioned content comparison is not authenticated source or independent kernel attribution. |
| Tetragon | Optional independent-implementation comparison | [inspected revision/license](../../integrations/interoperability/upstreams.lock.json): `31fa5abdddab20cd2cf7452f61b63f0fa6758c64`, Apache-2.0 | BLOCKED historical runtime; no approved evaluation binary closure or measured adapter comparison. Never required to run Sniffer Dog. |
| Linux audit / auditd | Required only for audit-based independent-comparison acceptance profiles; not native core | [recorded upstream/license inventory](../../integrations/interoperability/upstreams.lock.json): `280cb8c07c431439ff85771988b9656780b8ef2b`; userspace GPL-2.0, library LGPL-2.1 | PARTIALLY VERIFIED. Institution-provided package must have its own version/hash/license provenance. Same host/root is still shared. |
| bpftrace / ftrace / A3S / OBI | Optional comparison or diagnostic instruments | [tool inventory](../../validation/external/TOOL_INVENTORY.md), individual external status reports | EXPERIMENTAL or BLOCKED by profile. Several old notes retain abbreviated revisions or unpinned clone/build commands; not acceptable release pins. |
| LangGraph | Required only for the LangGraph evaluation/demo profile | [existing requirements](../../integrations/agents/requirements.lock): langgraph 1.2.11 and dependencies, exact versions | PARTIALLY VERIFIED. This requirements file has version pins but no artifact hashes; it is not a complete offline supply-chain closure. |
| Agent Zero | Optional P0-048-G candidate | [framework lock](../../integrations/real_agents/frameworks.lock.json): `ff2a5b9c9c4e490ba38dd7c313e779510bb2071a` | PARTIALLY VERIFIED installation/capture; retained business task fails. Its broad requirements installation is not a fully hash-closed build. |
| DeerFlow | Optional P0-048-G candidate | Same framework lock: `f79debed59ca6b1a31628e6b5ce55c8507793a4c`; upstream frozen uv flow | BLOCKED business acceptance after failed native capability; source pin is not acceptance. |
| OpenHands SDK | Optional P0-048-G candidate | Same framework lock: `46b1fa5cb91ada17e6ec938c7e8624a4fa19fa98`; upstream frozen uv flow | BLOCKED business acceptance after failed native capability. |
| Public local model/runtime | Required only for genuine model-driven demonstrations | [model preparation](../../validation/enterprise/prepare_local_model.py), retained model-pin records; newer evidence-assistant `model.lock.json` on #8 | PARTIALLY VERIFIED profile-specific weights/runtime hashes. Not a mandatory Sniffer Dog dependency. |
| SoftHSM2 | Test backend for PKCS#11 suite | [HSM manifest](../../aip-standalone/aip-hsm/Cargo.toml): cryptoki 0.12.1; [CI install](../../.github/workflows/ci.yml) | TESTED historically; CI OS package floats. Neither mandatory for ordinary verification nor hardware key custody proof. |
| PostgreSQL | Optional service storage feature; not native offline verifier | [service manifest](../../aip-service/Cargo.toml), PostgreSQL CI job | TESTED historically; customer database/backup/RLS operation not qualified. |
| Falco, Cedar, OpenFGA, AGNTCY, CycloneDX, Langfuse | NOT REQUIRED | Inspected upstreams and external evaluation documents | No reason to add them to the privileged runtime merely because they appear in research. |

## Reproducibility gaps found without installing anything

1. **Toolchain/actions/images are not fully immutable.** CI uses `stable`,
   `ubuntu-latest`, action major tags and unversioned Cargo tooling installs.
   The service Dockerfile uses `rust:1-slim` / `debian:bookworm-slim`; security
   CI downloads Trivy's `main` installer. Root Cargo checksums do not close
   those inputs. Source: [CI](../../.github/workflows/ci.yml),
   [security](../../.github/workflows/security.yml),
   [Dockerfile](../../deploy/docker/Dockerfile).
2. **Container and archive profiles differ.** The real-agent builder accepts
   a digest-pinned Python base, but apt packages and some framework dependency
   installs are not completely hash-locked. Helm requires approved image
   digests; that is a configuration gate, not evidence of a validated image.
3. **License inventory is not a release SBOM.** Existing upstream records
   retain license file hashes, but all binaries, OS packages, model artifacts
   and redistributed notices must be tied to the exact P0-048 bundle. No
   blanket license clearance is claimed. Native source is
   `LicenseRef-Proprietary`; integrating open-source adapters does not change it.
4. **Nested builds are separate.** The four baseline Cargo lockfiles are
   explicitly inventoried. Root `cargo test --workspace` covers 58 members,
   not every nested Aegis/validation/import package.
5. **Offline operation still needs proof.** Bundled native executables can
   avoid runtime downloads, but vendored rebuild inputs, destination dynamic
   libraries, external trust approval, clean install/uninstall and actual
   egress denial remain release gates. Namespace isolation alone proves none
   of these.

The complete per-file hashes and dependency declarations are in
[inventory.json](../../validation/p0_048/iteration-001/inventory.json).
Existing pins are retained as evidence; no upstream upgrade is silently applied.

## Upstream research boundary

The official [SPIRE repository](https://github.com/spiffe/spire),
[JWT-SVID specification](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md),
[GenAI conventions](https://github.com/open-telemetry/semantic-conventions-genai)
and [Tetragon repository](https://github.com/cilium/tetragon) were consulted.
JWT-SVID validation requires signature/algorithm, audience and expiry checks;
bearer replay is not eliminated by those alone. GenAI conventions define
telemetry fields, not an independent witness. Tetragon supplies event
observation and enforcement capabilities; only isolated observation evaluation
is in this mission. These facts do not validate any local adapter. The existing
immutable repository pins above remain the inspection references for follow-up.
