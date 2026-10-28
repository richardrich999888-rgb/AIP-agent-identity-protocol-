# Enterprise implementation inventory

Assessment date: **2026-10-28**. The implementation branch was created from
`3a029aec83fa2aa57ea8bb0a2c28968f3be037a4`, preserving the RBI baseline
`0991fb1eed1234403c1ff9683d010797ea073d39`. This inventory distinguishes source,
current executable checks and historical Linux evidence. A tested library or
temporary-directory installer does not qualify an institutional deployment.

The final enterprise milestone is **incomplete**. Clean supported Linux
installation, actual two-host administrative separation, a current real-agent
kernel run joined to independent signed authorization, a validated Kubernetes
runtime, institutional performance measurement and external assessment remain
open. No certification, RBI approval or production readiness is asserted.

## Branch audit and preservation

The following is the observed local/ref snapshot. Counts come from
`git rev-list --left-right --count REF...3a029aec`; they mean commits unique to
the named ref / unique to the selected base, not changes to signed formats.
The local default branch was not modified.

| Ref | Exact commit | Unique ref / base | Disposition |
| --- | --- | --- | --- |
| `codex/rbi-demo-preflight-2026-10-27` | `0991fb1eed1234403c1ff9683d010797ea073d39` | 0 / 18 | Entirely preserved in the selected base |
| Initially observed `codex/snifferdog-real-agent-swarm-validation` | `3a029aec83fa2aa57ea8bb0a2c28968f3be037a4` | 0 / 0 | Selected base; includes signed placement attribution, AIBOM/spend and RBI safeguards |
| Later observed `codex/snifferdog-real-agent-swarm-validation` / `origin/codex/snifferdog-real-agent-swarm-validation` | `f025a57911f7daf473cdfdcbf98d2f911df2534e` | 2 / 0 | Concurrent advancement reviewed and merged into this feature at `d747a9fd28d1a03be1051658ea65ae70e2dd13a6` |
| Local `main` | `cd660f6bd6269b664ca8fdbf9601a8d24c399127` | 0 / 365 | Old local ref; not the integration base |
| `origin/main` | `872dbf375838cff464eb019488c63d948015e9b8` | 0 / 348 | Ancestor; preserve default branch |
| `codex/val-ladder-sync` | `ae46a3a2f4e28821facd19706d0e99c299c42651` | 29 / 365 | Divergent; unique commits not copied or blindly merged |
| `codex/aip-v4-accountability` | `73bf70cf9e687d1b47709a8a6e8ea9c8eaa610e7` | 7 / 365 | Divergent; unique commits not copied or blindly merged |
| `origin/claude/codebase-production-readiness-wm6idp` | `4ee39f359430277a48c34b957609104d3cf781f6` | 0 / 112 | Ancestor |
| `origin/claude/aip-security-architecture-audit-zpf9b3` | `4ee05ea694a4ddf6de1f0f7477e0b19b31628711` | 0 / 26 | Ancestor |
| `origin/claude/autonomous-accountability-skills-16-30` | `27610ad9d7e3c192afe4f4c859c903403758ee89` | 0 / 187 | Ancestor |
| `origin/claude/skill-25-implementation-xbz0t3` | `061cebc975d81c8126d5f66d96f5384d11be0620` | 0 / 9 | Ancestor |
| `origin/claude/vanian-audit-maturity-addendum-n5ysvd` | `e05ec3b2eb5989ed63e7c1c489e119f35c68d2b8` | 0 / 113 | Ancestor |
| `origin/codex/accountability-test-gaps-2026-10-20` | `65eb9e6accdc7dce0893864bcbd6b2cfa9a7035c` | 0 / 22 | Ancestor |
| `origin/import/orbitaltrust-accountability-layer` | `6cc439f190161ba28e76d46cea1901de8dd527ea` | 0 / 347 | Ancestor; its evidence-format coexistence boundary remains |

No `release` branch or tag was present in this local ref set; this does not
claim that no remote release exists. The existing release implementation is
`.github/workflows/release.yml`. It distributes the service and existing
packet/verdict verifiers; it does not yet distribute this new runtime package.

The two concurrent swarm commits are `faf5ed0` (real-agent launchers and a
conservative observation harness) and `f025a57` (placement-parser Linux lint
fix). Both were preserved by the feature-branch merge before final tests;
their historical validation is not relabeled as a new runtime capture.

## Required document reconciliation

The assessment inspected `STATUS.md`, `AUDIT_CORRECTIONS.md`,
`docs/PRODUCTION_READINESS.md`, `docs/pilot/BFSI_PILOT_PLAN.md`,
`docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`, `deploy/pilot/README.md`,
`deploy/pilot/RUNBOOK.md`, and `integrations/mcp-gateway/README.md`, together
with their source and tests. These documents are not all synchronized:

- `AUDIT_CORRECTIONS.md` is a dated correction log. Its old service maturity
  statements do not override the current authenticated service source.
- `docs/PRODUCTION_READINESS.md` still lists missing metrics/runbook and old
  release/storage states. Newer source includes metrics, a pilot runbook,
  PKCS#11 mechanisms and storage controls. Their existence does not establish
  a complete production installation or hardware-HSM qualification.
- The pilot README's old transport table describes challenge signatures,
  while its later instructions and actual daemons use mandatory Noise NK
  around authenticated signed frames. The source has no plaintext daemon
  fallback.
- The pilot runbook mentions checking a collector health endpoint. The real
  collector writes signed health archives; it has no HTTP health endpoint.
- Historical status numbers and sealed archives document their recorded
  development runs. They are not current feature-branch or institution-host
  validation results.

Use `VALIDATION_REPORT.md` for the current execution record and
`PRODUCT_READINESS.md` for the current deployment conclusion.

## Mandatory component classification

The statuses below apply to the stated scope, not every possible behavior of
the component. `BLOCKED_BY_INFRASTRUCTURE` identifies an unexecuted acceptance
gate, never a skipped test counted as a pass.

| Required component | Classification | Source and executable boundary |
| --- | --- | --- |
| A — customer runtime sensor | `PARTIALLY_IMPLEMENTED` | Existing `aip-probe` drives actual `aip-observe` Linux sensors; new `deploy/enterprise/linux/package.py` packages/configures it. Sixteen deterministic packaging tests pass, including staging installation/uninstall. Clean Linux installation, sensor opens under installed service identity and workload coverage are `BLOCKED_BY_INFRASTRUCTURE`. |
| B — enterprise evidence collector | `PARTIALLY_IMPLEMENTED` | Existing `aip-collector::{config,authority,sink}` uses approved transport keys, mandatory confidential transport, wrapped evidence-key custody, persistent continuity and fsynced signed archives. Deployment/restart/loss acceptance on independent hosts is `BLOCKED_BY_INFRASTRUCTURE`; no durable probe resend buffer or bounded collector worker pool is implemented. |
| C — AIP authorization/identity integration | `IMPLEMENTED_BUT_NOT_INTEGRATED` | Reuse `aip-authorize::DecisionPoint`, signed `ExpectedExecution`, `aip-core` delegation and `aip-placement`; library tests exist for scoping/placement/authorization. Customer business authorization and a genuine real-agent end-to-end signed expectation/observation/verdict join remain integration work. |
| D — first-party MCP receipt signer | `IMPLEMENTED_AND_TESTED` for the bounded Rust receipt path | Existing `aip-mcp-gateway::issue_receipt`, `check_header_body`, `aip-airi::compare_tool_boundary`; the enterprise adapter invokes the existing Rust core through `aip-tool-receipt`, preserving the ToolReceipt format. Current gateway-specific evidence and the limits of `Forwarded` are recorded in the validation report. |
| D — actual IBM ContextForge integration | `IMPLEMENTED_AND_TESTED` for the pinned evaluation profile | Actual pinned deployment, real MCP upstream, receipt verification, replay/restart/concurrency/failure and signed-intent mismatch checks executed under `integrations/mcp-gateway/`. See exact run artifacts and metadata-transport limits in the gateway validation result; no bank production compatibility is implied. |
| E — enterprise evidence REST API | `PARTIALLY_IMPLEMENTED` | Extends `aip-service` and the existing stores with tenant-scoped read models, Reader scope, historical observation-archive admission/verification and API-derived operational UI. Agent/workload summaries are packet-derived, not a complete independently registered host inventory. Current coverage/off-host separation/business outcome are not established by archive integrity. |
| E — PostgreSQL provisioning/hardening | `PARTIALLY_IMPLEMENTED` pending real DB execution | `deploy/sql/schema.sql` now exactly matches the existing `store/pg.rs` table schema, including `signed_artifacts`. Hardening adds its SELECT/INSERT-only grants, forced tenant RLS, append-only UPDATE refusal and legal-hold guard. One source-parity test passes; real negative `storage_controls` tests require PostgreSQL and are not represented by compilation alone. |
| F — Python customer SDK | `IMPLEMENTED_AND_TESTED` for the read-only retrieval subset | `sdk/python/vanian` uses actual `/v1` routes, bearer callback, TLS verification, finite timeouts, bounded GET retry/reads, redacted structured errors and pagination. Actual service interoperability is separate from local transport negatives; no SDK call supplies kernel evidence. |
| F — TypeScript customer SDK | `IMPLEMENTED_AND_TESTED` for the read-only retrieval subset | `sdk/typescript` uses the same REST routes and native Node fetch with redirect refusal, timeout and response bounds. It is a private/source package, not a published registry release or another cryptographic implementation. |
| G — optional MCP evidence server | `IMPLEMENTED_AND_TESTED` for per-client stdio read access | `integrations/evidence-mcp/server.py` exposes eight allowlisted read/computation tools to a process using a tenant-bound Reader credential; actual official-client/service authorization smoke is recorded separately. No HTTP transport, shell, collector control or signing-key operation is exposed. |
| H — Linux installation tooling | `IMPLEMENTED_AND_TESTED` only for package/control-flow behavior | Deterministic tar/file manifest, independently anchored digest verification, ELF-target guard, no shell config sourcing, safe role-separated staging install and software-only retained-data uninstall. Real Linux/OS/libc/service qualification remains `BLOCKED_BY_INFRASTRUCTURE`. |
| H — Kubernetes | `PARTIALLY_IMPLEMENTED` | Opt-in Helm templates default to no runtime pods, require pinned images and a separate-administration assertion, and retain the collector PVC. Helm rendering, image build/scanning, CNI and kernel/node behavior have not executed here. No supported Kubernetes distribution/runtime combination is qualified. |
| H — air-gapped delivery | `PARTIALLY_IMPLEMENTED` | Offline binary package/verification and dependency-transfer procedures exist. No complete signed OS dependency bundle, vendored-build exercise, installed air-gap test or new runtime release signature is supplied by these scripts. |
| Qualified independent assessment / bank approval | `BLOCKED_BY_EXTERNAL_APPROVAL` | An institution and its qualified assessor must commission and perform this; source tests cannot self-certify it. |
| Production HA, measured institutional overhead and complete multi-framework banking demonstration | `MISSING` as validated product capabilities | No result is inferred from package structure, synthetic data, an old run or the existence of a framework adapter. |

## Actual symbol and evidence paths

| Requested name | Actual implementation | Verification/reuse path |
| --- | --- | --- |
| `aip-probe` | `aip-standalone/aip-probe/src/{main,config,sensors,keyfile}.rs` | `tests/live_sensors.rs` needs a capable Linux host; non-Linux `SensorSet::open` refuses. |
| `aip-collector` | `aip-standalone/aip-collector/src/{main,config,authority,sink,noise_key}.rs` | `tests/e2e.rs`; runtime uses `CollectorKey::production` and `CollectorRuntime::start_with_custodian`. |
| `aip-transport` | `aip-standalone/aip-transport/src/{auth,codec,confidential,client,server}.rs` | `tests/{confidential,loopback}.rs`; fixed `Noise_NK_25519_ChaChaPoly_SHA256`, allow-list, per-session challenge, signatures, sequence and 4 MiB frame bounds. |
| `aip-reconcile` | `aip-standalone/aip-reconcile/src/{reconcile,placement}.rs` | Signed expectation/evidence/coverage-aware engine; delegation and placement tests preserve uncertainty. It is not a ready banking business-transaction adapter. |
| `aip-observe-verify` | `aip-standalone/aip-observe-verify/src/{main,verify,report,cli}.rs` | Offline signed batch/health verification under externally supplied observer anchor; signature integrity does not prove the truth of compromised host input. |
| `aip-verify` | `aip-standalone/aip-verify/src/main.rs` | Existing EvidencePacket/signed-export verifier; keep separate from observer-archive verification. |
| `aip-lineage` | `aip-standalone/aip-reconcile/src/bin/aip-lineage.rs` | Declared by the **aip-reconcile** package; verifies archive before deriving observed parent/child edges. |
| `aip-sentinel-feed` | `aip-standalone/aip-sentinel-feed/src/bin/aip-sentinel-feed.rs` | Converts verified observer records into the existing sentinel file interface; sentinel is first-party integration, not independent corroboration. |
| `aip-mcp-gateway` | `aip-standalone/aip-mcp-gateway/src/lib.rs` and `src/bin/aip-mcp-gateway.rs` | Existing canonicalization/signing/comparison core; `src/bin/aip-tool-receipt.rs` is the adapter bridge, not a second Python signer. |
| `aip-service` | Package **airon-aip** in `aip-service/`; binary `airon-aip`, container install name `aip-service` | Reuse existing auth/evidence/authority/artifact/storage paths; current route contract is `docs/enterprise/openapi.yaml`, not invented `/api/v1` aliases. |

## Current tests versus historical Linux evidence

Executed during this implementation:

- `python3 -B validation/enterprise/test_packaging.py`: **16 passed**.
  Uses fixture ELF headers and temporary directories. It does not execute the
  daemons, systemd, Helm or a Linux kernel sensor.
- `python3 -B validation/enterprise/test_agent_harness.py`: **3 passed**.
  Exercises the actual LangGraph harness build block under controlled Cargo
  outcomes, including stale binaries and failed diagnostics. It is not a
  real-agent rehearsal.
- With pinned MCP 2.3.0 and Python 3.12,
  `PYTHONPATH=sdk/python .local/enterprise-venv/bin/python -B validation/enterprise/test_client_boundaries.py`:
  **9 passed**. Localhost HTTP responses and controlled MCP handlers verify
  malformed transport errors, cursor validation, tenant/role refusal, rate,
  input and complete serialized-output limits. These tests produce no kernel
  observation evidence.
- `python3 -B validation/enterprise/test_sql_provisioning.py`: **1 passed**.
  Compares manual SQL DDL against the service's actual schema. It does not
  execute the database's refusal controls.
- `bash -n integrations/agents/run.sh` and `git diff --check`: passed.

The full current Rust, actual service, gateway and official MCP-client
execution results belong in `VALIDATION_REPORT.md`. Tests needing PostgreSQL,
hardware HSM, systemd Linux, a real kernel or Helm are not silently upgraded
from unexecuted/ignored to passing.

Historical source-controlled evidence lives under
`validation/pilot_e2e/results/sealed/`, `integrations/agents/results/sealed/`
and `validation/external/{corroborate,spiffe}/results/`. `STATUS.md` records a
LangGraph 1.2.11 development run on Linux 6.18.44, observed process events and
offline archive verification. Those artifacts preserve their original
protocol/run dates; they are not overwritten or represented as a new run.

Current host: Darwin. Docker CLI presence does not provide a running Docker
engine or a privileged Linux node. No supported Linux distribution/kernel,
container runtime, Kubernetes combination or clean Linux installation was
qualified by this implementation session. Helm and local PostgreSQL server
binaries were not found in the inspected environment.

## Remaining runtime and trust limits

1. `aip-probe/src/main.rs` explicitly has no durable resend buffer; a failed
   send can lose that cycle's observations. No observation is fabricated to
   repair collector downtime. Account for uncovered intervals.
2. `aip-collector/src/main.rs` spawns a thread per accepted TCP connection.
   Read timeout and new systemd resource limits do not establish a bounded
   worker pool, validated backpressure, HA or a tested throughput envelope.
3. The live collector selects the wrapped-file custodian through
   `CollectorKey::production`. `aip-hsm` has a PKCS#11 mechanism and SoftHSM
   tests, but the collector daemon exposes no implemented HSM backend switch.
   Bank hardware integration, certification, ceremony and key backup remain
   unvalidated.
4. Probe sensor collection is host-wide; there is no per-business-agent
   process filter. Fanotify is mount scoped and AF_PACKET can be interface
   scoped. Kernel process/container identity is not automatically framework
   identity or proven attribution of in-process concurrent agent actions.
5. Independent off-host custody is a real deployment/administrative boundary.
   An installer confirmation, two containers or a valid signature cannot
   establish it alone. The probe's transport credential is not an
   evidence-signing key; the gateway, observer and authorization keys remain
   different authorities.
6. The historical observation API verifies admitted snapshots using
   institution-configured tenant/observer anchors and the actual Rust
   verifier. It establishes neither live stream continuity across separate
   uploads nor current coverage, truthful host input, off-host separation,
   a real-agent authorization join or banking transaction completion.
7. The Linux package checksum establishes package integrity only when the
   digest arrived through an independently authenticated approval channel.
   A neighboring checksum is not origin authentication. The new runtime
   package is not already a signed/published release.
8. A full kernel attacker can defeat on-host observations. Cross-sensor
   divergence and foreign-gate checks narrow specific failures; they do not
   make the kernel trustworthy. Missing authorization alone is not an
   unauthorized-action finding. Missing/blinded coverage is uncertainty.

The immediate RBI path remains `validation/rbi_demo/run.sh` on an authorized
Linux demonstration host, with synchronized clock, root/required capabilities,
tracefs, actual daemon builds, signed control/interference/recovery evidence
and evaluator-side offline verification. Its library-level acts remain
labeled separately. No observer-only packaging test closes that gate.
