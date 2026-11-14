# P0-048-A — architecture and branch inventory

Organisation: VANIAN Technologies Pvt. Ltd.
Review date: 12 November 2026 (Asia/Kolkata).
Iteration: 001. Scope: architecture/dependency inventory and baseline selection.

## Decision and scope

Use `fix/vanian-end-to-end-green` at
`4d0ce1e32c8dedde4e3a930abc2becf1f56b864e` as the **combined enterprise
audit baseline**, and target the draft audit PR at that branch. It preserves
the service-delivery and interoperability work with the combined recovery
fixes. This is the last broad combined acceptance baseline established by the
evidence inspected here, **not a production-qualified release or the newest
commit in the repository**. No inspected head combines every later integration
and satisfies P0-048 release acceptance.

All 37 advertised remote branch heads were fetched. All were searched for an
existing P0-048 checkpoint; none was found. Ten relevant trees were inventoried,
including all six requested branches and all seven requested PR heads.
The [immutable revisions](../../validation/p0_048/iteration-001/revisions.json),
[machine inventory](../../validation/p0_048/iteration-001/inventory.json),
[ancestry matrix](../../validation/p0_048/iteration-001/ancestry.json), and
[GitHub PR/CI observations](../../validation/p0_048/iteration-001/provider-review.json)
are retained. PR metadata was not treated as proof of runtime correctness.

The baseline has 2,877 tracked entries, 58 root workspace members and 72 Cargo
manifests including nested/nonmember crates. The inventory reads every tracked
Cargo manifest/lockfile, Python and JavaScript dependency manifest, workflow,
container definition, service unit, deployment file, and recognised upstream
pin/license policy in the ten trees. It records file hashes, parsed dependency
declarations, external command references and source/test counts. Human review
followed the critical source and evidence paths below. **This is not a manual
line-by-line proof of every source file or an exhaustive vulnerability audit.**
Runtime validation remains explicitly separate from structural inventory.

## Branch and PR reconciliation

Full revisions, base/head refs, PR descriptions, and retrieved workflow results
are in the provider record. Short revisions in this table refer to those exact
objects, not moving branch aliases.

| Branch / PR | Head | Observed state and disposition |
|---|---|---|
| `main` | `872dbf3` | 116 tracked entries; does not contain the modern combined enterprise path. Not a baseline for this work. |
| `integration/snifferdog-complete-enterprise-validation`, #8 | `ab16159` | Later native framework, OPA/OTel and Qwen capture work. Six retrieved workflows succeeded; Security failed. Does not contain PR #12 ancestry or its complete service-delivery/interoperability directories. Preserve and reconcile deliberately. |
| `feature/vanian-agent-governance-interoperability`, #9 | `9d52c68` | Optional external identity, A2A/ADK/Microsoft/OPA adapters and native authority/receipt comparison. Four retrieved workflows failed; older report describes runner-allocation blockage. Its implementation is inherited by #12. |
| `integration/vanian-enterprise-service-delivery`, #11 | `a933fdc` | Deployment registry, packages and customer onboarding; four retrieved workflows failed. Repaired in #12. |
| `fix/vanian-end-to-end-green`, #12 | `4d0ce1e` | Selected audit baseline. Seven returned PR workflows succeeded, including full CI, enterprise, interoperability and genuine observed/interrupted/recovery profiles. Four institutional/deployment gates remain BLOCKED. |
| `feature/syntriass-runtime-v02` | `2883da7` | Descends from #12; adds sovereign/runtime research. No PR-triggered runs returned for this exact head by the connector. That API does not enumerate every trigger and absence is not a failure or pass. |
| `feature/wow-demos` | `6ad92ae` | Descends from #12; demo/kit/rehearsal work exists. CI, harness and demo workflow succeeded; Security failed. Does not contain #19. |
| `fix/ci-userns-sandbox-tests`, #16 | `c39fc1f` | Namespace preflight refuses known setup unavailability before consuming authority. Functional CI passed; Security failed. A successful preflight is not proof that the later tool actually started; see G19. Sovereign runtime change, not a Sniffer Dog sensor repair. |
| `fix/chart-probe-seccomp`, #17 | `a0b1045` | Probe pod `RuntimeDefault` seccomp and test; also carries #16's change. CI, harness and enterprise passed; Security failed. Runtime compatibility still requires a cluster. |
| `fix/aip-edge-distinct-corroboration`, #19 | `9b81098` | Edge observer + verifier socket deduplication, plus #16 cherry-pick. CI and harness passed; Security failed in Trivy. Review completed before any proposed socket change. Not yet integrated into this audit branch. |

The provider workflow lookup is limited to PR-triggered runs and its first page.
Seven successful returned #12 workflows do not imply that every possible
security/deployment job ran. The inspected #12 CI jobs include formatting,
strict Clippy, debug/release tests, PostgreSQL, Python SDK, RED suite,
audit/deny and coverage. The historical
[acceptance matrix](../../validation/final_acceptance/acceptance.json) records
3,304 debug passes/10 ignored and 3,306 release passes/8 ignored on candidate
`9ed1662af95ce83bbbee69c9387d5bd638713575`; those overlapping totals are not
added. Candidate-to-publication changes are documentation/retained evidence,
not a new production implementation. No fresh Rust execution is claimed here.

For newer security failures, actual job results were fetched: #19 fails Trivy;
#8 fails Trivy and Gitleaks. Existing scanner findings/exceptions must be
reviewed in their own scope, not erased from old evidence to obtain green CI.

## Classification

`IMPLEMENTED` means source exists; `TESTED` means the stated scoped result has
evidence; `PARTIALLY VERIFIED` means some required guarantees remain unproven;
`EXPERIMENTAL` means a research/evaluation path; `MISSING` is relative to the
inspected scope; `BLOCKED` identifies an unexecuted gate and its prerequisite;
`NOT REQUIRED` means unnecessary for the native core. None means certification.

## Native execution-assurance path

| Component | Classification | Code and test/evidence anchors | Limit |
|---|---|---|---|
| AIP types, signatures, capabilities, delegation and revocation | TESTED, historical baseline | [core](../../aip-standalone/aip-core/src/delegation.rs), [authority](../../aip-standalone/aip-authorize/src/authority.rs), [authority regressions](../../aip-standalone/aip-authorize/tests/authority_reference.rs), [CI evidence](../../validation/final_acceptance/ci/candidate-9ed1662-workspace.json) | Institutional issuer enrollment and independent key custody are separate. |
| Process measurement, executable digest, PID/start/boot identity, pidfd anchoring | PARTIALLY VERIFIED | [probe](../../aip-standalone/aip-observe/src/probe.rs), [container tests](../../aip-standalone/aip-observe/tests/container_identity.rs), [blind-spot tests](../../aip-standalone/aip-observe/tests/blind_spots.rs) | Polling is weaker than anchored measurement. A short-lived event can be observed without conclusively binding it. Logical agent identity is not established by PID/UID/ancestry. |
| Scheduler, cgroup, socket-state/send, connector, fanotify and packet observation | PARTIALLY VERIFIED | [runtime](../../aip-standalone/aip-observe/src/runtime.rs), [live cutoff tests](../../aip-standalone/aip-observe/tests/live_cutoff.rs), [health](../../aip-standalone/aip-observe/src/health.rs), [same-run originals](../../validation/final_acceptance/same-run-qualified/originals/files.json) | Coverage depends on the specific kernel, permissions, namespace, clock and loss counters. Six configured sensors in a hosted profile do not qualify every installed profile. |
| `/proc/net` edge corroboration | PARTIALLY VERIFIED; known defect on baseline | [join](../../aip-standalone/aip-observe/src/probe.rs), [effect assessment](../../aip-standalone/aip-edge/src/effect.rs), [#19](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/19) | Repeated rows may inflate corroboration. #19 repairs two consumers; the shared join remains unchanged. Counts are not independent security domains. |
| Authenticated confidential probe-to-collector transport | TESTED, historical baseline | [Noise transport](../../aip-standalone/aip-transport/src/confidential.rs), [frame signatures](../../aip-standalone/aip-transport/src/auth.rs), [negative/loopback tests](../../aip-standalone/aip-transport/tests/loopback.rs) | Nonces/sequences prevent the tested replay forms. Durable failed-send recovery and rotation operations still need qualification. |
| Collector signing, custody and continuity | PARTIALLY VERIFIED | [allow-list](../../aip-standalone/aip-collector/src/authority.rs), [sink](../../aip-standalone/aip-collector/src/sink.rs), [restart tests](../../aip-standalone/aip-observe/tests/restart_continuity.rs), [custody review](../../validation/final_acceptance/infrastructure/probe-key-boundary.md) | Hosted probe and collector share root; signing-key inaccessibility from the probe is not enforced there. |
| Signed archives and offline verification | TESTED, scoped historical evidence | [verifier](../../aip-standalone/aip-observe-verify/src/verify.rs), [CLI](../../aip-standalone/aip-observe-verify/src/cli.rs), [external-checkpoint verification](../../validation/final_acceptance/same-run-qualified/verification/summary.md) | Valid signed subwindows do not establish complete capture. Approved external anchors/checkpoints are necessary for completeness and origin claims. |
| Reconciliation and supported effects | TESTED, scoped historical evidence | [reconciler](../../aip-standalone/aip-reconcile/src/reconcile.rs), [action derivation](../../aip-standalone/aip-reconcile/src/action.rs), [adversarial tests](../../aip-standalone/aip-reconcile/tests/adversarial.rs), [delegation tests](../../aip-standalone/aip-reconcile/tests/delegation_attribution.rs) | Default/refusals preserve `CannotProve`. The retained positive core run still has `ActionEvidenceUnavailable`; interruption has `WindowNotCovered`. |
| Native gateway receipts and expected-authority comparison | TESTED, scoped historical evidence | [gateway](../../aip-standalone/aip-mcp-gateway/src/lib.rs), [comparison](../../aip-standalone/aip-mcp-gateway/src/comparison.rs), [received-call tests](../../aip-standalone/aip-mcp-gateway/tests/received_call.rs) | A signed gateway request is not proof that the OS effect or business outcome occurred. |
| Independent mechanism comparison | PARTIALLY VERIFIED | [corroborator](../../aip-standalone/aip-corroborate/src/lib.rs), [retained comparisons](../../validation/external/corroborate/README.md), [audit observer](../../validation/airi/observers/audit_observer.py) | One-to-one matching is separate from native verdicts; audit and native sensors still share host/kernel administration. |
| Placement, lineage and delegation attribution | PARTIALLY VERIFIED | [placement](../../aip-standalone/aip-reconcile/src/placement.rs), [lineage tests](../../aip-standalone/aip-reconcile/tests/lineage_edges.rs), [placement tests](../../aip-standalone/aip-reconcile/tests/placement_attribution.rs) | Concurrent in-process logical agents cannot be disambiguated from process identity alone. |
| NEXORA, external anchors, incidents, ledger, SIEM and AIBOM | IMPLEMENTED, component-tested in baseline | [NEXORA](../../aip-standalone/aip-nexora/src/lib.rs), [anchor](../../aip-standalone/aip-anchor/src/lib.rs), [AIBOM](../../aip-standalone/aip-aibom/src/lib.rs), [workspace](../../Cargo.toml) | Additional evidence consumers do not increase provenance automatically. Operational custody/retention and external schema conformance remain separate. |
| PKCS#11 HSM interface | TESTED against SoftHSM in historical CI | [HSM crate](../../aip-standalone/aip-hsm/Cargo.toml), [CI](../../.github/workflows/ci.yml) | Software module testing is not hardware custody qualification. |
| Containment, enforcement, interlock and warrants | EXPERIMENTAL for this mission | [workspace boundaries](../../Cargo.toml), [containment](../../aip-standalone/aip-containment/src/lib.rs), [enforcement](../../aip-standalone/aip-enforce/src/lib.rs) | Not enabled or deployed by P0-048-A; production enforcement needs explicit approval. |
| UAS/robotics/industrial/space/enterprise/conformance profiles | EXPERIMENTAL profiles | [workspace](../../Cargo.toml), [conformance](../../aip-standalone/aip-conformance/src/lib.rs) | Native model consumers, not independently qualified real-world deployments. |
| OrbitalTrust import and Aegis workspace | PARTIALLY VERIFIED / EXPERIMENTAL respectively | [import boundary](../../orbitaltrust-accountability/README.md), [Aegis manifest](../../aegis-quantum/Cargo.toml) | `ot-sentinel`, core and feed conformance are members; `ot-mcp-gateway`/`ot-verifier` require the missing `ot-pqc`. Aegis is a separate workspace, not the Sniffer Dog build. |

The root manifest and machine inventory enumerate every crate, including CLI,
demo and test-only members not given separate product rows above.

## Existing enterprise and upstream integrations

| Integration | Classification | Evidence and exact scope |
|---|---|---|
| `agents` / LangGraph synthetic workflow | PARTIALLY VERIFIED | [agent subject](../../integrations/agents/agent_subject.py), [retained original archives](../../integrations/agents/results/sealed/offline_verify.txt). Real graph/tool execution is distinct from free-running agent/business acceptance. |
| `evidence-api`, service routes, Python/TypeScript SDKs | TESTED, scoped baseline | [upload adapter](../../integrations/evidence-api/upload_observations.py), [service runs](../../aip-service/src/runs.rs), [combined contracts](../../validation/enterprise/test_combined_contracts.py). Customer custody and production admission remain separate. |
| `enterprise-console` and read-only evidence MCP | TESTED, scoped baseline | [client smoke](../../validation/enterprise/client_smoke.py), [MCP integration](../../integrations/evidence-mcp/requirements.lock). A UI/API read cannot validate an unobserved action. |
| `service_delivery` | PARTIALLY VERIFIED | [onboarding](../../integrations/service_delivery/service_onboard.py), [bundle tests](../../integrations/service_delivery/tests/test_onboarding_bundle.py). Packages/staging exist; clean customer installation is BLOCKED. |
| SPIFFE native workload comparison | PARTIALLY VERIFIED | [comparison](../../aip-standalone/aip-spiffe/src/lib.rs), [identity tests](../../aip-standalone/aip-spiffe/tests/identity.rs), [historical live profile](../../validation/external/spiffe/README.md). Parsed assertions/registry exports are not automatically cryptographically verified SVIDs. |
| JWT-SVID and configured issuer JWT bridge | PARTIALLY VERIFIED | [identity verifier](../../integrations/interoperability/src/vanian_interop/identity.py), [negative tests](../../integrations/interoperability/tests/test_boundaries.py), [real SPIRE CLI harness](../../integrations/interoperability/examples/spire_jwt_live.py). Pinned keys, audience, expiry and trust domain checked. Revocation remains UNKNOWN; X.509 verification, rotation history and signed process-to-logical-agent binding are incomplete. |
| OPA, ContextForge and signed MCP gateway | PARTIALLY VERIFIED | [policy adapter](../../integrations/interoperability/src/vanian_interop/policy.py), [ContextForge](../../integrations/mcp-gateway/vanian_contextforge.py), [native receipt archive](../../validation/interoperability/results/20261028-receipt-join/report.json). Authenticated policy results and gateway signatures have different provenance. |
| Google ADK / A2A | PARTIALLY VERIFIED | [ADK](../../integrations/interoperability/src/vanian_interop/google_adk.py), [A2A](../../integrations/interoperability/src/vanian_interop/a2a.py), [validation](../interoperability/VALIDATION_REPORT.md). Live model/tool work exists, but full TCK, distributed replay and same-run independent logical-agent binding are not established. |
| Microsoft governance / ACS receipts | PARTIALLY VERIFIED | [receipt bridge](../../integrations/interoperability/src/vanian_interop/microsoft_receipts.py), [offline tests](../../validation/interoperability/test_microsoft_receipt.py). Content agreement for the untransformed integer-JSON profile does not authenticate a self-declared policy source. |
| NVIDIA OpenShell / NeMo | EXPERIMENTAL / BLOCKED runtime | [governance adapter](../../integrations/interoperability/src/vanian_interop/governance.py), [gaps](../interoperability/PRODUCTION_GAPS.md). An external event adapter is not a validated sandbox integration. |
| Later `governance` OPA/OTel | PARTIALLY VERIFIED, other branch | [exact source](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/tree/ab161597ea05d52813619d9962f8956811d2daf1/integrations/governance), [latest scoped report](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/ab161597ea05d52813619d9962f8956811d2daf1/docs/enterprise/END_TO_END_VALIDATION.md). Actual OPA and SDK/Collector checks exist. Telemetry is delayed controller metadata using `aip.*` attributes, not complete GenAI model/tool span correlation. |
| Tetragon | BLOCKED historical evaluation; optional | [build diagnosis](../../validation/external/tetragon/BUILD.md), [recheck](../../validation/external/tetragon/RECHECK.md). No accepted matched-event/overhead adapter found. Historical host lacked kprobes; current-host capability is not inferred from it. |
| A3S observer / A3S external evaluation | EXPERIMENTAL | [status and coverage](../../validation/external/a3s_observer/STATUS.md), [interference](../../validation/external/a3s_observer/TRACEPOINT_INTERFERENCE.md), [evaluation](../../validation/external/a3s/EVALUATION.md). Tracepoint interference and missing exit coverage are recorded. |
| Linux audit, bpftrace, ftrace | PARTIALLY VERIFIED external instruments | [audit](../../validation/external/auditd/STATUS.md), [comparison](../../validation/external/corroborate/README.md). Mechanism independence and administrative independence must be stated separately. |
| OBI / Langfuse / earlier OTel collector | BLOCKED historical evaluations | [OBI](../../validation/external/obi/STATUS.md), [Langfuse](../../validation/external/langfuse/STATUS.md), [earlier OTel](../../validation/external/OTEL.md). Earlier OTel installation blockage is superseded only for the newer branch's specific controller profile. |
| Falco, Cedar, OpenFGA, AGNTCY, CycloneDX | NOT REQUIRED for native core; inspected/proposed integrations | [inspected upstreams](../../integrations/interoperability/upstreams.lock.json), [remaining integration scope](../interoperability/PRODUCTION_GAPS.md). Source/license inspection is not installed interoperability. |

## Framework and demonstration evidence

| Framework/demo | Outcome against P0-048 qualification | Evidence |
|---|---|---|
| LangGraph | PARTIALLY VERIFIED; P0-048 adversarial task acceptance still pending | Latest Qwen evidence assistant has 93 signed batches and recorded separate offline checks, but those checks apply to its own declared profile: [original report](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/ab161597ea05d52813619d9962f8956811d2daf1/examples/local-evidence-agent/results/linux-observation/REPORT.md). |
| Agent Zero | FAIL for retained invoice task; Click task NOT_STARTED after capability failure | [latest dated outcomes](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/ab161597ea05d52813619d9962f8956811d2daf1/docs/enterprise/END_TO_END_VALIDATION.md): signed coverage did not supply missing file/report/task acceptance. |
| DeerFlow | FAIL native capability; business task BLOCKED/NOT_STARTED | Same dated report; real HTTP/model activity was not native tool/task success. |
| OpenHands | FAIL native capability; business task BLOCKED/NOT_STARTED | Same dated report; the model HTTP rejection is retained, not replaced with a mock. |
| Lying-agent demo on `feature/wow-demos` | PARTIALLY VERIFIED; P0-048-K/L acceptance not met | [README](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/6ad92ae78806546948874812dc8e6161d24d9d67/demos/lying-agent/README.md) and [rehearsal result](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/6ad92ae78806546948874812dc8e6161d24d9d67/demos/lying-agent/evidence/acceptance-2026-11-07/acceptance.json): ten successful lying/control summaries exist, but those runs' signed archives were not retained. One separate complete archive does not replace them. Unsynchronized-clock operation and scripted authority limits are explicit. |

## Deployment and acceptance

Linux tar/Debian packaging, systemd units, installer controls, Kubernetes
templates, read-only clients and air-gap instructions already exist. The
[packaging regressions](../../validation/enterprise/test_packaging.py) use
fixture ELF headers and must not be reported as clean-host installation.
The [air-gap procedure](../../deploy/enterprise/airgap/README.md) explicitly
does not supply a vendored OS/library/dependency bundle. The newer wow branch's
kit is a separate runtime/demo profile and is not proof that all P0-048
sensor, custody, firewall and archive gates pass.

Fresh checks and every failed invocation are in the
[iteration record](../../validation/p0_048/iteration-001/README.md). No dependency
was installed, sensor enabled, upstream substituted, production source changed,
main branch changed, or old archive rewritten by this iteration.

Next: P0-048-B, review/port #19's minimal change and close the shared socket-row
gap with deterministic negatives and genuine churn evidence on a supported host.
Keep the independent comparator and all evidence thresholds unchanged.
