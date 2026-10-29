# Combined recovery validation

Validation candidate: `9ed1662af95ce83bbbee69c9387d5bd638713575`.
The first successful genuine profiles were on `42d0d96`; both source-specific evidence sets and intervening failures are preserved.
Draft recovery PR: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/12
Target: `integration/vanian-enterprise-service-delivery`, verified head `a933fdc327e8744dc8a8441ea3d5b2d75063b91f`.
Latest integrated PR #8 snapshot: `d6eb35e4de11fbec10953e5ed00bd934f1cc02d7`.
No main merge, force push, credential publication, or security-check bypass was performed.

## Concrete repairs

1. Reviewed normal merges preserve the enterprise deployment registry and the newer run authorization/evidence interfaces. Combined OpenAPI and console-disconnect tests exercise both interfaces.
2. The model failure compared Ollama's rewritten 1023-byte compatibility/GC manifest with the approved original 860-byte manifest. Runtime, original manifest, configuration and model weights retained their approved hashes. Provisioning now checks bounded immutable metadata before downloading the runtime, selects only the reviewed content-addressed v2 manifest, and still hashes and sizes every complete model blob. Exact original positive and changed/unreviewed artifact negatives are retained in `model-review/`.
3. The same-run TypeScript smoke check imports the built customer JavaScript. The workflow builds that package before use; installed distributions must expose both deployment and run methods.
4. Live sensor collection previously read a batch close before draining sources, allowing a connector exec and its earlier scheduler counterpart into adjacent batches. Actual signed failed-run pairs reproduced the strict collector refusal. The live path now uses a bounded queue, one anchored monotonic cutoff with 50 ms delivery holdback, pair-aware conservative frontier, contiguous emitted sequence numbers and actual published ACK windows. Read/cap/clock/late-record failures withdraw coverage. The collector's matching rule and signed formats are unchanged; old signed failures remain unchanged.
5. SQLite bootstrap transaction context did not close its connection, retaining a mounted-workload reference. Bootstrap now commits and closes explicitly. Public failure retention keeps only named evidence and public trust/checkpoints.
6. SPIRE's join-token CLI emits a token line followed by a warning. Parsing now accepts exactly one bounded token line and excludes warnings; errors redact token content.
7. The enterprise clean-wheel check inherited `PYTHONPATH=sdk/python`. Package metadata made pip skip installation, followed by an import failure from the temporary directory. Isolated child Python processes now install the actual wheel and require the imported module to live beneath that temporary environment. A real offline wheel/source-metadata regression reproduces this failure without isolated mode.
8. Precise Linux import/helper/clone3 guards preserve portable security checks and Linux behavior. Full-workspace macOS compilation still cannot qualify Linux-only `ghost-demo` execution; supported Linux results are recorded separately.
9. Optimized NEXORA test fixtures could create two health references in the same millisecond. The uncited-health structural test now creates an explicitly different signed timestamp; a separate same-coordinate/wrong-key test retains cryptographic refusal. Production verification and signature semantics remain unchanged.
10. A subsequent SPIRE run enrolled but exhausted a nominal six-second fetch loop. Its discarded stderr prevents an exact cause attribution. Bounded readiness now allows 60 seconds with monotonic deadlines, daemon liveness checks, bounded child calls and safe classified diagnostics. Independently exported trust, JWT signature, audience and subject checks remain mandatory.
11. A subsequent genuine run completed API/Python/MCP/TypeScript checks but failed within the coarse console-browser stage. The old private diagnostics were excluded from public artifacts, so its exact failed operation is unknown. Browser progress now uses fixed substages and safe error classes, and explicit bounded waits cover the console's existing request budget. Exact rendered JSON, credential clearing, disconnect and all authorization/CSP checks remain required.

Principal changed source paths:

- `validation/enterprise/{prepare_local_model,same_run_validation,verify_sdk_packages}.py` and `run_typescript_smoke.ts`
- `validation/enterprise/{same_run_controls_test,test_combined_contracts,test_sdk_package_verifier}.py`
- `validation/enterprise/{run_client_smoke,test_console_progress}.py`
- `aip-standalone/aip-observe/src/{probe,linux,perf,sched,socksend,sockstate}.rs`
- `aip-standalone/aip-probe/src/{sensors,main}.rs` and `tests/live_sensors.rs`
- `aip-standalone/{aip-observe,aip-collector}/tests/live_cutoff.rs`
- `aip-standalone/aip-core/src/execution_binding.rs` and Linux placement guards
- `aip-standalone/aip-nexora/tests/{binding,verify}.rs`
- `integrations/interoperability/examples/spire_jwt_live.py` and its regression test
- `.github/workflows/{same-run-validation,enterprise-integration,interoperability}.yml`
- Combined `docs/enterprise/openapi.yaml`, `validation/enterprise/openapi_contract.py`, and `integrations/enterprise-console/app.js`.

The complete source/evidence history, including preserved upstream changes, is in Git. Historical PR #8 runs are not promoted into evidence for this candidate.

## Validation provenance

Current candidate workflows:

- Genuine same-run execution: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983596
- Workspace CI: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983581
- Enterprise/package validation: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983680
- Interoperability: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983593
- RBI rehearsal: https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40854983605

All three genuine profiles passed again on9ed1662: observed, interrupted and fresh recovery. `same-run-qualified/` retains their exact public originals and verification; `same-run-candidate/` retains the first successful42d profiles. Parent trust/checkpoints, browser screenshots and independent native re-verification are source-specific. Positive and recovery runs have actual signed task coverage and process-instance matches, while preserving `CannotProve / ActionEvidenceUnavailable`; interruption preserves `CannotProve / WindowNotCovered`. Gateway agreement never upgrades that action verdict.

All seven source-specific workflows completed successfully. Complete supported-Linux workspace debug: **3304 passed,0 failed,10 ignored**; release: **3306 passed,0 failed,8 ignored**. Formatting and exact locked workspace/all-target/all-feature Clippy with warnings denied passed. Explicit PostgreSQL controls: **14 passed**, distinct from14 default-feature ignored tests. Both the repaired health-binding case and new same-reference/wrong-key negative passed in debug and release. See `ci/candidate-9ed1662-workspace.json` for complete target counts and provenance.

Enterprise/package validation and all three interoperability jobs passed. Both Debian packages built and the actual Linux binary staging lifecycle passed; `live_clean_host_installation=false` is retained. SPIRE enrollment, OPA/mTLS,47 adapter tests,25 Microsoft receipt tests,9 SPIRE controls,4 browser diagnostic controls and compiled/installed SDK checks passed. Exact receipts are in `ci/candidate-9ed1662-{enterprise,interoperability}.json`. Historical failures remain failed in their original receipts.

`runtime-controls/` retains 130 focused passing tests, strict Mac and Linux cross-target lint, and explicit source/hash scope. `portable-controls/` retains 17 passing model/cleanup, SPIRE and combined-contract controls plus two additional password-policy/error-sanitization checks. The repeated local integration harness passed 19/19 checks on the candidate (`candidate-local-checks/`). Test groups overlap with workspace runs and must not be summed into a fabricated aggregate.

Earlier combined source `edfd0a12de6df7d63c63dbb6d1ce8d2ce0a8132c` passed supported Linux debug (3291 passed, 0 failed, 10 ignored), release (3293 passed, 0 failed, 8 ignored), and the explicit 14 PostgreSQL tests; that evidence is retained in `ci/edfd-workspace.json`. Its genuine same-run failed strict coverage, enterprise failed the wheel-provenance check, and interoperability failed the SPIRE token step. These earlier results are diagnostic evidence, not the candidate's final result.

The older3078/161/8 report is separately classified in `ci/initial-161-classification.json`:107 proc-stat ENOENT and35 ProcessNotVisible cases, one namespace-inode case, one socket-task-anchor case,15 missing-SoftHSM cases, an allowed-program exit127 and an XDP EPERM-versus-EACCES expectation. Its exact tested tree/host/job are not recorded, so these cannot all be relabelled environmental or current-source defects. The current complete supported-Linux suites provide the new qualification; the old failure records are preserved.

Historical PR11 runs40741903535 and40742409670 had no runner/steps and exact payment/spending-limit annotations (`ci/initial-audit.json`); they were not Rust test failures. Current candidate runners executed all checks. No security check, branch protection or cryptographic condition was disabled to change those results.

## Claim and infrastructure limits

All banking material is synthetic and read only. A signed gateway receipt attests the gateway request, not financial settlement. A valid authorization is separate from execution. A successful software harness may legitimately retain `CannotProve` where action evidence is unavailable; interface success must not be renamed action agreement.

Hosted observer/authority keys are outside monitored agent UIDs. The hosted probe and collector both run as root; this harness does not enforce a probe-to-collector key-access boundary. Valid signatures therefore do not qualify the required independent collector custody. The controller's separately retained public anchors/checkpoints are used for software verification. They are ephemeral CI operator anchors, not independently approved institutional trust. Shared-kernel/root custody remains **local isolation**, not separate administration.

No approved clean customer Linux/systemd hosts or independently administered collector domain were supplied. Debian build/staging evidence cannot qualify clean-host enrollment, authority provisioning, service operation, upgrade/recovery or evidence-retaining uninstall. Independent institutional/bank assessment remains external. The final matrix has11 scoped software gates `PASS` and4 gates `BLOCKED`: collector key boundary, customer installation, separate administration and independent bank acceptance. No gate is self-approved beyond its stated evidence scope.

Durable failed-send resend and forward realtime clock-discontinuity detection remain outside the batching fix. The diagnostic-salvage I/O-failure path has not been qualified. No universal completeness, production readiness, independent penetration test, hardware-backed custody or bank acceptance claim follows from these engineering tests.
