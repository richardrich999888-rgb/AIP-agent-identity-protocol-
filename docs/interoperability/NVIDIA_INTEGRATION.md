# NVIDIA integration

OpenShell adapter: IMPLEMENTED (parser contract tests). Genuine OpenShell workload: BLOCKED in this environment. NeMo Toolkit and Guardrails: NOT_EXECUTED.

At the inspected OpenShell commit, enforcement includes sandbox supervisor and gateway controls with filesystem, syscall and network boundaries; it is not merely an application guardrail. Public extension surfaces include Python/Go/TypeScript/Rust SDKs and OCSF JSON export. The repository describes a 0.1.x release cadence; that does not establish production support for this VANIAN adapter.

`openshell_event` accepts the documented OpenShell Gateway/Sandbox Supervisor producer names, event UID, class UID and timestamp. It preserves the complete native action/status/disposition, container UID and all policy/lifecycle metadata. An event UID is not a sandbox UID. Policy version and process ancestry are retained only when present in the native record; absent fields stay absent.

Imported JSON is UNVERIFIED_IMPORT. No producer signature or collector identity is inferred from its filename or product field. An institution must authenticate the export channel, bind sandbox→process using boot/start-time/executable evidence, preserve policy revisions, and separately establish Sniffer Dog coverage. Denial records do not prove absence of all execution. Agreement between OpenShell and Sniffer Dog may still share a compromised host-kernel failure mechanism.

The managed host has no container runtime, usable BPF capabilities or kernel BTF. We did not install a sandbox onto customer infrastructure, simulate its runtime output or call fixture OCSF a live workload. A real isolated deployment must exercise allowed and denied file/network operations, lifecycle/restart, policy updates, missing coverage and sensor degradation before promotion.

NeMo Guardrails supplies application governance decisions and configurable rails. Any future hook must preserve input/output/tool rejection and inconclusive evaluation without converting them into OS facts. NeMo Agent Toolkit already provides framework/tool/workflow instrumentation and telemetry; a future correlation bridge should consume those identifiers rather than duplicate profiling. No executable adapter was added merely to increase integration count.
