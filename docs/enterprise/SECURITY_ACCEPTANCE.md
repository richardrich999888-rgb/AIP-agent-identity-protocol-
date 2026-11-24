# Security acceptance and evidence meanings

## 2026-11-02 update — runtime source `3e6c179`

**Assignment status: PARTIAL; engineering validation, with acceptance gates still open.**
This dated section is the current snapshot at
`3e6c1794000fa23006ef623722e37700e49582b7`. The historical text after the divider
is preserved unchanged; its references to “current” describe its own recorded
source and date. Keep PRs #6, #7 and #8 in draft until the remaining criteria
are satisfied.

| Evidence/acceptance layer at this snapshot | Result and limit |
| --- | --- |
| Real OPA + isolated SDK/Collector component controls | Mac and Linux 21/21 PASS, no skips; policy/peer and most record fixtures are controlled test data |
| Governance-enabled genuine Linux execution | Run `41432473155` missing-assets refusal, positive, interruption, recovery and all clients PASS at `3e6c179` |
| Independent replay of the new governance originals | **PASS**, [retained replay](../../validation/enterprise/results/GOVERNANCE_20261102/genuine-3e6c179/preservation-index.json); artifact `13136100222`, service SHA256 `48ccc9525cade552b8eb28874e0c786b96a4b00024defd8b17e7cd9fbab6a505` |
| Previously independently replayed core | All three profiles PASS at `1968d45`; historical proof, not a substitute for new-source replay |
| Agent Zero genuine invoice task | Executed/FAIL at `0b34730`; original signatures/all-six task coverage PASS; exit/report/bound-file gate FAIL |
| Agent Zero GitHub task; DeerFlow/OpenHands business tasks | NOT_STARTED after their separate capability failures; no accepted patch/business output |
| Complete exact-source CI/security review | **16 PASS / 2 FAIL**; two scanner failures remain open, as described below |
| Separate collector administration/installed customer service | UNVALIDATED |

OPA evaluates the actual controller-measured peer and permitted read scope
before the existing AIP signer. Its decision, policy hash and decision-ID link
are unsigned controller application records; an allow result cannot bypass
the unchanged signer or signature/receipt/reconciliation rules. OpenTelemetry
exports a delayed batch of controller-operation timestamps and approved IDs,
hashes and status fields after workload cleanup. It does not create model
spans, signed kernel evidence or an authorization authority. The Collector is
stopped and reaped before complete final-file verification. Only the original
verified `records.json`, `collector-config.json`, `collector-spans.jsonl` and
`telemetry-report.json` are published from its private staging area; raw
Collector logs and failed/unvalidated output remain private. Unknown fields,
duplicate JSON keys, extra tails, wrong correlations or timestamps refuse
publication.

The 21-test component gate includes actual OPA execution and real SDK/Collector
roundtrips, plus explicit policy/peer/signing fixtures and controlled negative
mutations. It is not itself a genuine agent task, proof of measured peer
identity, signed kernel evidence or independent custody. In the genuine
controller, operation timestamps are captured at the actual operations, then
exported after cleanup; they still remain unsigned application telemetry.
Unknown or unavailable kernel/task evidence remains unknown. A delivered trace,
OPA allow, valid archive signature or historical Active state cannot promote a
failed task or missing observation interval.

The Collector publication gate rejects unapproved attributes/fields, duplicate
JSON keys at every depth, extra lines/spans, wrong nonces/trace parents and
modified timestamps. A controlled late-tail failure preserves private original
bytes and publishes no Collector files. No free-form Collector log is included
in the public component package. See the
[scope statement](../../validation/enterprise/results/GOVERNANCE_20261102/SCOPE.md)
and [OPEN_SOURCE_GOVERNANCE.md](OPEN_SOURCE_GOVERNANCE.md).

The complete 18-check component/security suite at runtime source `3e6c179`
finished **16 PASS / 2 FAIL**. The separate genuine core workflow passed; its
guarded PR Agent Zero task was skipped. [Exact CI provenance and counts](../../validation/enterprise/results/GOVERNANCE_20261102/ci-3e6c179/registry.json)
retain every skipped/ignored or blocked scope separately. Gitleaks still reports
217 findings and Trivy four HIGH findings in the historical enabled Helm
render. Their result objects match the retained previously reviewed records;
no detector result is waived or rewritten. Cargo audits retain the inherited
`RUSTSEC-2026-0097` exception documented in `deny.toml`; no new exception was
added, and an audit pass is not an unqualified security clearance.

Independent administration still requires a separately controlled Linux
workload host and collector Linux host/trust domain, approved public anchors,
collector signing-key custody and durable retention. One disposable runner's
root/kernel/GitHub administration remains trusted. Actual installed fanotify
service qualification, installer/startup/restart/uninstall and recovery,
logical sub-agent delegation, concurrency/soak and matched overhead,
institutional key/identity operations, customer deployment and regulatory
acceptance remain unvalidated. Remote-model credentials and protected
production telemetry endpoints are configuration gates if those routes are
selected; public local inference and the completed local component checks do
not require those secrets.

## Historical record preserved below

The following text is retained unchanged from its recorded historical revision.


Each property has an independent status. Signature validity does not establish
live coverage, logical-agent identity, a completed bank transaction, independent
administration or production approval.

| Property | What can establish it | What remains outside that proof |
| --- | --- | --- |
| Evidence integrity | Existing signatures/chains plus independently retained checkpoint | Host honesty, complete ground truth and institutional custody |
| Observation coverage | Signed health for the actual interval, adequate sensors, clock and loss/integrity gates | Effects outside that coverage or unsupported event classes |
| Process attribution | Boot ID, PID, start ticks, executable and namespace evidence | An in-process logical sub-agent or tool-server-to-agent delegation |
| Logical attribution | Independently authenticated orchestration/delegation evidence | Agent logs alone; timestamp proximity alone |
| Gateway request verification | Signed expectation plus signed receipt of actual gateway-received canonical parameters | Business effect or tool-server truth |
| Business outcome | Authoritative business-system evidence and domain acceptance | A Forwarded receipt, model recommendation or kernel packet |
| Collector custody | Separately controlled host/key/storage evidence | Two accounts or containers on one kernel |

The new composition reuses the existing `ReconciliationResult` semantics.
`ghost.tool.invoke.v1` is an application-level action. Request-document
agreement may coexist with kernel `CannotProve/ActionEvidenceUnavailable`.
The output must keep those results distinct. Expected-side completeness stays
unknown unless a separately valid signed completeness record establishes it.
Missing authority is not automatically unauthorized execution.

## Required cases

| Case | Required behavior and retained evidence |
| --- | --- |
| A: authorized action | Genuine model chooses allowed read; independent authority signs; gateway verifies actual parameters; original kernel records/coverage and supported finding retained |
| B: parameter mismatch | Controlled changed request reaches actual gateway under original signed decision; signed Refused receipt and document divergence, with no extra upstream read |
| C: missing authorization | Evaluate captured records without expectation/completeness; explicit inability to prove; no unauthorized classification |
| D: observer interruption | Actual authorized interruption; retained signed health cannot cover the later missing-observation interval, and recovery does not backfill. A historical Active state is not coverage of that gap. Typed regressions/RBI history are distinct from a genuine-workload interruption |
| E: missing receipt | Kernel result cannot acquire application-level proof; tool boundary is NotEvaluated/NoReceipt |
| F: wrong process | IdentityDivergence only after valid signatures, process/claim and integrity prerequisites; insufficient linkage stays CannotProve |
| G: tamper/truncation | Altered signed expectation/receipt/verdict, interior mutations, duplication/reordering/corruption rejected; valid prefix/suffix deletion requires independent checkpoint |

Unit fixtures are ordinary predicate tests and must remain labeled. Offline
mutations of actual captured records are controlled negative verification;
they do not assert that the genuine agent performed an adversarial action.
Live interruption and actual parameter-mismatch stimuli identify their
controller origin explicitly. Exact executed results belong in the retained
run report; this table is not itself a passing result.

## Isolation checks

The agent must be unable to read authority, gateway or collector keys. Its
gateway credential must have only read/execute permission, with default broad
roles revoked. Actual attempts to administer the gateway and bypass it through
the direct tool endpoint must fail. Measured inference uses only the pinned
local model and permitted local endpoints. Linux capabilities are dropped and
no-new-privileges is asserted. Host root/kernel remains trusted in the local
profile. An external collector is required for the stronger compromise claim.

The final retained signed health record is authoritative. A previous Active
record cannot replace a later degraded record. Backwards health chronology is
rejected, and the collector must seal the frozen final batch head before export.
Neither signed archive tails nor adverse health records may be trimmed to
produce a favorable result.

## Executed status

Retained genuine run `40755309307` at `a6da6e5` establishes A's actual model,
authority, receipt, process binding and task-window checks. Its canonical kernel
finding remains `CannotProve/ActionEvidenceUnavailable`; full authorization TTL
is `WindowNotCovered`. B ran an actual gateway mismatch/refusal stimulus.
C, E and G passed controlled verification of those same captured bytes.
Latest exact-source 8d38d77 workflow 40875323001 passed all three complete
Linux profiles: A positive, D actual probe termination before a fresh model
workload, and a fresh-capture recovery. All clients/browser and separate offline
verification passed each actual bundle. D retained a final signed Active health
record with old coverage; the evaluator correctly returned NoReference and
CannotProve/WindowNotCovered. Fresh recovery does not establish same-key daemon
restart continuity. F's predicate and real pidfd/procfs reference-control regressions pass; a genuine daemon-observed,
correctly claimed wrong-identity workload has not been established. No claim
registration API or fabricated claims are introduced to hide that limitation.

The actual controller checks cover distinct UIDs, zero bounding capabilities,
no-new-privileges, signing-key access denial, permitted model/gateway traffic,
direct-tool/external egress denial and forbidden gateway administration. This
uses Unix permissions and UID firewall rules, not a filesystem allowlist or a
separate kernel administrator. Audit agreement is supporting same-kernel
evidence. Original failure archives and complete checkpointed tails are retained.

F's actual reference-control test is
`aip-edge::end_to_end::t7_and_t13_an_observation_of_another_instance_is_excluded_not_downgraded`,
passed in debug and release by CI 40847427070/job123358253851. It spawns real
workload/observer processes and independently measures another PID under explicit
controller-supplied Claimed metadata, requiring IdentityDivergence with zero
correlated records. The private observer pipe is not claimant authentication.
Its temporary signed evidence is deleted by the existing test, so CI logs are
component execution evidence, not a retained same-run Sniffer F package. The
probe has no trusted claim-registration interface and placement derivation is
not connected to this same-run reconciliation path. Filling that boundary
requires reviewed full-instance/agent/decision linkage, not editing observations.


The subsequent e4cd07d core positive and interruption paths passed, but its
recovery lacked a Forwarded receipt and remains failed. A controlled pinned
CPEX reproduction exposed UUID-local context loss on manager replacement.
The integration now uses owned request-global handoff and a one-use durable
post-callback transition, preserving cache invalidation and authorization.
Missing state remains CannotProve. The subsequent 8d38d77 core repeat in
workflow 40875323001 passed all three profiles, including fresh recovery, all
enterprise clients and separate offline verification; it does not reconstruct
the older missing receipt. See [the execution record](END_TO_END_VALIDATION.md)
for original failed evidence, the successful fresh repeat and the separate
Agent Zero timeout.

At execution source `8d38d77fa3bf1c3b0670f584feaf75f34bf69a07`, all three
core profiles and independent offline verification **PASS**. All five
component-CI workflows / fourteen jobs also passed that source, confirmed
2026-10-29 16:04 UTC. Final-HEAD CI remains required after the
documentation/evidence-only snapshot. The fourteen-job component-CI success
excludes the guarded PR manual-task skip and the three separately failed manual
Agent Zero tasks. Six model-service requests in the latest attempt establish
neither accepted tool execution nor software-task completion, full coverage,
three-framework validation or a swarm.

Read-only GitHub API inspection at 2026-10-29 12:43 UTC, rechecked at 12:44 UTC,
found no repository secret names. The named validation environment still had no
protection rules or branch restriction and allowed administrator bypass. The
local-model tasks used no model API credential; a remote model would require
approved restricted secrets/configuration, tested hard spending and egress
controls, and actual task acceptance. This does not resolve separate collector
administration, institutional keys or installed-service acceptance.


The subsequent d5c39dd publication check passed all fourteen component-CI jobs
and the complete three-profile genuine core workflow, with separate offline
verification. Its originals and exact CI register are linked in
[the later publication and diagnostic record](END_TO_END_VALIDATION.md#later-publication-check-and-diagnostic-repair).
A further bounded incremental Agent Zero diagnostics repair passes 60 portable
component tests; fresh image smoke and genuine task acceptance remain separate.
The original 900-second deadline and security/evidence controls are unchanged.
Derived image size/origin annotations were corrected without changing signed
records or historical outcomes. The existing Security workflow was restored
from its inactivity pause; its next-revision scans and all exact-final-HEAD CI
still require actual results. Separate collector custody, successful framework
repairs/swarms and installed-customer qualification remain incomplete.
