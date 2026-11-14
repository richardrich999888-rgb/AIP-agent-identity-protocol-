# P0-050 open acceptance requirements

**14 November 2026 IST — current checkpoint:** Cargo discovery full CI and coverage now PASS; current 940948e main CI also passes. Static classification of four HIGH Helm findings is complete: all four conditions persist in the current optional template and remain `needs_review`, not suppressed or remediated. Security and release remain NOT READY. [Evidence and next experiment](evidence/p0-050-helm-triage/README.md).

**13 November 2026 IST — Cargo discovery continuation:** `049f015` replaces internal-layout guessing with Cargo executable reports. Fresh relocated edge 12/12, offline verifier 6/6, parser 2/2 and scoped lint/format pass. Full hosted CI/coverage pending; no weakened assertions or skipped tests. [Evidence](evidence/p0-050-cargo-discovery/README.md). Release NOT READY.

**13 November 2026 IST — current continuation:** prior full debug/release tests passed, but coverage failed the strict empty-environment test. Source `9d25aa4` supplies an explicit empty environment at final exec; the isolated negative regression now passes in normal and instrumented builds. Hosted scoped CI passes 314 Rust / 267 Python; coverage blocked by 12 aip-edge sibling-binary-discovery failures before sandbox tests; release NOT READY. [Evidence and acceptance](evidence/p0-050-exec-env/README.md).

**Latest S2 launch continuation (12 November 2026):** source `2408c6e` requires a positive child exec event and real terminal status before signing. Hosted teaching CI passes 313 relevant Rust and 267 focused Python tests, including all 32 sandbox tests. Downloaded original signed records and tamper/wrong-key controls replay offline; teaching 12/12 + 26/26 remains intact. Local ptrace is refused (EPERM): 288 pass / 18 fail retained, no skipped tests. Full workspace CI remains pending; Security retains four HIGH historical Helm findings. Release NOT READY; no complete demo or enterprise acceptance. [Originals and checkpoint](evidence/p0-050-launch/README.md).

Earlier checkpoint (historical; superseded only for the scoped launch item):

**Concurrent source preserved:** `5bc0c5f` added a general teaching-session
scoreboard while S2 evidence was being finalized. Its source and teaching CI
are present, but this S2 iteration does not independently accept its new trust
bindings. The evidence checkpoint is appended on top; source results for
`6764c7e` remain separately attributed. No shared commit was overwritten.

**Completed source CI:** `6764c7e` passes full CI `43212899569`, including
3,593 debug and 3,595 release test passes, plus coverage. Existing exclusions
are enumerated in the S2 checkpoint; no new sandbox skips. Teaching and harness
contracts pass. Security `43212899116` still fails four HIGH retained-render
findings. These statuses refer to the implementation, not a future docs head.

**S2 continuation:** the stable namespace-refusal and CI discrepancy has a
bounded repair at `6764c7e`, with 24/24 sandbox tests and retained signed CLI
checks passing locally and on teaching CI. The full local scoped total is 289;
197 focused Python checks and the unchanged 12/26 teaching gate pass on CI.
See the [checkpoint](evidence/p0-050-sandbox/README.md) for full-workspace status.
Per-launch acknowledgement remains open, so S2 and release are not complete.

**Release NOT READY — iteration 1, 12 November 2026.** Only the general compiler
applicability defect is closed in bounded scope. No production, certification,
regulatory approval or customer-deployment claim follows from these tests.

The replay follow-up adds external trust/byte pins and recomputes signed frozen
cases without accepting diagnostic PASS fields. That narrow gap is closed
(375 Python / 187 native tests locally; full CI assessed separately). It does not
close any lifecycle, sandbox, expert identity/custody, pack, sensor, deployment
or rehearsal requirement below.

| Priority / dependency | Exact incomplete requirement | Required proof to close |
|---|---|---|
| P0 current | Launch acknowledgement: hosted scoped checks pass; full CI pending; local tracing unsupported | Retain original failures and successful hosted signed archives; complete full CI. Executable hash-to-exec race remains separate. |
| P0 security | Four HIGH retained-render Trivy findings; source/config/evidence classification | Supported native sensor design and justified remediation while retaining original evidence; no blanket excludes or sensor disablement |
| P0 C1 | General answered-session command, precise failed-row/B1 question linkage | Source/question/draft/candidate hashes bound; no stale answers; meaningful independent scoreboard with all attacks passing |
| P0 C2 | Complete signed expert approval with identity, tenant, ID/version, source, suite, time and scope | Unauthorized/cross-tenant, changed source/suite, revoked/expired approval, rollback and supersession attacks; never unapproved activation |
| P0 D5 | Portable signed knowledge pack and local import policy | Real CLI export/import; byte/signature/tenant/authority/source/version/floor/model/approval/validation/import-authorization rejection; inactive default |
| P0 D6/F | Signed every-answer receipts, replay defense, authenticated local REST/MCP and examples | Independent offline signature verification; tenant/clearance/role failures; runnable Python and TypeScript examples |
| P0 A3b/D1–4 | Verified model/runtime staging, live model drafting, meter, held-out variations, model swap | Exact model/runtime hashes and licence provenance; real local inference; missing/hash-mismatched weights refused; model-dependent capability revalidated after swap |
| P0 E/G | Complete localhost teaching UI and six acts on two synthetic sectors | Vendored assets, roles/clearance, explicit uncertainty; live or visibly recorded scenes; no implicit approval/activation |
| P0 sensor | Complete trustworthy Sniffer Dog acceptance on supported hosts | Honest, undeclared, bypass, tamper, interruption and restart; original signed archives; process/socket identity, missing coverage, short-lived/unbound events and BPF/kernel limitations exposed |
| P1 OVERLAY provenance | All six recorded W4/W5 demo commits unavailable here | Authorized original working copy, or reviewed fresh replacement with newly generated evidence; no invented historical source |
| P1 CBOM | Quantum X-ray planted-weakness classification and CBOM acceptance | Ground truth, unknown/hybrid cases, false positives/negatives, retained original outputs; no unsupported safety classification |
| P1 PQ | Live **PROOF OF CONCEPT** unchanged-application overlay | Identity and downgrade refusal, actual PQ/hybrid handshake proof, captures before/after, identical application binary hashes |
| P1 kit | Complete Profile A founder laptop / Profile B Linux evaluation kit | AIRON/Sniffer/OVERLAY binaries, verified models/runtime, pinned local dependencies, documents/assets, verifier, public trust and complete dependency/licence/provenance manifests |
| P1 offline boundary | No-download install/execution; initial-netns sensor-safe isolation | Genuinely separate clean-machine test, missing/tampered component rejection, independently enforced egress boundary, captures and interface counters |
| P1 W6.1/W6.3 | Offline benchmark and second-machine reproduction | Existing wrapper audited, pinned datasets/models/runtime/baseline, raw results, comparison script, error analysis/limitations; separate hardware labels |
| P1 commercial | Investor plug → teach → liar; regulated-enterprise and defence sequences | Actual live duration, NOT READY on missing dependencies, labelled recordings; complete banking/defence plus manufacturing/healthcare modes retained from P0-049 |
| P1 rehearsal | Ten consecutive passes per required mode; twenty W3 | Exact SHAs, host/model hashes, statuses, signed evidence/verifier, captures, CPU/RSS/runtime, failed attempts/recovery; reset count on failure; W3 fresh install every fifth run |
| P1 external acceptance | Independent evaluator can install and verify without original runtime or internet | Immutable supported kit, independent trust anchors, original evidence and reproducible acceptance; connected CI is insufficient |

The applicability fix affects freshly compiled artifacts only. Any deployed old
capability requires explicit recompile/revalidation/new approval/supersession;
there is no automatic migration. Lexical context is not general semantic intent
recognition. Synthetic engineer signatures do not establish a real expert's
identity. No packet captures, live model weights, fresh native sensor run or
external clean-machine installation were obtained by this bounded iteration.

Useful independent work can proceed when resources are absent, but dependency
gates cannot be bypassed. See the [scored roadmap](../strategy/P0-050-EXECUTION-ROADMAP.md)
for the next bounded item; see the [report](P0-050-FINAL-REPORT.md) for fresh
versus historical evidence and the retained failures.
