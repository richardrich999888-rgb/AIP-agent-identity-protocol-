# P0-050 strategic gap matrix

Review: **12 November 2026, iteration 1**. Release: **NOT READY**.
This iteration closes the bounded applicability defect in the compiler. It does
not close W3, the offline kit, pilot qualification or independent acceptance.
Implementation: `ef3d9d434e5ed55e5994331abc91c03833f997ff`.
Evidence: [`../assurance/evidence/p0-050-iteration-1/`](../assurance/evidence/p0-050-iteration-1/).

## Ground truth and provenance

Freshly fetched AIP source and provider metadata were compared with source,
tests and retained records. OVERLAY was inspected through its authorized remote
branch/tree/file interface; this was **not a full local OVERLAY checkout or test
run**. A transient AIP promisor-object fetch failed with HTTP 503; the kit file
was subsequently read from its exact remote blob. No divergent branches were
merged. Historical results below were inspected, not rerun by this iteration.

| Source | Inspected revision | Observed state / evidence |
|---|---|---|
| AIP PR #13, `feature/wow-demos` | `6ad92ae78806546948874812dc8e6161d24d9d67` | Draft. Historical CI/demos/contracts pass; Security fails. Master loop, rehearsal ledger and kit audited. |
| PR #14, model resolver | `86f21056f2b4d7a1f3b84a642eef8e2d862629d4` | Open. Historical CI/contracts pass; Security fails. Not a current model-weight installation. |
| PR #16, sandbox correctness | `c39fc1f0431ddfaffa2d62199874e18e92087969` | Open. Historical CI/contracts pass; Security fails. Teaching branch still differs; integration must be reviewed. |
| PR #17, probe hardening | `a0b1045b80dbcd5aac33910361a4e67cfdd2f739` | Open. Historical CI/enterprise/contracts pass; Security fails. Chart hardening is not native-host acceptance. |
| PR #19, socket corroboration | `9b8109884455e37a61ca7abef1bb7d78a39a860d` | Open. Historical CI/contracts pass; Security fails. PR #20 has the selected socket fix, not a blanket branch merge. |
| PR #20, sensor correctness | `61dd73013d02ea7869de104d953f330098df1c32` | Draft. Provider now reports native qualification, same-run assurance, RBI, contracts and main CI success; Security failure. Not rerun locally here. |
| PR #21, teaching, starting head | `925432b181ea194565fa855b9d3d3c734723354b` | Draft. Baseline teaching fails fa-3; main CI has three sandbox failures; Security fails. All retained rather than waived. |
| PR #21, this implementation | `ef3d9d434e5ed55e5994331abc91c03833f997ff` | Teaching workflow `43169880420` and contracts pass. Security's Trivy job fails; main CI repeats the three sandbox failures. Audit/deny, PostgreSQL, SDK and RED jobs pass. |
| `integration/snifferdog-complete-enterprise-validation` | `ab161597ea05d52813619d9962f8956811d2daf1` | Retained archive inventory and earlier Qwen/native reports exist. Their production labels do not establish the P0-050 gates. |
| OVERLAY approved inspected base | `eccb66886d1f6b0b751909b6743d7e731e8061fb` on `claude/cbom-dashboard-ai-analysis-uujp2g` | 24 remote branches returned; no `feature/wow-demos`. CBOM/identity/gateway code exists. Original W4/W5 demo directories absent. |

All six recorded OVERLAY demo/fix revisions (`d1adc90`, `92c8b02`, `07d0319`,
`6072578`, `13c0fb1`, `3d63f95`) again return **422 / No commit found**. No
authorized local copy containing them is available here. Original evidence is
**UNAVAILABLE HERE**, not reconstructed. Replacement work must name fresh source
and evidence and remain **PROOF OF CONCEPT**.

The existing P0-049 matrix remains the detailed requirement ledger. The current
P0-048 checkpoint reports 10 native tests and two archive-verification checks on
its supported hosted runner at `ea5fe9e`; its restricted local failures remain
recorded. This is useful prior evidence, not a fresh P0-050 native run or a
second-machine offline installer acceptance.

## Workstream gaps

T paths refer to the teaching branch, W to the WOW snapshot, O to the OVERLAY
snapshot above. Effort is an estimate, not a delivery commitment. All hardware
access is subject to availability; no purchase is authorized by this matrix.

| ID / workstream | Existing implementation and source | Verified capability | Unverified claim / acceptance blocker | Business relevance | Technical risk | Effort / hardware | Next experiment |
|---|---|---|---|---|---|---|---|
| S1 Applicability — bounded fix accepted | T `research/capability-learning/harness/ir_compiler.py`, `tests/test_applicability.py` | Fresh local + CI: holdout 12/12, attacks 26/26, frozen subset 6/6; four targeted behavioral mutants detected | General language understanding and full W3 remain unverified; old serialized capabilities are unchanged | Prevents an unrelated measurement entering a taught procedure | Lexical topic/cue matches are not semantic intent proof | E2; existing CPU host | Preserve this gate through later lifecycle/UI integration |
| S2 Security / branch integration | T and PR #16 sandbox; PR #17 chart; PR #19/#20 sensor changes | Fresh local runtime/corpus 284 pass; historical PR #20 native/CI runs pass on its head | Teaching CI baseline: empty authorized output, missing loopback output, exit-code tamper test failure. Trivy fails. Branches are not one qualified product | Credible isolation and trustworthy evidence precede a customer pilot | High: runner/host differences, custody, shared-path conflicts | E3; Linux CI and native host | Reproduce sandbox refusal on CI, review minimal PR #16 content and conflicts; preserve all assertions. Then classify/remediate Trivy without deleting original evidence |
| S3 C1 general teaching scoreboard | T `capability/scoreboard.rs`, `harness/record_exclusion_policy.py` | Read-only real CLI; signed suites; cited questions and scripted answers; no state mutation | Recorder is scenario-specific; general answered-session command and precise failed-row/B1 question linkage incomplete | Expert can understand and correct failures before authorizing use | Misattributing a failing branch to the wrong question | E2; existing CPU host | General session → compiled candidate → scoreboard binding; reject stale question/source hashes |
| S4 Signed expert approval | T `capability/lifecycle.rs`, `learning.rs`, `capability_engine.rs` | Existing Ed25519 capability/report binding and lifecycle tests rerun with runtime suite | Full expert/tenant/version/source/suite/scope/expiry/revocation binding and authenticated teaching action not accepted | Accountable authorization of consequential rules | High: trusting caller-supplied roles or stale authority | E4; existing CPU host | Enumerate direct and transitive bindings, then test changed source/suite, revoked/expired/cross-tenant approval, supersession and rollback |
| S5 Knowledge pack | Existing artifact hashes, signatures and lifecycle primitives; CLI has no completed `pack` interface | No P0-050 pack acceptance | Export/import, lineage/floor/model policy, authority, approval and validation verification missing | Portable customer-controlled expertise and offline transfer | High: imported key trust, downgrade and implicit activation | E4; two isolated local states initially | After S4, reject every specified tamper/authority/version/model attack; default to inactive import |
| S6 Signed answers and interfaces | T `app.rs`, CLI, audit chain; generic SDK/MCP patterns | Existing tenant/clearance/model gates covered by runtime tests | Per-answer signed receipt and replay defense; authenticated teaching REST/MCP; Python/TS teaching examples incomplete | Inspectable answers, integration and audit exports | High: confusing eval principals with authentication | E3; existing CPU host | Bind caller, scope, sources, capability/version/model and result; verify independently before exposing adapters |
| S7 Local model and swap | Resolver/sidecar tests, W pull-the-plug harness; T model-change refusal | Runtime regression refuses model-dependent capability after dependency change | No staged verified weights/runtime here; fresh live drafting/answer/swap absent | Core offline-AI demonstration | False offline claim or invented model output | E2; supported CPU laptop, storage for pinned weights/runtime | Stage permitted pinned bytes with provenance; run disconnected answer, missing/hash-mismatch and live swap trials |
| S8 Local teaching interface | T sessions, drafts, questions, diagnostics; teaching UI absent | Components only | ASK/TEACH/QUESTIONS/TEST/APPROVE/USE/EXPORT/VERIFY and roles not integrated | Understandable three-minute story | Displaying success while a required gate is unavailable | E4; target laptop/browser | After S3–S7, build vendored localhost flow with explicit NOT READY states |
| S9 Sniffer Dog qualification | W liar demo; PR #20 lifecycle/socket/host qualification; integration archive inventories | Historical signed native archives and PR #20 hosted CI; not fresh local sensor proof | Unbound short-lived events, coverage/interruptions/restarts, BPF/kernel matrix, collector custody and load/attribution still require scoped acceptance | Independent execution assurance for regulated workflows | High: silent missing events or overclaiming VERIFIED | E4; supported Linux, root/kernel facilities, independent network boundary | Honest/liar/bypass/tamper/interruption/restart with original archives and ground truth; preserve VERIFIED/DIVERGENT/CANNOT_PROVE |
| S10 Quantum X-ray / CBOM | O `src/cbom/classify.rs`; scanner source exists | Selected source inspected only | Original W4 unavailable; planted-ground-truth classification and raw results not reproduced | Cryptographic inventory before migration | Misclassifying unknown or hybrid crypto | E3; build-capable Linux, approved O source | Reviewed fresh planted fixtures, expected CBOM and classifier attacks; keep unknown distinct from safe |
| S11 PQ Overlay | O identity and gateway code, `tests/pqc_truth_tests.rs`; W references missing demo | Selected source only; generic gateway proxy is not proof of a live PQ handshake | Original W5 unavailable; actual hybrid wire path, identity/downgrade refusal, pcaps and unchanged-app comparison unverified | Migration proof with an unchanged application | High: fallback or unauthenticated peer | E4; Linux/container/network capture facilities | Fresh **PROOF OF CONCEPT** with pinned app hash, bad/missing identity, downgrade and before/after capture |
| S12 Offline evaluation kit | W `demos/kit/build_bundle.sh` hashes tracked files and six named binary/library artifacts | Builder source inspected; historical partial kit only | Omits AIRON runtime, weights, inference runtime, teaching assets and dependency wheels; external host tools still needed; no complete provenance/licence or fresh-machine test | Reduces deployment effort and enables independent evaluation | Missing dependency or download fallback breaks offline use | E5; founder target plus genuinely separate Linux machine | Build Profile A/B manifests, reject absent or changed components before install; disconnected installation with captures/counters |
| S13 Independent benchmark | W `demos/benchmark/rerun.sh`, `compare.py` already exist | Historical measurements and wrapper source, not a new benchmark | W6.1 whole-wrapper validation and W6.3 second-host reproduction incomplete | Defensible efficiency claims and sizing | Mixing hardware or selective failed-case exclusion | E4; two labelled hosts, exact models/runtime/datasets | One offline command; raw baseline/capability results, excluded cases, error analysis and independent comparison |
| S14 Commercial sequences | W launcher currently plug → liar → quantum; synthetic banking/defence data | Historical component demos only | Required plug → teach → liar absent; bank/defence not final accepted; manufacturing/healthcare incomplete | Investor clarity and customer-specific evaluation | Unlabelled recordings, unsupported performance or readiness claims | E2; target laptop and/or qualified Linux host | Execute required scripts live after dependencies; measure actual duration, report overrun |
| S15 Independent acceptance | Partial retained suites/archives/verifiers; P0-049 documents | This bounded change reproduced on connected CI | Full kit external installation, original signed evidence, 10 runs/mode and 20 W3 runs absent | Buyer can verify without trusting the presenter | Equating CI or another directory with an independent offline machine | E4; separate supported machine and evaluator | Run full acceptance, retain failures, reset consecutive counts; fresh W3 install every fifth run |

## Commercial readiness, by distinct claim

“DEMONSTRABLE” means the stated scoped behavior can be shown. “REPRODUCIBLE”
requires retained inputs/source and a repeated result. Neither implies
“PILOT-READY” (agreed operating/security/acceptance gates) or “PRODUCTION-READY”
(operational qualification). **NOT VERIFIED** names missing proof; it is not a
claim that the product cannot ever work.

| Product | DEMONSTRABLE | REPRODUCIBLE | PILOT-READY | PRODUCTION-READY | NOT VERIFIED |
|---|---|---|---|---|---|
| AIRON Native | Bounded cited teaching/validation component; live model demo historical | Current applicability component local + CI; full kit no | Not established | Not established | Complete six-act workflow, pack, live model swap, full offline install |
| VANIAN Sniffer Dog | Retained native demonstrations; no fresh P0-050 live run | Original archive verification and PR #20 host results are prior scoped evidence | Not established | Not established | Required interruption/custody/coverage/kernel and deployment gates |
| Quantum X-ray | Underlying code; original demo unavailable here | Final demonstration not reproduced | Not established | Not established | Planted-weakness acceptance and independent CBOM evaluation |
| SYNTRIASS Overlay | Underlying code; intended demonstration is **PROOF OF CONCEPT** | Final demonstration not reproduced | Not established | Not established | Actual wire path, identity/downgrade tests, pcaps and same-app verification |

No certification, government endorsement, customer deployment or regulatory
approval is established by this evidence. See the [execution order](P0-050-EXECUTION-ROADMAP.md)
and [open gaps](../assurance/P0-050-OPEN-GAPS.md). The next bounded item is S2's
sandbox/CI discrepancy, which overrides the higher numerical score of S3.
