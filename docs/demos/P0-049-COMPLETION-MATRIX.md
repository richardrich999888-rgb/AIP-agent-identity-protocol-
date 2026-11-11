# P0-049 completion matrix

Release verdict: **NOT READY**. This is iteration 1, reconciliation plus the C1
homework scoreboard. No full-demo or independent-machine acceptance is claimed.
Review date: 12 November 2026 IST (11 November UTC).

## Source snapshot and branch reconciliation

| Label | Repository / revision | What was inspected |
|---|---|---|
| T | AIP `feature/airon-teach-demo`, starting `4e422b6` | Full git checkout, teaching loop, source, tests and retained results |
| W | AIP `feature/wow-demos`, `6ad92ae78806546948874812dc8e6161d24d9d67` | Detached audit checkout; master loop, rehearsal log, kit, launcher, benchmark scripts and evidence |
| O | OVERLAY approved base `eccb66886d1f6b0b751909b6743d7e731e8061fb` | Connector commit/tree snapshot and selected CBOM, identity and test source; private git clone was unavailable to the shell |

T and W have **27 and 37 unique commits**, respectively, since common ancestor
`2883da7`. Of their 17 overlapping changed paths, `.gitignore`,
`deploy/syntriass/requirements.lock` and `deploy/syntriass/setup_env.sh` differ.
The remaining 14 are byte-identical. No branches were merged.

OVERLAY exposes 24 branches in the returned inventory and no `feature/wow-demos`.
All six recorded demo/fix revisions (`d1adc90`, `92c8b02`, `07d0319`, `6072578`,
`13c0fb1`, `3d63f95`) returned **No commit found**. They are also absent from this
workspace. Their original source and complete evidence are **UNAVAILABLE HERE**,
not reconstructed. O is accessible and contains the underlying product; it does
not contain `demos/quantum-xray` or `demos/pq-switch`.

## PR and CI reconciliation

| PR | Exact inspected head | State | Latest observed workflow results | Implication |
|---|---|---|---|---|
| #13 | `6ad92ae` | Open draft | CI and demos success; Security failure | Description predates later source; not release acceptance |
| #14 | `86f2105` | Open | CI success; Security failure | W already merged these prerequisites; T has equivalent resolver/sidecar files but different teaching dependency additions |
| #16 | `c39fc1f` | Open | CI success; Security failure | W sandbox source includes the fix by content; T still differs. Ancestry alone was insufficient |
| #17 | `a0b1045` | Open | CI and enterprise success; Security failure | Chart seccomp hardening does not close the retained-render Trivy finding or establish sensor operation |
| #19 | `9b81098` | Open | CI success; Security failure | Distinct socket corroboration changes remain different from W; review integration separately |

For W's Security run `42447753606`, secret scan and cargo audit passed; Trivy
failed. No workflow, finding or retained render was suppressed. Historical green
CI does not imply clean-machine, model, kernel-sensor or external-evaluator proof.

## Requirements

Paths with T/W/O prefixes refer to the snapshots above. Evidence described as
historical was inspected, not re-created in this iteration. New results are in
`docs/demos/evidence/p0-049-iteration-1/` once the recording commit is added.

| Requirement / status | Current implementation | Source file | Test | Evidence | Missing behavior | Dependency | Next action |
|---|---|---|---|---|---|---|---|
| 1. Offline answers — HISTORICAL PARTIAL | Live local-model harness and citations | W `demos/pull-the-plug/run.sh` | W `accept.py`, server/meter tests | W `evidence/2026-11-08-64d6f40-*` | Fresh packaged run with captures on supported host | Weights, llama-server, bundle | Stage pinned bytes, package and rerun |
| 2. Expert teaching — PARTIAL | Ingestion, sessions, deterministic draft, typed answers | T `domain/teach.rs`; `harness/{draft_from_session,apply_answers}.py` | T teach CLI + Python tests | T `docs/demo/results/A1*`, `A2*`, `A3a*`, `B2*` | Live model drafting and complete workflow | Model bundle, B3 scope issue | Finish A3b without overwriting document evidence |
| 3. Questions — PARTIAL | Deterministic cited questions; OCR warning | T `harness/question_generator.py` | `test_question_generator.py` | `B1_question_generator.json`, `B3_holdout_questions.json` | Word-form restriction blocks holdout; term length not explained | Reviewed typed-answer policy | Fix with regression and false-activation checks |
| 4. Homework C1 — IMPLEMENTED, bounded acceptance | New read-only `cap-scoreboard`, real validator, gate failures, inputs, trace, review prompts | T `capability/scoreboard.rs`, CLI | `teaching_scoreboard.rs` (14 new) | C1 recorder, two synthetic maintenance domains | UI linkage to precise B1 question IDs; full rehearsal | E1; trusted expert suite | Review bounded evidence; integrate teaching screen later |
| 5. Signed approval C2 — PARTIAL | Existing signed `cap-approve` and lifecycle | T `capability/lifecycle.rs`, `learning.rs` | `capability_engine.rs` | Existing research lifecycle results | One teaching action joining approval/activation/supersession | C1, approver roles | Compose existing gates; never auto-approve |
| 6. Reuse — PARTIAL | Deterministic capability path; activation/supersede/rollback commands | T `app.rs`, `learning.rs` | `runtime_app.rs`, `capability_evolution.rs` | Existing v0.2 results | Teaching workflow, current live meter and variations | C2, D1/D2 | Measure end-to-end reuse with zero model calls |
| 7. Knowledge packs D5 — OPEN | No completed `pack export/import` command | T CLI | No pack acceptance suite | None | Signed, tenant/version/approval/validation-bound export/import | C2, signing/trust format | Implement before pack demo |
| 8. Model revalidation D4 — PARTIAL | Model-bound use refused after changed model; deterministic capabilities independent | T `app.rs`, lifecycle | `model_dependent_capability_needs_revalidation_after_model_change` | Historical phase E refusals | Live real-weight swap in teaching workflow | Two verified model files | Show both properties; no unsupported 40/40 claim |
| 9. Undeclared action — HISTORICAL PARTIAL | Scripted liar, kernel observation, auditd comparison | W `demos/lying-agent/{agent,observe,acceptance}.py` | W lying-agent tests | Retained 7 batches / 86 events + 1 health record reverified this iteration; tampered copy rejected | Fresh initial-netns run behind independent isolation; missing-event/interruption acceptance | Kernel facilities, auditd, dedicated isolated host | Capture traffic/counters without disabling sensor |
| 10. Quantum X-ray — ORIGINAL UNAVAILABLE | CBOM classifier/scanner exists at O | O `src/cbom/classify.rs`; original demo absent | O CBOM tests not run here | Historical W summaries only | Demo source, planted-sample acceptance and fresh raw outputs | Accessible O checkout/build | Reimplement from verified requirements and label fresh provenance |
| 11. PQ Overlay — ORIGINAL UNAVAILABLE / PoC | Underlying hybrid encryption and identity tooling | O `src/bin/syntriass-identity.rs`, identity tests | O tests not run here | W historical summaries reference unavailable commits | Demo, captures, same-binary hashes, fail-closed trials | Linux/container facilities and O build | Reimplement; label **PROOF OF CONCEPT** |
| 12. Independent reproduction — OPEN | Some hashes, verifier and retained results exist | W kit and benchmark tools | No independent full-kit test | Same-host historical runs only | External evaluator installation and full acceptance | Completed kit, second machine, evaluator | Provide immutable kit and independently held trust anchors |
| W3 signed answer records D6 — OPEN | AIP primitives; runtime audit hash chain | T `app.rs`, AIP signing crates | Existing audit-chain tests | No full per-answer receipt evidence | Signed questioner/capability/model/source/outcome binding; replay rejection | Identity/auth, receipt format | Implement and verify independently |
| W3 REST F1 — OPEN | CLI and evaluation JSONL interface | T CLI | CLI tests | No authenticated teaching REST evidence | Ask/list/verify endpoints and OpenAPI | D6 and role/clearance checks | Build localhost interface; eval principals are not authentication |
| W3 MCP F2 — OPEN | Existing AIP gateway patterns, no completed teaching adapter | T existing MCP code | No teaching MCP tests | None | Approved capability tools and signed calls | D6/F1 | Add authenticated adapter |
| W3 examples F3 — OPEN | Existing generic SDKs | T `sdk/python`, `sdk/typescript` | Generic SDK tests only | None for teaching | Working Python/TS teaching examples | F1/F2 | Add runnable offline examples |
| W3 UI E1-E3 — OPEN | W pull-the-plug page is a different screen | T teaching UI absent | No teaching UI/role/accessibility acceptance | None | Local Ask/Teach/Questions/Homework/Approve/Meter/Pack UI, roles, clearance, errors | C2/D5/D6/F1 | Build with vendored assets and no CDN |
| W3 two domains G2 — PARTIAL | C1 checks motors and transformers | C1 recorder; T frozen corpora | C1 real CLI cases | Bounded scoreboard runs | Full six-act teaching on a second sector | Complete W3 | Do not call two maintenance tasks two customer sectors |
| Bundle W7.1 runtime — OPEN | Builder copies only probe/collector/verifier and three OVERLAY binaries | W `demos/kit/build_bundle.sh` | Historical install test | W 177-file kit log | `syntriass`, models, inference runtime, teaching files, wheels, system deps, assets | Runtime/overlay artifacts | Extend component manifest and fail on omissions |
| Bundle provenance — PARTIAL | SHA256SUMS, commit and binary maps | W kit + model staging | Historical one-byte corruption test | W `MANIFEST`/model provenance | Authenticated release manifest; complete dependency/license material | Distribution decisions | Hash all shipped bytes and retain source/licence records |
| No-download installation — OPEN | Kit builder downloads nothing; setup can fall back to PyPI | W kit; T `deploy/syntriass/setup_env.sh` | No full clean-machine install | Historical partial kit run | Refuse missing local deps instead of network fallback in install path | Full offline wheel/system-dep staging | Test with egress blocked on independent host |
| Kernel-safe isolation — OPEN | Security demo kept initial netns, exception documented | W `demos/kit/install_test.sh` | No independent isolation test | Historical security run explicitly host-network | External VM/switch/firewall boundary and verified captures/counters | Dedicated authorized host | Preserve sensor and prove boundary independently |
| W6.1 benchmark — PARTIAL, checklist stale | `rerun.sh` and `compare.py` already exist | W `demos/benchmark/` | Summary tests only | Published raw measurements; no fresh full rerun | Completed wrapper acceptance, full inputs/runtime hashes, excluded proposal disclosure | Models, exact runtime, complete offline kit | Verify wrapper and run; do not recreate it blindly |
| W6.3 / W8.3 second hardware — OPEN | One-machine historical measurements | W benchmark and sizing docs | None on second host | No qualifying second-host data | Rerun, error analysis and explicit per-host comparison | Second machine | Keep hardware results separate, no invented ranges |
| Investor sequence — INCORRECT / NOT READY | Existing sequence is plug → liar → quantum | W `demos/launch.py` | W launcher tests reflect old sequence | No requested sequence measurement | plug → teach one rule → liar | W3 ready gate | Correct sequence after W3 is executable; measure duration |
| Banking/defence — PARTIAL | Synthetic corpora and launch modes | W `demos/sectors/{banking,defence}` | Existing pull-the-plug checks | Historical summaries; some full run dirs not retained in git | Current whole-mode acceptance | Models, sensor; defence also PQ | Rehearse with full evidence |
| Manufacturing/healthcare — OPEN | Generic customer fallback says NOT READY | W launcher | No sector tests | None | Synthetic scripts/corpora and requirement-aware gates | Sector acceptance definitions supplied by P0-049 | Implement both; no generic READY fallback |
| Ten consecutive per required mode — OPEN | Historical subset rehearsals exist | W launcher | Existing rehearse control | W rehearsal log and subset result files | All required modes at final SHA with complete archives/captures | Every mode ready | Failed run resets consecutive count |
| W3 twenty consecutive — OPEN | No complete teach launcher | T G3 | None | No qualifying run | 20 runs; fresh offline install every fifth on required host | W3/kit + CPU-only clean host | Keep bounded tests outside rehearsal totals |
| Phase 8 docs — ITERATION DRAFTS | This matrix plus guide/report/gaps/verification/buyer/rehearsal documents | T `docs/demos/` | Command checks recorded below | Current iteration | Release-complete evidence remains unavailable | Remaining rows | Keep NOT READY until external acceptance |

## Adversarial acceptance ledger

Every line below is still required at release level. A unit/fixture pass does not
close the full-demo criterion.

| Attack | Present source/test/evidence | Remaining dependency / next action |
|---|---|---|
| Network leakage | W namespace harness; historical no-route checks | Full-run captures and independent isolation, including initial-netns sensor |
| Missing weights / hash mismatch | T resolver tests; no weights here | Repeat through packaged launcher/install on supported host |
| Forged pack / unauthorized import / invalid version / missing approval | Pack command absent | Implement D5 and all negative cases |
| Unauthorized approval | Existing lifecycle tests; new scoreboard cannot activate a PROPOSED record | Authenticated teaching approval path and revoked-authority trials |
| Cross-tenant retrieval | Existing runtime tests and W fixed questions | Full teaching/API/pack retrieval boundary tests |
| False activation | Existing false-activation fixtures; C1 missed-scope failure remains visible | Fix B3 without broadening scope; full evaluation |
| Revoked authority | New removed-expert-anchor CLI rejection | Revoked approver, runtime and imported-pack authority tests |
| Undeclared execution | W scripted liar + historical signed observations | Fresh sensor and independent ground-truth run |
| Missing kernel events / sensor interruption | Historical failed auditd batch retained; verifier health says ContinuityUnverified | Demonstrate understandable failure and no complete-coverage claim |
| Tampered evidence | Retained archive verifies; altered archive exits 1 | Full release manifest/signature and independent trust anchor |
| Replayed receipts | No completed per-answer signed receipts | D6, replay state and independent verifier |
| Incorrect crypto classification | O classifier still lacks exact bare TLSv1 match; original fixes unavailable | Fresh planted-ground-truth tests and review of classification semantics |
| PQ identity failure | O identity tests exist; original demo unavailable | Fresh missing/impostor/plaintext/PSK-fallback capture tests |
| Offline installation failure | Historical partial same-host kit test | Complete local dependencies, independent clean-machine failure/recovery |

The first next actionable item after this bounded iteration is C2 teaching approval
composition, or the documented B3 word-form issue if its precise semantics are
settled in tests. A3b remains unstaged in this checkout. This iteration does not
borrow W's historical model bytes, sensor observations or performance as current proof.
