# P0-051 release gap matrix

**NOT READY.** Reconciled 12 November 2026 (Asia/Kolkata). Every row below is
unfinished unless explicitly scoped as accepted. Source existence and historical
passes do not establish current release acceptance. No branches were merged.

## Current baseline

| Branch / PR | Fetched head | Evidence inspected |
|---|---|---|
| WOW / #13 | `6ad92ae78806546948874812dc8e6161d24d9d67` | MASTER_LOOP and original rehearsal ledger; historical CI/demos pass, Security failure |
| Teaching / #21 | `6764c7eb38fa3c5cb0d9884303b14c1cd422d6ad` | Reviewed concurrent sandbox continuation after initial `62db903`; teaching CI `43212899727` passes; main CI `43212899569` passes; concurrent evidence checkpoint `512fd4f` preserved, Security `43212899116` fails |
| Native observation / #20 | `61dd73013d02ea7869de104d953f330098df1c32` | P0-048 checkpoint iteration 004, original hosted archives and current CI metadata; main/native/same-run/RBI/contracts pass, Security fails |
| Reviewed sandbox fix / #16 | `c39fc1f0431ddfaffa2d62199874e18e92087969` | Runtime probe and tests reviewed by content; starting teaching versions equal its parent. No blanket branch merge |
| OVERLAY | `eccb66886d1f6b0b751909b6743d7e731e8061fb` | Authorized remote branch/tree snapshot, 24 branches, 1,528 tree entries; no demo directories. Git clone separately failed for lack of git credentials; connector inspection works. This is not a fresh build/test |

All six original OVERLAY revisions (`d1adc90`, `92c8b02`, `07d0319`, `6072578`,
`13c0fb1`, `3d63f95`) again return 422 / No commit found. No authorized local
original is available here. Original W4/W5 source/evidence remains unavailable;
a replacement must have fresh provenance and **PROOF OF CONCEPT** labelling.

P0-050's later `91df9e9`/`62db903` continuation already supplies independently
pinned OpenSSL signature verification and native case replay. It is preserved,
not rebuilt. Historical 375 Python / 187 runtime / 197 focused-CI counts overlap.
P0-048's ten native assertions are source/host-specific prior evidence, not a new
P0-051 sensor qualification. The prior two maintenance examples are not two sectors.

## Acceptance ledger

| ID | Requirement / current state | Existing source or evidence | Missing proof / next action |
|---|---|---|---|
| R1 | Sandbox setup correctness — reviewed concurrent repair adopted | `sovereign/vanian-sovereign/src/adapters/sandbox.rs`; PR #16 | Concurrent `6764c7e` implements repair and stronger timeout/program-change controls. Source `6764c7e` whole-workspace CI passes with existing excluded cases documented in S2. Source `5bc0c5f` teaching and main CI pass; current `7c9a0b3` runs are recorded separately. Local duplicate patch retained as superseded, never pushed |
| R2 | Remaining sandbox assurance — OPEN | Existing runner retains CANNOT_PROVE observation | Probe-to-launch policy race, executable TOCTOU, filesystem isolation and resource limits are not solved by the preflight repair |
| R3 | Security CI — OPEN | Four HIGH retained Helm-render Trivy findings; original evidence kept | Classify/remediate supported configuration while preserving evidence and native observation; no blanket suppression |
| A1 / C1 | Teaching-session scoreboard — PARTIAL | `capability/scoreboard.rs`, scenario recorder, cited B1/B2 questions | P0-051 adds general TXT session command and exact question/citation/edit links; 33 new checks pass locally and within hosted focused acceptance; full Python 408 passes. `7c9a0b3` adds explicit input-bound example mapping, separate native replay and refusal preservation: 37 new checks, 445 full local Python passes and 267 focused CI passes (overlapping counts). PDF/DOCX extraction-to-corpus binding and E1 remain open; mapping declarations are unsigned |
| A2 / C2 | Signed expert approval — PARTIAL | `capability/lifecycle.rs`, `learning.rs` | Complete authenticated teaching action and approval envelope; bind tenant/expert/ID/version/source/suite/scope/time/trust anchor |
| A3 | Authority verification — OPEN end-to-end | Existing signature/trust-map and independence checks | Forged, wrong expert/tenant, expired and revoked authority attacks in teaching workflow |
| A4 | Activation — PARTIAL | Existing lifecycle and CLI gates | Never activate without required validation/approval; unauthorized activation rejection through actual teaching interface |
| A5 | Supersession — PARTIAL; cross-scope displacement fixed | `cap-activate --supersede`; `ee3850c` | Version selection now matches tenant + security domain + capability ID; 7 new behavior/CLI tests, 194 runtime passes. Signed authority/version/lineage/policy-floor enforcement remains open |
| A6 | Safe rollback — PARTIAL; cross-scope displacement fixed | Existing rollback command; `ee3850c` | Other tenant/domain records remain byte-identical. Authenticated actor, expired/revoked/stale/below-floor rejection and transactional handling of storage failure remain open |
| A7 | Approval revocation — PARTIAL | Existing revoked state | Trust-anchor and expert revocation at use/import/rollback; no stale approval reuse |
| A8 | Tenant/clearance — PARTIAL | Runtime/corpus regressions | Full session/API/pack scope, wrong tenant, changed source/capability/suite attacks; no implicit activation |
| B1 | `pack export/verify/import` — OPEN | Existing hashes, Ed25519 and lifecycle primitives | Signed real synthetic maintenance `.pack`, version, implementation, provenance, approvals, validation, scope and model dependencies |
| B2 | Offline pack trust — OPEN | No accepted pack interface | Separate-process verification; external authority pins; reject one-byte/forged/wrong-tenant/wrong-authority/missing-approval/changed-source/incomplete-validation |
| B3 | Pack policy — OPEN | No accepted import policy | Reject invalid version, unsupported dependency, replay and rollback below floor; import remains inactive |
| C.D1 | Live meter — OPEN | Existing measurement adapters | Measured per-answer strategy/model calls/CPU/RSS/time/network; no fake metrics |
| C.D2 | Variation testing — OPEN end-to-end | Frozen capability cases | Held-out variations in actual workflow; no acceptance relabelling |
| C.D3 | Scope refusal — bounded gate accepted, UI OPEN | 12/12 holdout, 26/26 attacks, 6/6 subset; reusable replay | Preserve frozen gate and explain refusal in plain language; lexical context is not general intent understanding |
| C.D4 | Model change — PARTIAL | Existing model-dependent refusal tests | Two verified real model files/runtime; live swap, refusal and revalidation |
| C.D6 | Every-answer signed receipt — OPEN | Audit chain and signing primitives | Caller/capability/version/model/source/outcome binding, replay rejection and independent verifier |
| C.E1 | Local interface — OPEN | CLI and harness components | ASK / TEACH / QUESTIONS / TEST / APPROVE / USE / EXPORT / VERIFY; vendored assets, no CDN |
| C.E2 | Login/roles/clearance — OPEN | Existing domain gates | Real authenticated expert/approver/user separation; eval identities are not authentication |
| C.E3 | Accessibility/errors — OPEN | No accepted teaching screen | 1366×768, keyboard/error/empty-state checks, clear citations/refusals/evidence/approval status |
| C.F1 | Local REST/OpenAPI — OPEN | CLI/evaluation interface | Authenticated localhost endpoints and schema; retain tenant/clearance/receipt gates |
| C.F2 | MCP — OPEN | Generic gateway patterns | Approved capabilities as signed tools, authorization and failure tests |
| C.F3 | SDK examples — OPEN | Existing generic Python/TS SDKs | Runnable offline examples for the real teaching interfaces |
| C.G1 | Six-act live teaching — OPEN | Scenario-specific component recorder | Unknown question → document → questions → correction/approval → validated reuse → signed pack; label recordings |
| C.G2 | Second synthetic sector — OPEN | Motors and transformers are both maintenance | Full workflow on another sector, separately frozen data |
| C.G3 | Twenty W3 rehearsals — BLOCKED | Zero final-release qualifying runs | Complete workflow/kit; supported clean CPU-only host; fresh offline install every fifth run; retain failures and reset count |
| C.G4 | Offline capture — OPEN | Component namespace counters only | Full live run capture and independently enforced boundary; no packet-capture claim from counters alone |
| D1 | Honest/liar original WOW sequence — PARTIAL | W scripted agent and historical native archives | Fresh honest + undeclared action, omitted agent log, native effect and independent audit corroboration |
| D2 | Signed collector/verification/tamper — PARTIAL | P0-048 archives/verifier and loss handling | Full original archive every acceptance run; separate verifier; one-byte tamper; interruption/restart/coverage withdrawal |
| D3 | Native correctness/administration — PARTIAL | PR #20 process/socket fixes, ten hosted native assertions | Supported kernel/load/short-lived attribution; separately controlled hosts/keys before independent-administration claim |
| E.W4 | Quantum X-ray — original unavailable | Underlying O CBOM source | Fresh synthetic target, actual discovery, CycloneDX CBOM, ranked migration report and planted-weakness acceptance; no invented compliance |
| E.W5 | PQ switch — original unavailable / PoC | Underlying O identity/crypto code | Actual hybrid transport, unchanged app hash, before/after captures, identity/downgrade refusal and measured overhead |
| F.AIRON | Offline AIRON payload — OPEN | Partial W bundle and model resolver | Runtime, verified weights/manifest, inference server, pinned local dependencies, documents, UI and pack tools |
| F.VANIAN | Offline observer payload — PARTIAL | Probe/collector/verifier, historical examples | Complete synthetic agent, public trust/configuration, original example archives; ephemeral credentials, no bundled secrets |
| F.OVERLAY | Offline PQ/CBOM payload — OPEN | Original demo binaries/source unavailable here | Verified gateway/scanner, targets/scripts and provenance from accessible reviewed source |
| F.COMMON | USB manifest/launcher — PARTIAL | W builder hashes six listed artifacts | Full SHA-256/provenance, SBOM/AIBOM/CBOM, licence inventory, hardware/install/rehearsal documentation |
| F.INSTALL | Clean offline installation — BLOCKED | Earlier same-host partial test is not acceptance | Completed kit and genuinely separate clean machine; no downloads, missing/hash-mismatch refusal, sensor-safe network boundary |
| G1 | Pull the Plug — historical only | W local model demonstration | Current staged model/runtime, local answer/citation/model identity, measured execution and zero external egress |
| G2 | Teach One Rule — OPEN | Cited draft/answers/validation components | Signed approval, availability and bounded reuse in the actual show |
| G3 | Catch the Lying Agent — historical only | W liar demo / PR #20 evidence | Fresh original native/corroborated/signed archive and offline verification in show |
| G4 | Exact investor sequence/duration — OPEN | Old launcher is plug → liar → quantum | Plug → teach → liar live; measure full runtime, disclose overrun; no hidden replay |
| H.BANK | Banking — PARTIAL | Synthetic W corpus/mode | Business problem, authorization/assurance, evidence, boundary/limitations; whole-mode acceptance |
| H.DEFENCE | Defence — PARTIAL | Synthetic W corpus/mode | Offline intelligence/access restrictions, evidence, boundary/limitations; whole-mode acceptance |
| H.MFG | Manufacturing — OPEN whole mode | Maintenance component | Complete expert-guided taught capability workflow with evidence and limitations |
| H.HEALTH | Healthcare — OPEN | No accepted sector mode | Synthetic policy/document verification; evidence and limitations; no real patient data |
| I.W6.1 | One-command benchmark — PARTIAL | W `rerun.sh` and `compare.py` already exist | Audit actual wrapper, stage pinned inputs/runtime; fresh raw baseline/capability results and error analysis |
| I.W6.3 | Second-machine benchmark — BLOCKED | Historical one-host measurements | Distinct supported host, CPU/RAM/model/binary hashes, latency/CPU/memory/network/verification times and differences |
| I.W8.3 | Hardware sizing — PARTIAL | Earlier one-machine sizing | Second-machine data; do not combine hardware or invent single-run ranges |
| I.RUNS | Ten consecutive per required mode — BLOCKED | Historical subset rows only | Final modes/kit, complete originals, failed attempts/recovery; reset consecutive count on failure |
| J1–J10 | Independent evaluator acceptance — BLOCKED | Bounded replay/signature utilities | Verify hashes, install offline, execute live, inspect originals/signatures/tamper/citations, reproduce results, inspect limits and rerun tests on supported separate host |

All mandatory rows must close with evidence before release. No licensing,
purchase, outreach, new repository, production deployment or patent action was
performed. Use **EXPERT-GUIDED TAUGHT CAPABILITY** for the teaching behavior.

P0-051 bounded implementation: `5bc0c5f`; evidence and subsequent reconciliation
are in [the current report](P0-051-FINAL-REPORT.md). The next bounded source `7c9a0b3` implements explicit example mapping; it does not close authenticated approval, full C1/UI or release acceptance.

Iteration 3 source `ee3850c` fixes the demonstrated cross-tenant/domain lifecycle
collision. Teaching CI 43224795762 passes 296 relevant Rust and 267 focused
Python checks; local full Python remains 445. These counts overlap. Original
baseline failures and signed records are in `evidence/p0-051-iteration-3/`.
Main CI is separately tracked; Security still fails four HIGH findings.

## Iteration 4 — native approval authority (12 November 2026)

Parent `31d3ee5a84e7565db9458b9834f46b51dfd53720` freshly fetched. Its main,
teaching and contracts CI pass; Security fails the four previously retained HIGH
Helm findings. This is baseline CI, not validation of the changes below.

A2/A3/A6/A7 advance to **PARTIAL**: optional strict authority policy binds expert
key, tenant/domain, capability scope/version, clearance and validity to a v2
Ed25519 approval. CLI activation/rollback and runtime use recheck policy; policy
removal cannot downgrade the signature. Source dependencies are rechecked in
strict CLI paths. Local runtime 201/201 and teaching Python 445/445 pass; seven
new Rust tests are included in 201, not additional totals. Exact evidence and CI
will be retained in `evidence/p0-051-iteration-4/`. See `APPROVAL-AUTHORITY.md`.

C2 stays OPEN end-to-end: operator actions are not authenticated; C1 session/full
original-document/example-map approval binding, transactional writes, local
policy rollback protection and per-approval revocation remain open. Legacy mode
is explicitly not C2-qualified. Packs and all previously listed release blockers
remain open. No new rehearsal or clean-machine credit. **NOT READY**.

## P0-051 iteration 4 — policy-bound approval

Source `00c06de1503785470a73a7a2f0890ad8f9c1ce84` adds optional strict expert
authority grants and v2 Ed25519 approvals. Approval/activation/rollback/use enforce
key, tenant/domain, scope/version, clearance, expiry and revocation. Policy removal
cannot downgrade a v2 approval. Native CLI rechecks source dependencies.

Local runtime **201 pass**, teaching Python **445 pass**; teaching CI **303 Rust /
267 focused Python pass** (overlapping counts). Holdout **12/12**, attacks **26/26**
including six nonactivation probes; rejected control remains **11/12**. Independent
verification of original local/offline/hosted signatures passes; six tamper controls
reject. Full evidence, commands, source/host hashes, CI and failed recorder attempts
are in [iteration 4](evidence/p0-051-iteration-4/README.md). Native policy setup is
in [APPROVAL-AUTHORITY.md](APPROVAL-AUTHORITY.md).

**NOT READY. C2 remains partial.** Actor/role strings do not authenticate operators;
C1 session/full-document/example-map approval binding, policy rollback resistance,
per-approval revocation and transactional writes remain open. Strict policy must
be explicitly configured; legacy mode is not C2-qualified. Packs, models, UI/API,
OVERLAY, clean-host installation and independent demo acceptance remain open.
No new qualifying rehearsal: the offline 33-test component run on this same host
counts as zero demos. No live investor runtime, second host or sensor qualification.

## Iteration 5 — fresh teaching-review commitment (13 November 2026)

Reconciled parent `93c65bcdc293aa950552f1a11515c4b21a553e8e`; preserved seven
newer sandbox/CI commits by fast-forward. Parent main, teaching, contract and
Agent Zero CI pass; Security fails. This baseline is not new-source validation.

C2 prerequisite: emit an unsigned content-addressed review only after fresh
signed-suite and example replay. Full original document, session, answers,
example map, suite/trust, capability, native results and binary are bound.
27 new tests include each input mutation, separate-process verification, missing
files, symlinks and false approval labels. Full Python 472 pass (27 included).
Native runtime code and activation policy are unchanged. No frozen labels change.

Next: incorporate this digest in the expert signature and enforce its replay
binding at native approval. The current verifier proves pinned-byte integrity,
not human identity or activation permission. C2, signed packs, complete demos,
independent clean-host acceptance and all remaining release gates stay OPEN.
Release **NOT READY**; zero qualifying rehearsal credit.
