# AIRON Native — "Teach it like a child" demo: build loop

**Branch** `feature/airon-teach-demo`, from `feature/syntriass-runtime-v02` (`2883da7`)
**Rule** one item per iteration, proved by a test and a recorded run, committed, ticked, then stop.
**Started** 2026-11-05

---

## Iteration 1 — ground-truth verification (DONE)

Every line of the assignment's "ground truth at start" was re-checked against git
and a test run rather than assumed. Nine of ten matched exactly. One did not.

| Claim | Verdict | Evidence |
|---|---|---|
| `feature/syntriass-runtime-v02` head `2883da7`, 31 Oct 2026 | ✅ | `runtime: S2 strongest-fit router and S1 evidence-bound execution` |
| built from `7bf697b` | ✅ | `7bf697b` is an ancestor (`docs+demo: final pre-YC report …`) |
| none of it merged to `main` | ✅ | 466 commits ahead; not an ancestor of `origin/main` |
| crate `sovereign/syntriass-runtime`, binary `syntriass` | ✅ | `[[bin]] name = "syntriass"`; workspace member at `Cargo.toml:156` |
| `exp-record`, `cap-review`, `cap-upgrade-check`, `cap-activate --supersede`, `cap-rollback`, `serve --eval` | ✅ | all six plus both flags present in `src/` |
| `tests/capability_engine.rs` | ✅ | **16 tests, 16 pass** |
| `research/capability-learning/harness/` — all six scripts | ✅ | `atomic.py`, `propose_atomic.py`, `ir_compiler.py`, `correct_ir.py`, `fp_probes.py`, `gate_drafts.py` |
| `offline.sh` refuses to start if an external route exists | ✅ | `offline.sh:14` — `external route present; refusing` → `exit 1` |
| `run_demo.sh`, seven scenes, real binary and models | ✅ | header states seven scenes; Scene 3 already labels its recorded draft |
| 25/30 strict, 0 wrong release decisions, 0.2 ms median, 0 model calls; 1.5B 1/30, 3/30, 4/30; 3 leaf edits vs 68; 2 vCPU / 8 GB / no GPU; Qwen2.5 0.5B+1.5B | ✅ | `V02_REPORT.md:4–5, 15, 17` — every figure verbatim |
| **"Model swap left 40/40 outputs identical"** | ❌ **NOT SUPPORTED** | see below |

Full suite on the branch: `cargo test -p syntriass-runtime --locked` → **8 binaries, 90
passed, 0 failed, 0 ignored**.

### The one correction

The branch contains no 40/40 model-swap result. What it does contain:

- `SECURITY_BOUNDARIES.md:17` — Phase E: **8/8 refused after a model swap**.
- `runtime_app.rs::model_dependent_capability_needs_revalidation_after_model_change` — passes.
- `app.rs:215` — `"execution model changed; compatibility re-validation required"`.
- `LEARNING_BENCHMARK.md:32` — a **40-item** set, but that is the v0.1 *baseline*
  benchmark, not a swap result.
- `40/40` does appear on the branch, in `AIBOM_EVIDENCE_REPORT.md:104`, about
  mutation repeats. Unrelated.

So the assignment's line conflates a 40-item benchmark with a swap result that was
**8/8 refused**, which is the opposite shape: the system does not keep answering
across a model change, it *refuses* a model-bound capability until re-validated.

**Consequence for D4.** The honest demonstrable claim has two halves, and only one of
them is "identical outputs":

1. A capability with **no model dependency** answers identically after a swap —
   trivially, because it makes no model call at all. That is worth showing, and it
   must be said that way rather than as evidence of robustness.
2. A **model-bound** capability is **refused** after a swap until re-validated. That
   is the stronger property and it already has a passing test.

D4 is rewritten below to demonstrate both. Nothing on screen may say "40/40 identical".

---

## Environment gate — read before planning any model-dependent item

Verified in this container on 2026-11-05:

| Fact | Value |
|---|---|
| GGUF weights vendored in the repo | **none** (`find -iname '*.gguf'` → empty) |
| How the demo gets a model | `run_demo.sh:65` hard-codes `/home/claude/vanian-build/models/qwen2.5-1.5b-instruct-q8_0.gguf` — an absolute path on the original build machine |
| Inference runtime installed | none — no `llama-server`, `llama-cli`, `ollama` |
| `huggingface.co` | **403 at the proxy** (`gateway answered 403 to CONNECT`) |
| `registry.ollama.ai` | **403 at the proxy** |
| `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `index.crates.io` | reachable |
| This container | 4 vCPU, 16 GB — **not** the 2 vCPU / 8 GB the measured numbers were taken on |

Two consequences, both structural:

**Model weights cannot be obtained here.** The pinned digests in
`research/compute-memory/bench/run_all.sh` are good discipline, but the bytes they
pin are behind a host this environment's network policy refuses. So every act that
needs a *live* model call — Act 1 ("it doesn't know"), the model's rephrasing in B1,
and the swap in D4 — is **BLOCKED on infrastructure, not on code**. It is not a
defect in this branch and not something an implementation choice can route around.

**Published numbers may not be re-measured on this hardware.** 4 vCPU / 16 GB is not
2 vCPU / 8 GB. Any figure this loop measures here is a *new* measurement on
different hardware and must be labelled with this container's specification, never
merged with the `V02_REPORT.md` figures.

Unblocking needs one of: allow-listing `huggingface.co` in the environment's network
policy, or vendoring the pinned GGUF files into the offline bundle (large, and a
licence question for naming), or a model API key — which would break rule 2
(offline) and is therefore the wrong answer.

**What is NOT blocked.** Most of the backlog needs no model at all: A1, A2, B1's
deterministic core, B2, C1, C2, D3, D5, D6, all of E, all of F, and the
non-interactive parts of G. The loop proceeds on those and marks the model-dependent
acceptance criteria BLOCKED rather than faking them.

---

## Backlog

Legend: `[ ]` open · `[x]` done · `[B]` blocked (reason recorded) · `[~]` partial,
with the unproven half named.

### Phase A — Teaching from real documents
- [ ] **A1. PDF / DOCX / TXT ingestion.** Clauses with page numbers and character
  spans for the atomic pipeline. Pin and vendor every new dependency for offline
  install; record licences. *Acceptance:* a 20-page synthetic PDF with a table and
  one scanned page yields correct clauses and page references.
  *Note:* scanned-page OCR needs a local engine; `tesseract` is not installed and is
  an apt package, so check that apt is reachable before promising the scanned half.
- [ ] **A2. Teach session API.** `syntriass teach start --doc <file> --page <n>`
  creating a session holding cited clauses, the expert's plain-language rule, and 2–5
  labelled examples with reasons. Persisted under the tenant, mode 0600.
- [ ] **A3. Draft from session.** Session → `propose_atomic.py` → IR. Output a
  candidate plus every field marked `hypothesis` or `issue`.
  *Watch:* if `propose_atomic.py` requires a model to draft, the deterministic
  IR-compile half still runs; split the item rather than marking it blocked whole.

### Phase B — The AI asks the teacher
- [ ] **B1. Question generator.** Each `hypothesis`/`issue` field → one plain-language
  question carrying the candidate values from the clause. Deterministic templates
  only. *Model rephrasing is deferred and marked [B]:* no weights available, and
  `YC_TECHNICAL_CLAIMS.md` already records that the local model's drafts all failed,
  so a rephrasing path must never be allowed to introduce a value.
- [ ] **B2. Answer application.** Answers become typed leaf edits on the IR, each
  recorded with who, when and why, and counted on screen.
- [ ] **B3. Test against the v0.2 holdout.** The generated questions must cover the
  **3** leaf edits that were needed after the suite failure (`V02_REPORT.md:15`).
  Record honestly whether answering them up front lets the candidate pass without a
  failed run — including if it does not.

### Phase C — It checks its own homework
- [ ] **C1. Scoreboard.** Boundary probes + expert suite; "Passed N of M". On failure:
  the rule misunderstood, the probe input, expected vs actual, and which question to
  revisit.
- [ ] **C2. Approve.** Signed approval → activate → supersede. One CLI command, one UI
  action. Builds on `cap-activate --supersede` and the six suite-attack tests.

### Phase D — Reuse, refusal and ownership
- [ ] **D1. Live meter.** Per answer: strategy (capability / model / withheld), model
  calls, wall-clock ms, CPU-seconds, bytes out from the namespace counters (must read
  0), and cost at a configurable ₹/CPU-hour. Every value measured, none hard-coded.
- [ ] **D2. Variation test.** "Try 10 variations" over held-out paraphrases; live
  correct / withheld / wrong counts.
- [ ] **D3. Out-of-scope refusal.** "Outside what I was taught" plus the scope summary.
  Test with the existing false-activation probes (`fp_probes.py`,
  `fixture_on_unseen_and_false_activation_sets`).
- [ ] **D4. Model swap — REWRITTEN, see "The one correction".** Demonstrate *both*:
  (a) a capability with no model dependency answers identically after a swap, stated
  as "makes no model call" and not as robustness; (b) a model-bound capability is
  **refused** until re-validated — the 8/8 Phase E property. Screen must not say
  "40/40 identical". *Live swap of real weights is* `[B]`*: no weights available.*
- [ ] **D5. Knowledge pack export / import.** `syntriass pack export --tenant T --out
  <name>.pack` → one signed file with capabilities, tests, approvals and version
  history. `pack import` verifies the signature and every capability's validation
  before activation. A one-byte change must fail import with a clear message. Tests
  for all three paths.
- [ ] **D6. Signed record per answer.** AIP signing: who asked, which capability and
  version or which model, sources, outcome. Offline verify command. Tamper test.

### Phase E — The teaching screen
- [ ] **E1. Local web UI** on localhost only, assets and fonts vendored, no CDN:
  Ask, Teach, Questions, Homework, Approve, Meter, Model switch, Export/Import.
- [ ] **E2. Login and roles.** expert / approver / user plus clearance; a
  lower-clearance user blocked from restricted capabilities and documents, on the
  existing permission model (`other_tenant_and_lower_clearance_cannot_see_the_capability`).
- [ ] **E3. Accessibility and robustness.** Works at 1366×768; every action has a
  visible result or error; nothing silently does nothing.

### Phase F — Integration with existing tools
- [ ] **F1. Local REST API** — ask / list capabilities / verify record, plus OpenAPI.
- [ ] **F2. MCP server** exposing approved capabilities as tools on the existing
  `aip-mcp-gateway` pattern; every call signed.
- [ ] **F3. SDK examples** in the existing Python and TypeScript folders.

### Phase G — Demo hardening
- [ ] **G1. Demo script** `demo/teach/run_teach_demo.sh` — six acts end to end on a
  synthetic maintenance manual, with a non-interactive CI mode.
- [ ] **G2. Second domain.** Full flow on a synthetic document from another sector, to
  show it is not tuned to one example.
- [B] **G3. Rehearsal record.** 20 consecutive passes on a clean CPU-only machine,
  fresh offline-bundle install every 5th run. **Blocked:** needs live model weights
  (acts 1 and 6) and a 2 vCPU / 8 GB machine; this container is 4 vCPU / 16 GB.
  The non-model acts can be rehearsed and logged separately, labelled as partial.
- [ ] **G4. Offline proof artefact.** Packet capture over a full run showing zero
  outbound packets, saved with the command used. *Runnable now* for the non-model
  acts; `tcpdump` availability to be checked as part of the item.

---

## Discovered items (added as found)

- [x] **X1. Hard-coded absolute model paths — DONE.** Commit `08fb7db`.
  Not one instance but **seven**, across five scripts: five model-directory
  defaults and two `llama-server` paths, plus three duplicate copies of the
  SHA-256 digests. Replaced by `deploy/syntriass/models.manifest.json` (4 pinned
  models, digests cross-checked between `run_all.sh` and `BASELINES.md`) and
  `deploy/syntriass/resolve_model.py`, with precedence
  `MODELS` > `SYNTRIASS_BUNDLE/models` > `/opt/syntriass/current/models` — the
  last being where `README.md` section 3 actually installs, so no default was
  invented. SHA-256 is authoritative and a mismatch is **refused**, never warned
  about. Exit codes are the contract: 2 caller error, 3 not staged, 4 integrity,
  5 provenance unverified.
  *Tests:* `deploy/syntriass/tests/test_resolve_model.py` **23/23**;
  `cargo test -p syntriass-runtime --locked` **90/0**;
  `test_atomic.py` **34/0**; `test_ir_compiler.py` **17/0** (2 skipped);
  `cargo fmt --check` clean.
  *Recorded run:* `docs/demo/results/X1_model_path_resolution.json` —
  `run_demo.sh <OUT> --propose` now reaches Scene 3 and stops with **exit 3**
  and the operator-facing message, where before it failed on a build-host path
  with no remedy. Scene 6 (offline) and Scene 2 (`strategy: Exact`) pass live;
  Scene 1 runs and correctly reports a missing *bundle* model, which shows the
  fix reached the Rust runtime's config through `mkconfig.py`.
  *Lesson recorded:* two of the seven instances were missed by the search pass
  and caught only by the test, which asserts over an explicit caller list
  instead of trusting a grep.
- [ ] **X3. Pin the three requested extra models.** One 7B-class, IBM Granite
  instruct, Mistral-7B-Instruct. **Blocked here:** every model card is behind
  `huggingface.co`, which answers 403 at this proxy, so no licence can be read.
  Per the owner's decision a licence must be verified from the card before an
  entry is added, and one restricting commercial use must stop and escalate.
  `models.manifest.json` records them under `not_yet_pinned` and
  `resolve_model.py provenance` already exits 5 for any entry whose
  `source_url` or `licence` is `UNVERIFIED_NO_NETWORK`, so the staging script
  cannot download one by accident.
- [ ] **X4. `research/bittorrent-p2p/bench/bench.py:43`** defaults `BENCH_WORK`
  to `/home/claude/vanian-build/btwork`. Same defect class as X1 but a scratch
  directory rather than a pinned artifact, and in a separate research area, so
  it was deliberately left out of X1's scope rather than widened into it.
- [ ] **X6. The sidecar's training data is gitignored.**
  `.gitignore:11` is a blanket `*.jsonl`, which excludes
  `research/system-one/data/maintenance-priority-v2/*.jsonl` even though that
  dataset's `MANIFEST.json` is tracked. On a fresh clone the sidecar therefore
  cannot start, and the demo dies in Scene 1 with
  `Inference: sidecar reply missing or oversized` — a message that names
  neither the file nor the cause.
  **Good news:** the dataset is seeded (`seed 20261031`) and regenerates
  **byte-identically** to the five digests pinned in the tracked manifest
  (verified this iteration). So the fix is a generate-and-verify step in setup,
  not a large-file commit. Also worth fixing the message so it names the file.
- [ ] **X7. The documented Python requirement is understated.**
  `deploy/syntriass/README.md` section 1 says "Python ≥ 3.10 with numpy", but
  `research/system-one/methods/extractors.py:102` imports
  `sklearn.linear_model`, so the sidecar needs **scikit-learn** as well. On this
  container `numpy 2.4.6` + `scikit-learn 1.9.1` made the sidecar healthy
  (`train_rows 1200`, matching the manifest). Fix the requirement table and add
  both to whatever the offline bundle installs.
- [ ] **X2. Hardware label on every emitted number.** D1 and G1 will produce figures
  on 4 vCPU / 16 GB. The emitter must stamp the live container's CPU and RAM into the
  result file so no reader can merge them with the 2 vCPU / 8 GB report figures.

---

## Standing rules this loop is held to

1. Nothing staged — real binary, real models; a replayed draft says "recorded draft"
   on screen.
2. Offline always, via `offline.sh` or an equivalent routeless namespace; a test must
   fail if an outbound connection is attempted.
3. "Taught capability", never "fine-tuned model". Expert corrections are counted and
   shown, never presented as autonomous learning — `YC_TECHNICAL_CLAIMS.md` records
   that the local model's drafts all failed.
4. Validation is never weakened. Root-cause fixes with regression tests only.
5. Measured numbers only, each live or read from a retained result file with its path.
6. No secrets, no customer data; synthetic or public documents; ephemeral test keys.
7. `feature/airon-teach-demo`, small conventional commits, no force-push, no `main`
   without a reviewed PR.
8. Stop and ask for: naming or branding, licences, patent text, publishing a
   repository, or anything describing this as fine-tuning model weights.
