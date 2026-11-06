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
- [x] **A1. PDF / DOCX / TXT ingestion — DONE.** Commit `<A1_SHA>`.
  `research/capability-learning/harness/ingest_documents.py` yields `Clause`
  records with a 1-based page number and an exact character span; the
  invariant `page_text[char_start:char_end] == clause.text` is asserted for
  **every** clause, OCR'd ones included, because a span that does not slice
  back out of the page is a citation nobody can check.
  *OCR is labelled, not merged.* `extraction` is part of every clause, so an
  image-only page yields `pdf_ocr` and never `pdf_text`. OCR misreads digits
  and this pipeline drafts *thresholds* from clause text, so an OCR'd value
  belongs in the `hypothesis` class that gets a question put to the expert.
  A missing OCR tool is a **refusal naming the apt package**, not a skipped
  page — a silently dropped scanned page is a clause the expert never sees.
  *Fixture:* `make_pdf_fixture.py` builds a byte-reproducible 20-page manual;
  page 19 is an annex table, page 20 is **image-only with 0 text-layer
  characters**, asserted, so the OCR path is genuinely exercised rather than
  assumed.
  *Measured:* 64 clauses — 61 `pdf_text`, 3 `pdf_ocr`. Table rows 3.3 / 6.6 /
  11.0 recovered. OCR on this fixture was **exact, digits included**
  (`['114','10.0']` both sides) — but that is a cleanly rendered 300 dpi
  synthetic page and is **not** evidence about real scans, which is the whole
  reason the label exists.
  *Tests:* `test_ingest_documents.py` **32/32**; full capability-learning
  suite **85/85** (was 53).
  *Deps, licences verified from metadata not memory:* `pypdf 6.21.4`
  BSD-3-Clause, `python-docx 1.2.0` MIT, `Pillow 13.0.0` MIT-CMU; system
  `tesseract-ocr 5.3.4` Apache-2.0 + `poppler-utils`. None restricts
  commercial use. **Rejected:** `pdfplumber` (drags in pdfminer.six →
  `cryptography`) and `pytesseract` (a wrapper around a binary already shelled
  out to).
  *Evidence:* `docs/demo/results/A1_document_ingestion.json`.
  *Two findings recorded:* PDF wrapping puts newlines inside phrases, so a
  clause reads `between 10\nC and 25 C` and any field parser must treat that
  as a space (pinned by a test); and tesseract/poppler are **apt** packages,
  so an air-gapped bundle must carry their `.deb` files.

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

- [x] **X1. Hard-coded absolute model paths — DONE.** Commit `e012395`.
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
- [x] **X6. Sidecar training data gitignored — DONE.** Option (b) as decided:
  the ignore rule stays and `deploy/syntriass/verify_datasets.py` regenerates
  the seeded dataset, checking every split against the digest pinned in the
  tracked `MANIFEST.json`. It reads that manifest **from git, not disk** —
  a regenerated run rewrites it, so comparing the working copy against itself
  would pass unconditionally. All five splits reproduce byte-identically. A
  mismatch is refused with a non-zero exit, never a warning.
  Both message layers fixed: `sidecar.py` names the file, the cause and the
  two exact commands; `sidecar.rs` reports the child's exit status, the stderr
  log path and a bounded tail of it. A **race was fixed in production code**,
  not papered over in the test — a dying child has not necessarily flushed
  stderr when `try_wait()` first returns, so the most valuable case could
  report an empty log; there is now a bounded 500 ms settle. 5 Rust tests;
  95/0 on three consecutive runs.

- [x] **X7. Python environment pinned — DONE.** `requirements.lock` pins 17
  packages with hashes **derived from wheels actually downloaded** for cp311
  x86-64, not transcribed; `setup_env.sh` installs with
  `pip install --require-hashes`, preferring the bundle's wheels and falling
  back to PyPI only when none are staged. It installs into a **venv**, and
  that is not tidiness: installing system-wide failed outright because the
  lock pins `packaging 26.3` while Debian ships 24.0 with no `RECORD` file.
  Found by actually running the reinstall. `fastembed` is excluded with the
  reason recorded — it would fetch a model from Hugging Face at first use, so
  it cannot be on an offline path. README §1 corrected; `mkconfig.py`'s
  hard-coded `/usr/local/bin/python3` now resolves the venv.
  **Evidence re-run from the lock-installed venv after uninstalling the
  hand-installed packages**, so none of it rests on anything added by hand.

- [x] **X2. Hardware stamp — DONE.** Every file under `docs/demo/results/`
  carries the live container's CPU model, core count, RAM and `gpu: none`,
  plus an explicit note that these are **not** the published 2 vCPU / 8 GB
  bench machine and must never be merged with those figures.

- [x] ~~X2. Hardware label on every emitted number.~~ (see above) D1 and G1 will produce figures
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
