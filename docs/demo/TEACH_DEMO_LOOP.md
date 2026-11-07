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
- [x] **A1. PDF / DOCX / TXT ingestion — DONE.** Commit `84bc3c7`.
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

- [x] **A2. Teach session API — DONE** (`d01ca3a`). `syntriass teach
  start --doc <file> --page <n> --clauses <A1.json> --tenant T --task X
  --expert E (--rule TEXT | --rule-file F) --examples EX.jsonl`, plus
  `teach list` and `teach show`.
  *Boundary:* the session contract and every invariant live in
  `sovereign/syntriass-runtime/src/domain/teach.rs` (pure — no IO, no clock,
  no randomness; `now_ms` is an argument); persistence is
  `adapters/teach_store.rs`; the CLI only parses, hashes the document and
  wires the two. Clause extraction stays in the A1 Python ingester, whose
  JSON is the contract between them.
  *Measured, live, in one run:* text-layer session from page 2 — **4 clauses
  cited, 3 examples (1 allowed / 2 not_allowed), 0 flagged for
  confirmation**; OCR session from page 20 — **3 clauses, all 3 flagged**;
  file mode **0600** and tenant directory **0700** read back from the
  filesystem, not asserted in prose; **2** sessions listed for the tenant;
  **5 refusals** each the real stderr of a real non-zero exit (document
  edited after extraction, one-sided examples, a requested page with no
  clause, a session edited on disk, a cross-tenant read).
  *Independent corroboration:* the canonical encoding is reproduced in
  Python from the stored file and hashed with `hashlib`, with no Rust
  involved, and agrees with the `session_id` the binary wrote. **26
  mutations** — one per hashed field, including clause and example ordering
  — each break it, so the check is not vacuous.
  *Tests:* **78 new Rust** (44 core, 15 store, 19 through the real binary);
  crate **173/173**, was 95. **32 new Python**; capability-learning
  **117/117**, was 85. `cargo fmt` and `clippy -D warnings` clean.
  *No model call, and that is asserted:* a teach session is bookkeeping over
  an expert's words and a document's bytes. The config's model fields are
  `UNUSED_BY_TEACH` and the recorded run states `model_calls: 0`.
  *Three design decisions, stated because each refuses something:* (a) **one
  of each label is required** — a single-class example set cannot
  distinguish a rule from a constant, so a suite built from it would pass a
  procedure that always answers the one label it ever saw; (b) a clause's
  `text` must be exactly as long as its `[char_start, char_end)` span claims,
  **counted in characters**, so a citation nobody can check back against the
  page is refused; (c) the document is **re-hashed from disk** at
  `teach start` and a clause set from another revision is refused, because
  the spans would otherwise point into text that no longer exists.
  *Evidence:* `docs/demo/results/A2_teach_session.json`.
  *Two findings recorded:* a **check-ordering defect found by the CLI test,
  not by review** — asking to teach from a page the ingester found nothing on
  answered "clauses: at least one clause must be cited", which does not tell
  the expert which page failed; `NoClauses` was removed and the page-coverage
  check now owns that case (regression test in `domain::teach`). And X2's
  hardware stamp was hand-written into A1's result file; a second hand-copy
  is how two result files come to disagree about the machine, so it now comes
  from one shared emitter, `research/common/demo_evidence.py`.
  *Scope beyond the backlog line, deliberately:* `teach list` and `teach
  show` were added alongside `start`. Without a read path the 0600
  persistence and the stored-hash check cannot be demonstrated from the CLI
  at all, so `start` alone would have been untestable end to end.
- [x] **A3a. Deterministic draft from a session — DONE** (`9599325`).
  `draft_from_session.py`: session → the IR fields the **cited clause text
  determines**, with every other field classified `evidence` / `hypothesis`
  (alternatives enumerated) / `issue`, and one question per unsettled field.
  Reuses the existing vocabulary in `atomic.py` rather than inventing a
  parallel one; no model is loaded and none is reachable.
  *Measured on the real EP-114 corpus the task spec names* (22 cited clauses →
  16 claim units): **6 evidence, 8 hypothesis, 8 issue**; 2 complete claims
  (`missing_input` → `INSUFFICIENT_INPUT`, `default_outcome` → `PASS`); the
  validity range read as **10–75 °C** on `temperature`; `topic_terms`,
  `inputs` and `rules` left unfilled; 16 questions; status
  `NEEDS_EXPERT_ANSWERS`.
  *The honest reading, which is the point of the split:* a deterministic pass
  does **not** produce a compiling capability, and the draft says so. What it
  does produce is the denominator — how much of the IR the document fixes on
  its own — recorded before any model exists to take credit for the rest.
  *Independently cross-checked:* every filled value is asserted in the
  recorded run against literals read from the corpus by hand, and the sentence
  each came from is confirmed present in the file, so the evidence does not
  rest on the drafter agreeing with itself.
  *Tests:* `test_draft_from_session.py` **26/26**; capability-learning
  **143/143** (was 117). The load-bearing one is negative: no filled value may
  be absent from the text it is attributed to.
  *Evidence:* `docs/demo/results/A3a_deterministic_draft.json`.
  *Two findings recorded.* (1) **A segmentation mismatch between A1 and the
  claim extractors.** A1 splits at `. ; : ! ?` so a citation is a span a human
  can check, which puts `Step 1 validity:` in a *different clause* from the
  numbers it heads — and `plausible_kinds` needs the word and the numbers in
  one unit, so fed A1's fragments it determined **nothing at all** (0 claims
  on the first run). Cited clauses are now rejoined in document order and
  re-split at sentence ends, with each claim unit recording the clause ids it
  came from. Neither splitter was wrong; they are for different jobs, and the
  bridge belongs between them. (2) **My A1 PDF fixture's prose is not the real
  corpus's prose.** `make_pdf_fixture.py` writes "shall be between 10 C and
  25 C"; the corpus writes "Step 1 validity: … between 10 and 75 degrees
  Celsius inclusive". The extractors were built for the latter, so the fixture
  is fine for A2 (citation plumbing) but cannot exercise A3a at all. A3a is
  therefore recorded against the real corpus.
  *One deterministic rule added, and only one:* in "between A and B UNIT" the
  unit is written once and applies to both bounds — the IR's `validity` has a
  single `unit` field for `min` and `max`, so there is no second unit B could
  have had. Reading it as shared is a reading of the sentence, not a choice
  about it, and it is gated on the clause saying "between" with exactly two
  numbers one of which is tagged. Rules that *would* need judgement
  (`against: limit` with a fraction, which cued input a bare number names)
  were left as `hypothesis` with their candidates rather than guessed.
  *Defect found later, while building B1 on it, and fixed:* claim-unit ids
  were not unique. One A1 clause that spans a line break (the corpus header
  line runs into the next sentence) becomes two claim units with the same
  source, and both were called `p1#0`; the lookup by id kept the second, so the
  first unit's question **quoted the wrong sentence**. Ids are now made unique
  by order of appearance (`p1#0`, `p1#0/2`), with a regression test that fails
  on the old code. None of the numbers recorded above changed — 6/8/8, 16
  units, 16 questions, the same two claims — because no `evidence` field came
  from a colliding unit; only the quoted text of one question was wrong.
  *Two more defects, found while designing B2, and fixed* (`12623c4`):
  (1) **Leaves left neither filled nor asked.** The rule and range readers
  returned at the first leaf they could not determine. On EP-114 none of the
  four rules had its reading or its outcome classified at all, so an expert
  could have answered every B1 question and still held four rules that cannot
  compile, with nothing saying so. Each leaf is now classified on its own; a
  rule written "corrected <reading>" makes the reading a choice between the
  reading itself and the corrected value instead of evidence.
  (2) **A latent crash.** A complete rule was handed to `atomic.assemble` in a
  shape it does not take, raising `KeyError('conditions')` out of `draft()`
  the first time any rule was complete. EP-114 never reached it because no
  rule there is complete; any procedure with one plain "below 5 megohms,
  reject" sentence would have.
  The A3a recorder's own cross-check had the same blind spot as B1's: it
  compared a dict keyed on the field path. The re-recorded corpus has three
  `rules[].op` and four `rules[].outcome` evidence fields, and such a dict keeps
  one of each. The defect was latent: before the fix A3a produced no rule
  evidence, so no recorded run lost a check to it. (Commit `12623c4`'s message
  says "one rules[].op out of four"; the correct figure is one out of three.)
  It now compares (claim unit, field, value) triples read off the corpus by
  hand.
  **The numbers above are superseded.** Re-recorded on the real corpus:
  **13 evidence, 8 hypothesis, 13 issue** (was 6/8/8); 16 claim units and the
  same two complete claims; **21 questions** (was 16). The 7 new evidence
  fields are the comparison and outcome of the rules, each confirmed against
  the sentence by hand (`<` on the three single-comparison rules; `REJECT`,
  `DRY_OUT`, `DRY_OUT`, `RETEST_30D`). The draft still does not compile, and
  still says so. Tests: 6 new, 5 of which fail on the previous code;
  `test_draft_from_session.py` **34/34**.
  *And a misreported compile status* (`d3cf790`, re-recorded): A3a called
  `compile_ir` with the bare task spec and caught `KeyError`. `compile_ir`
  reads `spec["proposed_by"]` only after validating the whole IR, so every
  draft "failed to compile" with `KeyError('proposed_by')` whatever its IR held
  — the recorded evidence said exactly that. With a complete spec, `compile_ir`
  would instead have *accepted* the EP-114 draft: it does not enforce its own
  schema's `minItems`, so an IR with no rules and no inputs "compiles". A3a now
  checks the compiler's schema strictly first (`schema_subset.py`, shared with
  B2) and then compiles with a complete spec (`ir_check.py`); the recorded
  reason is now the true one — `topic_terms`, `inputs` and `rules` are empty.
  `ir_compiler.py` itself is unchanged, so no v0.2 figure moves.
- [ ] **A3b. Model drafting.** `[B]` until the model bundle exists. The model
  chooses among the alternatives A3a enumerates and fills `topic_terms`,
  `inputs` and `rules`; it must never introduce a value A3a marked as
  determined, and `--no-repair` remains the ablation that proves it does not.

### Phase B — The AI asks the teacher
- [x] **B1. Question generator — DONE** (`a9867ee`).
  `question_generator.py`: every field A3a could not settle → exactly one
  plain-language question quoting its sentence and citation. Deterministic
  templates only; model rephrasing stays `[B]` and may change wording only,
  never a choice.
  *Three rules that make the questions safe to act on.* (1) **The answer's
  shape is the compiler's own schema** — each `answer_schema` is lifted from
  `ir_compiler.ir_schema(outcomes)`, asserted identical by test, so B2 can
  refuse an answer that cannot compile at the question rather than at compile
  time, and B1 defines no answer vocabulary of its own. (2) **Choices are
  closed wherever the system can close them**, and never include a value
  outside the draft's candidates, the task's outcomes or the compiler's
  enumerations — outcome fields offer the task's vocabulary even when the
  clause names none, which turns "what happens outside the range?" into a
  choice. (3) **An unknown field path fails closed** (exit 3) instead of
  getting a generic question.
  *Measured on the real EP-114 corpus:* of 16 unsettled fields, **12 asked**
  (2 with closed choices) and **4 not asked** — the corpus header line, the
  title sentence, "Confidential." and one more — each listed with a reason,
  never dropped.
  *The check that matters:* for every closed-choice question whose answer can
  be read off the document by hand, the recorded run asserts the true answer is
  among the choices offered — **3/3 reachable** (`INVALID_TEST` for the
  validity outcome; both `>=` and `<` for "at least 1.5 but below 2.0"). A
  choice list that excludes the right answer forces a wrong one.
  *Correction:* the first recording of this run made only **2** of those 3
  checks while the commit that introduced it (`a9867ee`) claimed 3/3. The two
  `rules[].op` checks were keyed on the same question in a dict, so one
  silently overwrote the other. Fixed by making the checks a list and asserting
  the number made; the result file now records `checks_made: 3`.
  *Superseded by the A3a every-leaf fix* (`12623c4`, re-recorded on a clean
  tree): of **21** unsettled fields, **17 asked** (6 with closed choices) and
  the same **4 not asked**. The five new questions: four ask which reading each rule compares, and
  one asks what the "at least 1.5 but below 2.0" rule compares against (it was
  previously asked only its comparison). B1 needed no change: every new path
  already had a template. Reachability checks extended from 3 to **7/7** —
  the two resistance rules must offer `corrected`, the two PI rules `cued_1`.
  *Tests:* `test_question_generator.py` **48/48**; capability-learning
  **193/193**. Every path A3a can emit is parametrised and must have a
  template; questions are asserted free of internal jargon (`[]`, `.*`, "IR",
  "hypothesis", "issue", "evidence", "schema").
  *Evidence:* `docs/demo/results/B1_question_generator.json`.
  *Defect found in A3a and fixed first* (`2e4d2fc`, recorded under A3a):
  colliding claim-unit ids made one question quote the wrong sentence.
  *Finding for E1:* the sentence that answers the validity-outcome question,
  "Outside that range the test is invalid and must be repeated.", is itself
  one of the four not asked, because on its own it states nothing the system
  can use. B1 is right not to infer from it — but the Teach screen must show
  the surrounding text beside each question, or the expert answers without it.
  *Known limit:* "If the resistance is acceptable but PI is below 1.5" lists no
  candidate number, because A3a's candidates exclude unitless numbers. The
  quote shows `1.5`; B1 does not add values of its own.
- [x] **B2. Answer application — DONE** (`50e915b`).
  `apply_answers.py`: draft + task + answers file → the answered IR and one
  edit record per leaf (`path`, `type` from the compiler's schema, `before`,
  `after`, `who`, `when_ms`, `why`, the question it answers), with counts
  printed on screen. Pure core, no model, no clock.
  *What an answer is bound to.* The questions are regenerated from the draft by
  B1, never read from a file, and an answers file must name the SHA-256 of
  those questions **and of the draft** — the draft's document-determined values
  (the 10–75 °C range) appear in no question, so the questions digest alone
  would not notice a draft changed after the expert answered.
  *Refused, the whole file, each problem at its question:* an answer outside
  the question's `answer_schema` (the compiler's own, checked strictly — no
  undeclared fields, no booleans as numbers); **a number the compiler would use
  that the quoted sentence does not state** (`provenance_check` run on the
  answer alone); a word list not copied from the sentence; a leaf the document
  already determined, an object already set, a duplicate scope limit or input;
  a bad `who` (the runtime's teach identifier grammar), `when_ms` or empty
  `why`; more than one author in a file.
  *Elements belong to their sentence.* A range, rule or scope limit enters the
  IR only when every leaf is filled, from the document or from answers, in
  **document order** — B2 never reorders rules. A partly filled one is reported
  with its missing leaves and not emitted. Answering "not applicable" to a
  rule's leaf withdraws the rule, and is refused if another answer fills part of
  it. The IR does not depend on the order answers were written in.
  *Measured on the real EP-114 corpus* (chain A1 → compiled `teach start` → A3a
  → B1 → B2): 17 questions, **16 answered + 1 not applicable**, 0 unanswered;
  **50 leaf edits** by the answerer (54 leaves set; 4 equal the draft's neutral
  correction values and are not counted), **13 leaves from the document**; 6
  elements complete (1 scope limit, 1 range, 4 rules); **the answered IR
  compiles**, with no number lacking a cited source. Every edit is read back
  from the IR at its path by the recorder, independently of B2.
  *Who answered — read this before quoting any number above.* **No domain
  expert.** I read every answer off the corpus myself, each citing its sentence,
  and they are recorded under `engineer:recorder`. This measures the mechanism,
  not how an expert answers; "50 leaf edits" is the cost of answering *these*
  questions, not a measured expert effort. The answered IR is **not scored**
  (`NOT_MEASURED`): C1 does that.
  *Refusal recorded too:* the same answers with three planted faults — 2.5 for
  "below 2.0", "synchronous motors" as the subject, the 11 kV limit taught twice
  — are refused as a whole with exactly those three errors, each at its own
  question, nothing applied.
  *Tests:* `test_apply_answers.py` **62/62**, `test_schema_subset.py` 21,
  `test_ir_check.py` 5; capability-learning **288/288**. Each of the 12 guards
  was disabled in turn and fails at least one test; two (no overwrite, a
  correction set once) are unreachable from real A3a output and are tested on a
  crafted draft, because B2 reads the draft from a file and must not trust it.
  *Evidence:* `docs/demo/results/B2_answer_application.json`.
  *Defects found on the way, all fixed first and recorded under A3a/B1:*
  rule leaves never classified (an expert could answer every question and still
  hold rules that cannot compile), a latent `KeyError` on the first complete
  rule, the misreported compile status, and the A3a recorder's path-keyed
  cross-check.
  *Count caveat for B3:* `leaf_edits` uses the v0.2 definition
  (`correct_ir.leaves`, changed leaves only), so it is comparable with "3 leaf
  edits vs 68" — but it includes leaves the schema requires and the compiler
  ignores (e.g. `number: 0` on a rule compared with the limit).
  *Open for D (approval), not decided here:* the runtime refuses approval when
  `approver_id == proposed_by` (`lifecycle.rs:277`). B2 emits no capability, so
  it sets no proposer; when one is emitted, the proposer must be the person who
  answered, or the teacher could approve their own rules.
  *Not covered by CI:* no workflow runs `research/` tests; they run locally.
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
  *Refusals must be explained in plain words, not as validation errors.* The
  one-of-each-label rule (A2) is a hard requirement and stays one; the Teach
  screen says **"Add at least one example where the answer is NO, so the
  system can tell a rule from a constant."** Same for every other refusal the
  core raises: `TeachError` already names the field and the value, and the
  screen's job is to say what to do about it.
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
