# Stored teaching session → signed-suite scoreboard

**Bounded C1 integration, not full teaching acceptance.** This is an
EXPERT-GUIDED TAUGHT CAPABILITY diagnostic. It makes no model call, creates no
approval and does not activate or write to the original capability lifecycle.

Use the operator's existing runtime configuration, verified stored session,
task specification, expert answer file, original source and signed suite:

```bash
python3 research/capability-learning/harness/score_teaching_session.py \
  --binary /absolute/path/to/syntriass \
  --config /absolute/path/to/operator-config.json \
  --tenant halvorn-power --session SESSION_CONTENT_HASH \
  --session-task tx_acceptance \
  --task research/capability-learning/tasks/tx_hutx2.json \
  --answers /absolute/path/to/answers.json \
  --document /absolute/path/to/halvorn-hu-tx-2.txt \
  --suite /absolute/path/to/expert-suite.json \
  --out /absolute/path/to/new-scoreboard
```

`--session-task` identifies the stored session's task; the signed suite must
also name the task specification's `intended_task`. Task and configuration
policy/domain must agree. Trust comes from `config.experts`, never a key bundled
in the submitted suite. This CLI assumes an authorized local operator owns the
configuration and stored session. It is not an authenticated REST/UI endpoint.

The command loads the session through native `teach show`, which verifies its
content hash. It snapshots the source and checks the session's full document
hash and every cited span. It regenerates the draft and questions, checks answer
bindings and cited values using B2, and compiles only those checked answers.
An unchanged native validator evaluates the signed suite in disposable state.
The runtime's bound document digest must match the supplied source body.
Untrusted expert, mismatched task/tenant, insufficient clearance, stale answers,
unsupported values and forged signatures cannot produce a passing diagnostic.

Exit **0** means PASS_SIGNED_SUITE. Exit **3** means REJECTED_BY_SUITE; show the
failed input, expected/actual result and question links. Exit **2** means REFUSED;
read `result.json` and retained command stderr. Output directories are owner-only
and must be new. Preserve a failed directory and correct the input in a new run.
No input file, proposed production capability or prior evidence is overwritten.

`scoreboard.json` adds exact regenerated question IDs, quotations, citations and
answer edits to failed rows. `fired_rule_author` links a question to the executed
rule's source sentence. `field_review_candidate` may instead concern an earlier
missing guard. Neither is a claim of root cause. Unmatched fields remain visible.

## Run the synthetic component demonstration

With a staged binary, Python 3.10+, Git and this checkout:

```bash
python3 research/capability-learning/harness/record_session_scoreboard.py \
  --binary target/debug/syntriass --out /tmp/p051-session-new
(cd /tmp/p051-session-new && sha256sum -c SHA256SUMS)
```

Expected: original control **11/12, exit 3**; corrected validation **12/12,
exit 0**; corrected attacks **26/26, exit 0**. Six frozen nonactivation cases are
included in 26. The recorder's exit 0 means these bounded expectations held.
`rejected-control/scoreboard.json` must link `val-09` to the actual source-linked
exclusion question. The synthetic engineer's answers and temporary evaluator key
do not establish human expertise, independent administration or approval.

Private keys are created only in temporary working state, removed before the
recorder finishes and excluded from retained output. Original signed suites,
public trust, source, answers, command output and metadata remain. Reports and
hash manifests are unsigned; rerun the validator instead of trusting PASS text.
Authenticate public trust separately before relying on any third-party evidence.

```bash
SYNTRIASS_BIN="$PWD/target/debug/syntriass" python3 -m pytest -q \
  research/capability-learning/tests/test_session_scoreboard.py
```

This first integration accepts UTF-8 TXT documents in the existing corpus format.
PDF/DOCX evaluation needs a reviewed extraction-to-corpus binding. Session example
agreement is **NOT_MEASURED**: `allowed`/`not_allowed` labels do not define a
mapping from the capability's multiple outcomes. No mapping is inferred. This
gap, authenticated approval, UI, packs and per-answer receipts remain open.
There is no model, kernel sensor, packet capture, full offline installation or
full-mode rehearsal in this component exercise.
