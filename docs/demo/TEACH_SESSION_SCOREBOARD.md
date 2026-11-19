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

Without an example map, exit **0** means PASS_SIGNED_SUITE and example agreement
remains NOT_MEASURED. With a map, exit **0** means PASS_SESSION_AND_SUITE. Exit
**3** means REJECTED_BY_SUITE or REJECTED_BY_EXAMPLES; show the failed input,
expected/actual result and question links. Exit **2** means REFUSED;
read `result.json` and retained command stderr. Output directories are owner-only
and must be new. Preserve a failed directory and correct the input in a new run.
No input file, proposed production capability or prior evidence is overwritten.

`scoreboard.json` adds exact regenerated question IDs, quotations, citations and
answer edits to failed rows. `fired_rule_author` links a question to the executed
rule's source sentence. `field_review_candidate` may instead concern an earlier
missing guard. Neither is a claim of root cause. Unmatched fields remain visible.

## Explicit example review

A session's binary labels do not define the meaning of every capability outcome.
An operator can supply `--example-map /absolute/path/to/example-map.json` and a
new `--out` directory. The map must bind all six values from the preceding
diagnostic: session ID, bound capability hash, full source-document SHA-256,
and exact task, answers and signed-suite file SHA-256 values. Changing any of
these requires a new review declaration. The original session hash also binds
the example identities, inputs, labels and reasons.

For the existing synthetic maintenance example, the explicit declaration is:

```json
{
  "schema": "syntriass.teach-example-map/v1",
  "bindings": {
    "session_id": "COPY_FROM_RESULT",
    "capability_hash": "COPY_FROM_RESULT",
    "source_sha256": "COPY_FROM_RESULT",
    "task_sha256": "COPY_FROM_INPUT_SHA256_TASK_JSON",
    "answers_sha256": "COPY_FROM_INPUT_SHA256_ANSWERS_JSON",
    "suite_sha256": "COPY_FROM_INPUT_SHA256_SUITE_JSON"
  },
  "review": {
    "who": "COPY_SESSION_EXPERT_OR_ANSWER_AUTHOR",
    "when_ms": 1,
    "why": "Replace with the actual review reason and current timestamp."
  },
  "outcomes": {
    "ACCEPT": "allowed",
    "REMOVE_FROM_SERVICE": "not_allowed",
    "INVALID_TEST": "not_allowed"
  }
}
```

The values above are a template, not approval or a ready-to-use map. `when_ms`
is a declared timestamp, not proof of time or an authority-expiry check. A
matching `who` string does not authenticate that expert. C2 must sign and verify
the complete teaching authorization, including the reviewed map digest.

The native engine replays the original examples. Unmapped outcomes remain
withheld. The capability-defined missing-input outcome, native out-of-domain,
ambiguous or evidence-required results, and execution failures cannot satisfy a
negative example. Attempts to map a missing-input/native refusal to a binary
answer are refused. Results retain the native outcome beside the reviewed label.
Examples are reported separately and add **zero** cases to the independent signed
suite. Passing examples never override a failed suite. No approval, activation
or change to the original lifecycle occurs; the combined verdict is unsigned.

## Run the synthetic component demonstration

With a staged binary, Python 3.10+, Git and this checkout:

```bash
python3 research/capability-learning/harness/record_session_scoreboard.py \
  --binary target/debug/syntriass --with-examples --out /tmp/p051-session-new
(cd /tmp/p051-session-new && sha256sum -c SHA256SUMS)
```

Expected: original control **11/12, exit 3**; corrected validation **12/12,
exit 0**; corrected attacks **26/26, exit 0**. Six frozen nonactivation cases are
included in 26. The recorder's exit 0 means these bounded expectations held.
The explicitly reviewed examples pass **3/3 separately** in each scenario.
The control still exits 3 even with passing examples. Original pre-review
NOT_MEASURED outputs are also retained. Omitting `--with-examples` preserves
that earlier unmapped behavior.
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
  research/capability-learning/tests/test_session_scoreboard.py \
  research/capability-learning/tests/test_example_mapping.py
```

This first integration accepts UTF-8 TXT documents in the existing corpus format.
PDF/DOCX evaluation needs a reviewed extraction-to-corpus binding. No example
mapping is inferred. Authenticated approval, UI, packs and per-answer receipts
remain open.
There is no model, kernel sensor, packet capture, full offline installation or
full-mode rehearsal in this component exercise.
