# C2 — signed lifecycle actions (iteration 1)

Source `dbafea499c136db76e25c187480a443f3805f155`, recorded on a clean tree
(`host-and-source.json`). Release remains **NOT READY**; C2 remains partial.

## What changed

Before this source, `cap-activate`, `cap-rollback` and `cap-transition` recorded
whatever `--actor` and `--role` strings were passed, and nothing at use time
checked how a record became ACTIVE: a stored record whose `state` was edited to
`ACTIVE` executed (`a_record_hand_set_to_active_is_refused_at_use_time` first
asserts that the pre-existing check accepts it).

With `"require_signed_lifecycle": true` and an `operators` trust store:

- every lifecycle action is an Ed25519 `SignedAction` (`capability/action.rs`)
  binding capability hash, edge, role, signer, history position (`seq`), the
  hash of the history before it (`prev_chain`), time and reason;
- `--key` is required and `--actor` is refused; operator edges need a key in
  `operators`, approver edges a key in `approvers` and, under strict approval
  policy, a current authority grant; no caller can sign as the validator;
- at use time (CLI `approval_current` and the serving path `app.rs`), an ACTIVE
  record must end in a signed move into ACTIVE whose recorded fields equal the
  signed ones, at its own history position, by a currently authorized signer.

Default off: legacy behaviour is unchanged (Python 490/490 drive it unmodified).
Also, in both modes, activate/rollback now authorize and compute every change
before writing any (regression test for a refused supersession that previously
left no version active).

## Results

| check | result | file |
|---|---|---|
| `tests/signed_lifecycle.rs` | 17/17 | `signed-lifecycle-tests.txt` |
| serving-path test (`runtime_app.rs`) | 1/1 | `serving-path-test.txt` |
| `cargo test -p syntriass-runtime` | 221/221 (203 before) | `runtime-full.txt` |
| `cargo test -p vanian-sovereign` | 113/113 | `vanian-sovereign-full.txt` |
| capability-learning Python, real binary | 490/490, no skips | `python-capability-learning.txt` |
| `cargo clippy --all-targets -- -D warnings` | exit 0 | `clippy.txt` |
| `cargo fmt --all --check` | exit 0 | `fmt.txt` |
| each of 8 defences disabled alone | every one fails a test | `mutations.txt` |

`mutations.txt` keeps one discarded attempt: the first `--actor` mutation did
not apply because rustfmt had re-wrapped its anchor line, so its "ok" was the
unmutated code. It was re-run with the current text and fails as required.

No hosted CI run is recorded here; both `ci.yml` and `teach-scoreboard.yml` run
the whole `syntriass-runtime` test set, so these tests run there on push.

## Not provided — read before relying on it

- **Freshness against storage rollback.** Whoever can rewrite the state
  directory can truncate a record's history back to an older, genuinely signed
  activation; every remaining signature verifies. Needs the history anchored in
  an append-only log.
- **Operator keys are not tenant/domain scoped** (approver actions are, through
  the authority grant).
- Keys are files; this is not human login, an independent administration
  boundary, or authenticated distribution of the trust stores.
- Store writes are still sequential files: a crash or I/O failure between two
  writes of one supersession can leave a partial change. Only logic refusals
  are now write-free.
