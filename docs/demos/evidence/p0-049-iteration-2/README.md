# Dependency and audit-gate evidence

**Release NOT READY.** These are unsigned development/test records. They do not
constitute signed answer receipts, a distribution manifest or rehearsal passes.

`local-result.json` binds the tested source files by SHA-256 and records the dirty
working-tree state honestly. The implementation commit retains those same bytes.
The old database fixture and its provenance live in
`sovereign/vanian-sovereign/tests/fixtures/sqlite-032/` at the repository root.

- `runtime-tests.txt`: 284 passes across the runtime and corpus crates, including
  19 namespace execution tests and two old-database regression tests.
- `consumer-tests.txt`: 144 passes in the other rustix consumer crates.
- `audit-gate-tests.txt`: four passes using the real workflow command and a
  temporary Cargo stub. `audit-control.json` preserves the old false-green result.
- `audit-before.json` and `audit-after.json`: real cargo-audit 0.23.0 outputs for
  the old and changed lockfiles against the same pinned advisory database, with
  no ignore list. Exit statuses and commands are in `audit-status.json`.
- The two advisory Markdown files are exact copies from RustSec commit
  `fd6f39814c4d3c359fdbe223d0280dec4933f78f` (CC0-1.0).
- Dependency trees, update output, clippy and the old fixture generator output
  are retained alongside those records. The SQLite version actually linked is
  3.54.1; old fixture generation asserted 3.46.0.
- `deny-*.jsonl` and `deny-status.json`: cargo-deny 0.20.2, exit 0, with the
  unchanged policy. The raw stream retains one unmatched existing advisory
  exemption warning and 68 duplicate/wildcard warnings; all four check classes
  have zero errors. Nothing was suppressed to get this result.
- `scoreboard/`: a clean rebuild/run at implementation commit
  `9e3909eea8328d7e81a5887a6e80430237642616`. The same capability hashes and
  14/14, expected 11/12 rejection, 12/12 results survive the dependency upgrade.
  Suites are signed with an ephemeral synthetic test key; diagnostics are
  unsigned. Private keys are not retained. The separate `result.json` contains
  actual hardware, binary hash, counters, exact CPU/RSS and timings. No timing
  is combined with iteration 1 or converted into a performance range.
- `ci-source.json`: source workflows were queued and had no assigned jobs when
  inspected. No new remote check was counted as passed.

From this directory, run `sha256sum -c SHA256SUMS`; inside `scoreboard/`, run its
own checksum check. Verify suite signatures with iteration 1's independent
verifier and independently held trust anchors. The aggregate manifest is
unsigned and proves consistency only with a manifest the evaluator already trusts.

Only native Linux behavior was exercised. The developer tool installation and
crate staging used the network. Neither malformed-WAL exploit reproduction nor
full offline installation is claimed. Read the iteration report and current PR
for subsequent CI results; earlier snapshots remain immutable. An external
evaluator must independently establish its trust anchors.
