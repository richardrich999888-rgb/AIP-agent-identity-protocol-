# Independent verification — current scope

**Full release verification: NOT READY.** A second machine and external evaluator
have not installed or accepted the complete kit. Source checkouts, unit tests,
new directories and development namespaces do not satisfy that requirement.

## Reproduce the C1 diagnostic

Build a binary from the immutable implementation commit recorded in the evidence,
then run `record_scoreboard.py` as documented in `DEMO_GUIDE.md`. On a disconnected
host, use an already staged binary and Python; the recorder performs no downloads.
It regenerates the exact pinned datasets and refuses a hash mismatch.

Check `result.json`: source SHA and dirty status, binary hash, hardware and limits,
per-case status, full elapsed times, model calls (zero), and limitations. Inspect
the actual `scoreboard.json` files instead of relying only on the summary. The
transformer candidate must still fail `val-09`; hiding it invalidates acceptance.

```bash
sha256sum target/debug/syntriass
cargo test --locked -p syntriass-runtime --test teaching_scoreboard
cd /path/to/recorded/output
sha256sum -c SHA256SUMS
```

The suite signature is Ed25519 over `syntriass-expert-suite/v1\n` followed by compact
JSON with fields in this exact order: `suite_id`, `tenant`, `task`, `expert_id`,
`cases`. Each case is ordered `id`, `text`, `expected`, `counterexample`. Use the
operator's independently held expert public key. The retained public key in this
synthetic exercise is evidence of which test key was used; it is not independent
proof that a domain expert authorized it. `suite.rs` defines the canonical bytes.
The scoreboard recomputes validation; it does not accept an imported verdict.

The diagnostic JSON is **unsigned**. Existing validation/approval records have
their own binding format; no signed per-answer receipt or signed knowledge pack
was added by this iteration. A matching hash is not an approval.

## Verify retained Sniffer Dog evidence

From a W checkout at `6ad92ae` and a built verifier:

```bash
cargo build --locked -p aip-observe-verify
target/debug/aip-observe-verify \
  --observer-id collector.lying --key-version 1 \
  --pubkey-file demos/lying-agent/evidence/2026-11-06/public/observer.pub \
  --batches demos/lying-agent/evidence/2026-11-06/public/attested.archive.jsonl \
  --health demos/lying-agent/evidence/2026-11-06/public/health.archive.jsonl --json
```

Observed again in P0-049: **7 linked signed batches, 86 kernel events, 1 health
record, no signature/chain findings**. Replacing `--batches` with
`demos/lying-agent/evidence/2026-11-06/tampered.attested.archive.jsonl` returns 1.

The retained health state is **ContinuityUnverified**, with zero records asserting
coverage and an unsynchronised clock. Verification proves these signed bytes and
their internal links, not complete observation, an honest root, current sensor
availability or absence of truncation. Independently retained boundary checkpoints
are needed to detect a valid-prefix/suffix truncation. Do not report this as a new
live kernel-observation run.

## External evaluator acceptance still required

The evaluator must obtain a complete immutable bundle and release trust material
independently; install it without internet on supported clean hardware; retain
host identity/provisioning, hashes, signed records, packet captures and interface
counters; run every required mode ten consecutive times and W3 twenty, including
fresh installs every fifth W3 run; preserve failures and reset the relevant pass
count. Reproduce benchmarks on that second machine with its own hardware label.
OVERLAY's original unavailable W4/W5 commits cannot be used as reproduction bases.
