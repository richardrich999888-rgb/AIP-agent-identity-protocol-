# Reproduce the P0-057 checkpoint

Source commit: `5be83a87bec680d26510c2be93e66fdfda008b1e`.
Diagnostic harness commit: `5a7d2625a861821e74f979cd0700fbbe6dbe1de1`.
Evidence files arrive in the subsequent documentation checkpoint; production
source hashes must match that source commit. Use the exact branch checkpoint
linked from PR #23, then check the manifest before running code.

Build with the inherited audited Rust 1.99.1 pins. The local toolchain and
format/clippy manifests and command outputs are retained. Dependency versions
and checksums remain in the unchanged `Cargo.lock`. No credentials are needed
for these synthetic tests; private lab signing keys are ephemeral and never saved.

```bash
cargo test --locked -p aip-core -p aip-reconcile -p aip-mcp-gateway -p aip-observe-verify -- --nocapture
cargo test --locked -p aip-observe --lib --test lifecycle_races --test socket_multiplicity --test container_identity --test blind_spots -- --nocapture
cargo fmt --all -- --check
cargo clippy --locked -p aip-core -p aip-observe -p aip-reconcile -p aip-mcp-gateway -p aip-observe-verify --all-targets -- -D warnings
```

These scoped suites are 455 and 102 executed tests respectively at the recorded
source. Fresh environment results may differ and must be retained. Build failure,
SKIP/early-return, missing privilege, zero tests, timeout and ignored assertions
do not count as a pass. `--offline` works only after the locked dependencies have
been obtained; the original uncached attempt and unchanged-lock online rerun are
both preserved.

For fresh original signed samples, choose a **new** empty output location:

```bash
P0_057_RETAIN_DIR=/tmp/p0-057-fresh-samples cargo test --locked -p aip-observe --lib image_race_ -- --nocapture
cargo build --locked -p aip-observe-verify
python3 -B validation/p0_048/verify_lifecycle_archive.py --verifier target/debug/aip-observe-verify --originals /tmp/p0-057-fresh-samples/cold --output /tmp/p0-057-cold-replay
python3 -B validation/p0_048/verify_lifecycle_archive.py --verifier target/debug/aip-observe-verify --originals /tmp/p0-057-fresh-samples/warm --output /tmp/p0-057-warm-replay
python3 -B validation/p0_057/verify_native.py --verifier target/debug/aip-observe-verify --out /tmp/p0-057-hosted-replay
cargo build --locked -p aip-mcp-gateway --bin aip-execution-assurance
python3 -B validation/p0_057/verify_same_run.py --verifier target/debug/aip-execution-assurance --out /tmp/p0-057-same-run-replay
```

The reused lifecycle verifier checks signatures on the process-sample archive
with its declared empty kernel-event list. Eight local archive checks and six
hosted-original checks do not establish independent administration. Public anchors
in this lab are controller-created review inputs, not institutional trust.

To reproduce the original defect, create an isolated worktree at audit commit
`ceb7682`, apply only `validation/p0_057/iteration-002/baseline-reproducer.patch`
from this checkpoint and run `cargo test --locked -p aip-observe --lib image_race_
-- --nocapture`. Expect both assertions to fail with mixed/stale snapshots.
The patch adds the scheduling hook and tests, not the repair. Do not replace the
original logs or apply the reproduction patch over the corrected source.

The existing `.github/workflows/p0-048-native-qualification.yml` executes the ten
privileged kernel assertions on an explicitly disposable GitHub-hosted VM. The
retained run `43582459564` uses exact head checkout and produces signed originals.
Do not relax the local kernel, use a production host, attach XDP to a real
interface, or count fixture events as live capture. Independent two-host testing
requires the separately approved environment described in TWO_HOST_QUALIFICATION.

Audit replay: copy `iteration-001/provider-snapshot.json` into a new output
directory, then run `python3 -B validation/p0_057/audit.py --refs
validation/p0_057/iteration-001/revisions.json --out NEW_DIRECTORY`. Compare
`inventory.json.gz` and `ancestry.json` with the retained originals. The snapshot
requires the recorded Git objects; it does not use today's moving branch heads.

Verify retained bytes from each iteration directory with `sha256sum -c SHA256SUMS`.
Those unkeyed manifests detect accidental changes relative to the reviewed
checkpoint; authenticate the Git revision and public anchors independently.

For the separate real gateway trial, check out ContextForge `ff6a566a` in an
isolated directory and follow the exact commands in
`iteration-002/gateway-runtime-command/result.json`. Its `uv.lock` hash must
match `integrations/mcp-gateway/contextforge.lock.json`; use
`uv sync --locked --no-dev --no-install-project --python python3.12` there.
Build `cargo build --locked -p aip-mcp-gateway --bin aip-tool-receipt --example
contextforge_fixture`, then run `validate_contextforge.py` with that environment,
the two binaries, and a fresh output directory. The fixture supplies test
authority only; do not present this trial as a model or kernel workload.

Portable diagnostic checks:

```bash
python3 -m unittest discover -s validation/enterprise -p test_gateway_diagnostics.py -v
python3 -m unittest discover -s validation/enterprise -p same_run_controls_test.py -v
```

The genuine same-run workflow requires its declared disposable hosted Linux
environment and actual local model. The original failed ZIP and job log are
immutable evidence. New attempts get separate source/run identifiers and cannot
replace the failed recovery. Missing receipt means refusal; journal diagnostics
are never eligible substitutes.
