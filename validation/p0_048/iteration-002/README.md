# Iteration 002 — socket multiplicity evidence

Parent commit: `40f2c1bd003e5c40378fb7e91ec89b4de9a03fbf`.
Date: 12 November 2026 (Asia/Kolkata); command records use UTC.
This is a bounded B work item, not full B/J/L acceptance.

## Results

| Check | Actual result | Qualification |
|---|---|---|
| New live regression on unchanged production baseline | 1 failed, 1 passed | Four copies of one signed socket record counted as four facts. Failure preserved. |
| Baseline 14-test end-to-end suite under four churn threads | 13 passed, 1 failed | Honest run had five records versus two in the replay comparison; 307,193 peer-confirmed loopback connections. |
| Fixed unit suites (`aip-observe`, `aip-edge`, edge observer) | 109 passed | Includes 20 new unit regressions: reviewed PR #19 plus shared-join/process-lifetime guards. |
| Full `aip-edge` suite | 80 executed passes, 1 BLOCKED | Rust prints 81 ok; PID-namespace test returns early on EPERM. Includes 30 unit tests already counted above. |
| Selected sensor suites | 68 executed passes, 3 BLOCKED | Rust prints 71 ok; three netlink-connector tests return early on EPERM. See `blocked-tests.json`. |
| Same end-to-end suite under churn after fix | 14 passed | Same command/test assertions; 341,191 peer-confirmed connections. No churn worker errors. |
| Separate fstat/procfs comparison under churn | 1 passed | 40 samples × 3 held sockets: every count exactly one. 193,251 churn connections; zero repeated target rows happened in this run. Deterministic duplicate fixtures still exercise that branch. |
| Shared `ghost-demo` caller | 13 passed | Live socket and signed-verdict tests; no skipped checks in visible output. |
| New live regressions rerun with original archive retention | 2 passed | Three synthetic runs: honest, self-report-only and observer loss. |
| Offline native verifier, final harness | 6 scoped checks passed | Two batch+health archives accepted; outage missing-health request refused; outage initial batch signature alone accepted; one-byte mutation and wrong key rejected. No outage coverage claim. |
| Rust formatting / scoped Clippy with denied warnings | PASS / PASS | Workspace formatting; all targets in modified crates and `ghost-demo`. |
| Python syntax / final source-and-evidence checks | See `final-checks.json` | No native release or clean-machine qualification is inferred. |

Do not sum overlapping reruns. The primary suites cover **241 distinct
executed passes and four explicitly BLOCKED tests**, including 23 new
regressions (20 unit, two live edge, one fstat comparison). Full-workspace
debug/release tests, live auditd comparison and the enterprise release gate
are not established by that number.

The first offline-harness attempt expected a health file after intentionally
killing the observer, and failed with native exit 2. Its logs and mutated
derivatives remain in `offline-verification/`. The corrected harness adds a
negative check requiring that refusal and checks only the surviving initial
batch separately. It neither supplies a fabricated health record nor weakens
the native verifier. Results are in `offline-verification-final/`.

## Reproduction and provenance

Every `*.json` command record stores exact argv, selected environment, start
time, elapsed wall time, exit code and log hash. `baseline.json`, binary hashes
and `tested-source-hashes.json` bind these runs to their source/build. The new
regression was first run before any production file changed. The baseline
churn binary and sibling binaries were built before the patch and were not
rebuilt during that run.

Rust **1.99.1**, the repository's retained toolchain version, was installed
only after the audit. `toolchain.json` pins official manifest/component URLs,
SHA-256 values and MIT/Apache licence texts; `toolchain-install-script.txt`
retains the exact host-local installer. Download checksums were verified over
TLS; no upstream detached-signature verification is claimed. Cargo used the
unchanged root lockfile. Initial dependency retrieval was online; subsequent
listed Cargo commands use `--locked --offline`. This is not an air-gap bundle.

Representative commands, from the repo root with that toolchain on PATH:

```sh
cargo test --locked --offline -p aip-observe -p aip-edge -p aip-edge-observer --lib --bins
cargo test --locked --offline -p aip-edge
cargo test --locked --offline -p aip-observe --test sniffer_dog --test adversarial --test observer_integrity --test container_identity --test restart_continuity
cargo test --locked --offline -p ghost-demo --test live --test signed_verdict -- --nocapture
cargo test --locked --offline -p aip-edge --test end_to_end --no-run
python3 validation/p0_048/socket_churn.py --report /tmp/p0-048-churn.json -- /path/to/target/debug/deps/end_to_end-HASH --test-threads=4
P0_048_RETAIN_DIR=/tmp/p0-048-fresh-originals cargo test --locked --offline -p aip-edge --test socket_duplicates -- --test-threads=1
P0_048_RETAIN_DIR=/tmp/p0-048-fresh-originals python3 validation/p0_048/socket_churn.py --report /tmp/p0-048-fstat-churn.json -- cargo test --locked --offline -p aip-observe --test socket_multiplicity -- --nocapture
cargo build --locked --offline -p aip-observe-verify
python3 validation/p0_048/verify_socket_archives.py --verifier /path/to/target/debug/aip-observe-verify --originals /tmp/p0-048-fresh-originals --output /tmp/p0-048-fresh-verification
cargo fmt --all -- --check
cargo clippy --locked --offline -p aip-observe -p aip-edge -p aip-edge-observer -p ghost-demo --all-targets -- -D warnings
```

Use fresh retention/output directories: the scripts refuse overwrites. Read
the test-executable path from Cargo's `--no-run` output. Exact host paths used
here are in the command JSON. Kernel skip diagnostics were rerun with
`--nocapture`; blocked gates are excluded from the executed-pass total.

`originals/` retains the actual synthetic batch/health/claim/public-announcement
files, signed expectations, public decision anchors and derived reports.
Observer loss produced no health file; it stays absent. Mutation files are
labelled and kept separately. Public anchors originate from the same-host
synthetic fixture: signature integrity is reproducible, independent key
custody is not established. Health in this reference does not state clock
synchronisation. The offline verifier has no runtime package download; no
fresh-machine firewall/offline deployment qualification was performed.

`SHA256SUMS` covers this iteration's changed source, documentation and retained
evidence, excluding itself. Prior iteration checksums stay unchanged and must
be evaluated against their original commit (`40f2c1b`) when a checkpoint has
subsequently changed. Historical signed originals are not rewritten.

Publication preflight found that the repository's global JSONL ignore rule
excluded the raw archives, so the ten explicitly reviewed original/mutation
JSONL files were added explicitly before publication. It also flagged Cargo's
trailing blank lines in eight original logs. The existing `.gitattributes`
policy for preserving generated logs was extended only to this directory's
log EOFs; source whitespace and all security scanners remain unchanged.

## Remaining gates

The host refuses the process-event connector and new PID namespaces (EPERM).
Qualifying those four tests needs a supported disposable Linux host with the
required kernel facilities/capabilities. No host security setting was relaxed.
The fstat comparison is a second interface on the same kernel, not auditd,
Tetragon, independent administration, logical-agent attribution or capture-rate
ground truth for every process. Full B and C–L remain open.

Prior-head Security CI failed: Gitleaks matched two tokenizer SHA-256 strings
in the audit inventory, and Trivy reported four HIGH findings in an unchanged
retained Helm render (host network/PID, root context, /proc mount). No scanner
suppression or evidence deletion was added. CI for the publication commit is
reported on draft PR #20; pending/blocked jobs are not passes.
