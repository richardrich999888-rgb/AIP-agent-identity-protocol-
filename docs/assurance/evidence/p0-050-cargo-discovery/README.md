# P0-050: Cargo executable discovery

13 November 2026 IST. One bounded item: repair reference executable discovery under Cargo's changed build layout. Source `049f01552e9742af1aeceeb08450a88c1b8d671e`; approved feature/airon-teach-demo, draft PR #21. Release NOT READY.

## Audit and acceptance

Fetched current branches and read the prior exec-env checkpoint at ef23c76. Its teaching/contracts workflows passed, but full CI 43286698986 failed. The quality log shows the floating stable toolchain upgraded from Rust 1.99.1 to 1.100.0. Edge and dependent profile tests guessed target/profile from current_exe; Cargo now ran tests under build/package/hash/out. The separate ghost-demo verifier helper made the same assumption and passed a hash directory as a profile. Missing binaries are genuine harness failures, not passes or evidence-verification defects.

Acceptance: build current sibling binaries and use Cargo-reported executable paths; reject failed builds, missing outputs, wrong target kinds, relative paths and conflicting reports; real relocated adversarial and offline-verifier tests pass; no skipped assertions; full CI and coverage remain separate gates.

## Repair

Edge stores paths from the successful cargo build JSON compiler-artifact messages in its existing once-per-process build cache. Sibling lookup uses that cache and never falls back after a failed build. Installed/reference CLI adjacency behavior remains when no build was requested. The separate ghost-demo test helper similarly selects the current nexora-verify executable from Cargo's report. No filesystem search through unrelated outputs and no stale-file bypass.

Nested builds use --locked --offline, the package manifest, and Cargo's configured directories. Standard debug/release modes are selected; custom profiles and cross-target execution are not qualified here. Cargo/build configuration and repository code remain trusted developer inputs. This is reference/test tooling, not a production deployment mechanism.

The regression harness relocates the real existing test executable to an opaque directory, then runs its unchanged assertions. CI now executes both relocated suites. Parser unit tests reject malformed, missing, relative, conflicting and library-only reports. Duplicate reports of the same path are idempotent and do not become independent evidence.

Primary reference: https://doc.rust-lang.org/cargo/reference/build-cache.html explicitly distinguishes final output from internal build directories and documents the 1.100 layout change. Source/package dependency isolation and all evidence/signature/coverage thresholds are unchanged.

## Fresh local results

- Old edge implementation, relocated real adversarial executable: expected FAIL, 12 failures; original log and command receipt retained.
- Candidate relocated edge adversarial suite: 12 PASS, zero ignored.
- Relocated ghost-demo live_nexora suite: 6 PASS, zero ignored, including real separate-process verification and mutation refusals.
- Artifact parser: 2 PASS (positive, idempotent and negative matrix), zero ignored.
- Formatting and scoped Clippy (warnings denied): PASS.
- First ghost verifier compile/Clippy attempt failed because serde_json was not a direct dev dependency. Original failures retained; corrected using the already locked serde_json 1.0.151, no version upgrade or installation. Exact dev pin, registry checksum c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14, MIT OR Apache-2.0. Cargo.lock only adds the ghost-demo dependency edge.

Local Rust is the existing 1.99.1 toolchain; relocating tests reproduces the invalid layout assumption without pretending this is native Cargo 1.100 validation. The initial edge success preceded adding --offline to nested builds; a fresh published-source relocated rerun also passed all 12 cases with --offline enabled. Hosted CI must still validate the current 1.100 toolchain. Logs and receipts retain the distinction. Local command durations are not benchmarks. Counts overlap existing suites and do not count as full demo rehearsals.

## Remaining acceptance

Hosted source CI/coverage pending. The four historical Helm HIGH findings, unsupported local ptrace, executable TOCTOU, independent custody, clean-host kit and required live rehearsals remain open. Earlier signed archives remain unchanged; these component tests do not retain a new complete demo archive or establish enterprise qualification.

Next: inspect full CI/coverage and fix any remaining scoped regression before accepting the repair; then classify retained Trivy findings without altering originals.
