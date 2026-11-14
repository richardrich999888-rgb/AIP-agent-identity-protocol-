# P0-050: final-exec environment isolation

13 November 2026 IST. One bounded continuation from 699abb7. Source fix `9d25aa44971db54a3f5d9af515386c3240cc14c5`, tree `9b59f94364243040823c74ceb80dd0d79d2c27b5`, approved feature/airon-teach-demo, draft PR #21. Release NOT READY.

## Ground truth and acceptance

Freshly inspected completed prior CI 43253800291: format, lint, full debug/release tests, dependency audit/deny, Python SDK, PostgreSQL and RED-ledger jobs PASS; coverage FAIL. Its original full decoded quality and coverage logs are retained losslessly in ci/*.log.gz. This replaces the prior pending status, not the original checkpoint. Security remains a separate failed gate with four historical Helm findings.

Coverage's sandbox_environment_is_empty test failed because `/usr/bin/env` printed `__LLVM_PROFILE_RT_INIT_ONCE=__LLVM_PROFILE_RT_INIT_ONCE`. The other 31 sandbox tests passed. Outer Command.env_clear does not prevent an instrumented helper runtime from adding its own environment later; libc::execv then inherited that environment.

Acceptance: explicitly empty environment at the final exec boundary, unchanged strict integration assertion, normal and instrumented regression PASS, existing execution acknowledgement and negative controls preserved, hosted coverage rerun. No allowlist of special instrumentation variables, skipped security test, weaker threshold, new dependency or host-policy relaxation.

## Smallest defensible change

Final syscall is now execve with an explicit one-null-pointer envp vector. argv and target path remain unchanged. The shared unsafe syscall wrapper does not allocate between fork and exec. The private exec-event/status protocol, signing, consumed authority and CannotProve remain untouched. Primary API reference: https://man7.org/linux/man-pages/man2/execve.2.html (envp explicitly supplies the new program environment).

The new unit regression starts a separate test process with only synthetic environment variables. It then exercises the same final syscall through pre_exec, asserts successful real `/usr/bin/env` execution and zero stdout. No process-global environment mutation, ptrace requirement or namespace skip. The original sandbox_environment_is_empty integration assertion remains unchanged and runs in hosted CI.

## Fresh local evidence

- Isolated baseline using execv: expected FAIL, exit 101.
- Same regression after execve fix: PASS.
- Regression built with RUSTFLAGS=-Cinstrument-coverage: PASS; not a full coverage report.
- Scoped Clippy with warnings denied: PASS. Formatter succeeded.
- Exact commands, source hashes, host and durations: local/*.json; raw output losslessly compressed in local/*.log.gz. Totals overlap; one regression is not a full product acceptance.

An initial test-harness attempt ran before Command had applied the synthetic environment and printed ambient configuration. Its original output is retained locally and deliberately not published; its digest and omission reason are recorded. The corrected isolated harness still reproduced the defect before the fix. A direct cargo fmt invocation failed because cargo-fmt was not on that invocation's PATH; rerunning through the existing task-local toolchain recorder succeeded. No dependency installation was required.

Local full sandbox execution remains blocked by ptrace EPERM from the previous checkpoint; this iteration does not call it passed. The kernel-independent final-exec regression is valid locally. Existing synthetic signed originals and offline replay remain at ../p0-050-launch/ and are historical, not regenerated for this change.

## Hosted status and remaining work

Source teaching 43285784481 PASS: 314 Rust (201 runtime + 79 sovereign unit + 32 sandbox + 2 SQLite), 267 focused Python, no failures/ignored cases. Full log and complete original signed artifact 13974667557 are retained. ZIP SHA-256: `5b5f28f8011c6cc2d56879b1201f25d962f3f80449be12c6872c527ba79e5a1f`. All sandbox controls and the unchanged empty-environment assertion pass. Full CI 43285784491 was started. Contracts 43285784543 PASS. Hosted coverage FAILED in job 131418681204 before sandbox tests: 12 aip-edge adversarial tests could not locate the built aip-edge-observer binary under target/llvm-cov-target/debug/build/aip-edge/864eeba112f12ebe/out. Full original log is current-coverage.log.gz. This failure is not evidence against or acceptance of the environment fix; full coverage remains BLOCKED. No complete repair acceptance or production claim. Retain any further failure before correcting it.

Next: reproduce and repair aip-edge coverage sibling-binary discovery without skipping adversarial tests; then classify the four retained HIGH Helm findings without altering historical originals. Executable TOCTOU, sensor coverage, independent collector administration, clean-machine offline kit and required live demo rehearsals remain open. No full-mode rehearsal credit.
