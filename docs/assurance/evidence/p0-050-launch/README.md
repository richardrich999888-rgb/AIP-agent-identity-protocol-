# P0-050 S2: positive per-launch acknowledgement

12 November 2026. Candidate source `2408c6ee89f2f3f0068e12ff5ddf2229e35f128a`, draft PR #21, approved feature/airon-teach-demo. **Hosted scoped acceptance and offline replay PASS; full workspace CI pending; release NOT READY.**

## Selected item and measurable acceptance

Exactly one bounded item: a successful namespace readiness probe must not let a later failed launcher produce a signed tool exit. Require real kernel exec notification for the intended child plus its terminal status; refuse missing, malformed, duplicate or forged stdout acknowledgements; preserve one-shot consumption, real exit codes 1/126/127, script and signal execution, deadline behavior, and CannotProve. No weakened signature or independent-observation gate. Full applicable CI and original signed-packet replay must pass before accepting the repair.

Baseline 31d3ee5 freshly reproduced both probe-success/failed-launch and non-executable-tool false records (expected red tests, exit 101). Concurrent approval-authority source 00c06de and evidence 8c1e9d2 were preserved before publication. They are not accepted anew by this sandbox change. OVERLAY branch metadata was refreshed (overlay-branches.json); no OVERLAY code acceptance or new full-repository audit is claimed in this bounded continuation.

## Change and trust boundary

The same vanian executable has a private helper dispatch. A private inherited socket, closed on tool exec, carries a strict fixed-length status frame only after the helper observes its own child's PTRACE_EVENT_EXEC and terminal wait status. Launcher stdout, a zero exit, and socket EOF cannot prove tool execution. Parent requires successful helper completion and the exact frame before signing. No record on uncertain launch; consumed authority remains spent.

This is trusted runner evidence, not an independently administered witness. A malicious configured helper/unshare or administrator can subvert it. No record schema or historical evidence is upgraded. Existing executable-hash-to-exec race, interpreter pinning, filesystem/resource confinement and collector custody remain open. Namespace PID1 is now the helper; privilege-gaining executables and PID1-dependent tools are not qualified. Tracing must be permitted by host policy. No security-policy relaxation or fallback was introduced.

The outer watchdog bounds total time to tool timeout + 1000 ms; it may preempt the helper's internal 10000 ms setup/termination waits. Missing completion returns LaunchUnproven. This conservative bound is not a guarantee every slow host can run the tool.

Primary kernel interface references: https://man7.org/linux/man-pages/man2/ptrace.2.html and https://man7.org/linux/man-pages/man2/waitpid.2.html. They describe the mechanism; retained tests establish observed behavior.

## Local results, original failures preserved

- Initial sandbox candidate: 13 pass / 13 fail (26 tests at that point).
- Final pre-integration scoped run: 288 pass / 18 fail, zero ignored. Runtime 194 pass; sovereign unit 77 pass / 1 fail; sandbox 15 pass / 17 fail; SQLite 2 pass. Counts overlap other runs.
- Host PTRACE_TRACEME returns -1 / EPERM. Namespace readiness succeeds. Positive execution and the pre-exec-death test are BLOCKED here, not passing. No precise seccomp/LSM attribution is asserted.
- Strict private-frame unit test and fake-launcher exits 0/1/126/127 regression pass. Scoped Clippy passed. Exact commands, source hashes, outputs, durations and original failure receipts are in local/.
- Non-executable negative test alone can also pass because tracing is unavailable; it is not independent causal proof of EACCES handling. Hosted positive controls and invalid-exec cases are required.
- Read-only reviewer report: REVIEW.md. No independent administrative domain claimed.

No new package was installed. Direct libc =0.2.189 reuses the existing locked crate; checksum 3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2, upstream https://github.com/rust-lang/libc, MIT OR Apache-2.0. Existing Rust toolchain provenance is retained in ../p0-050-sandbox/toolchain/. No licence changes. Fully pinned air-gap supply chain and clean-host installation remain open.

## Publication and acceptance status

CLI git push lacked credentials; publication used the connected GitHub API with expected-head fast-forward checks and exact tree comparison. The first stale-head update was rejected after concurrent evidence arrived; its changes were preserved. Source tree: 986017f91ba707f2bd1af7414eb9248700475470. No merge or force push.

Hosted teaching run 43252347920 passed: **313 Rust** (201 runtime + 78 sovereign unit + 32 sandbox + 2 SQLite), **267 focused Python**, no failed or ignored cases. All new negative controls and positive exec/script/signal/timeout checks ran. Original signed CLI record has expected output; unauthorized action refuses; one-byte tamper and wrong key reject. All 12 holdout and 26 adversarial outcomes (including six frozen nonactivation probes) pass. Counts overlap, not additive.

Untouched archive ci/teaching-original.zip, artifact 13961055405, SHA-256 `9ad6a53e709f93091cc25e87e1a5684ffebfa2dbcd28de051918b64a445125d0`. GitHub merge fae11335937777439404a3f91660c77c1ca3bb51 matches source tree exactly. Full decoded job log retained losslessly as ci/teaching-job.log.gz. Local .log files are likewise losslessly gzip-compressed; receipts retain original command names. Extract originals with `python3 -m zipfile -e ci/teaching-original.zip ci/original` from this directory, after independently authenticating/checking the pinned digest. Extracted duplicates are untracked; the ZIP retains every original member.

Separate local source build replayed runner original/tamper/wrong-key controls and all 38 signed teaching outcomes in a new network namespace (only loopback, no external route), using only public verification material. See reverified-final/commands.json and teaching-replay/. This is offline verification, not fresh-machine installation, original-runtime independence for teaching semantics, or independently administered custody. Teaching replays still use the source-pinned syntriass engine; runner verification needs no original agent runtime. Pins require authentication by the evaluator.

The first replay correctly refused a stale previous-run synthetic expert key. Its complete outputs, helper snapshot and receipt remain in reverified/ and local/offline-reverify.*. Only the replay helper's explicit key pin was corrected after inspecting this run's hash-checked original; no original packet, acceptance label or verifier was changed.

Formatting and integrated scoped Clippy pass. Contracts CI passes. Full workspace CI 43252347919 remains pending at this checkpoint. Security 43252348084 fails the same four HIGH KSV-0009/0010/0118/0121 findings in historical `validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`; original SARIF ZIP and log retained without suppression. Its SHA-256 is `a196db8a069f775acbf9be9a7a8d4ed4b2755b49231e5d606dd0a8cfe7dfef39`. No live Sniffer Dog, genuine model, OVERLAY, full-mode demo or rehearsal credit. Next: resolve any full-CI regression; otherwise classify the four retained HIGH Trivy findings without altering original evidence.
