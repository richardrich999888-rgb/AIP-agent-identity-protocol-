# P0-057 adversarial results

Only explicitly executed cases below receive new P0-057 credit. Fixture tests,
live sensor tests and mutations of retained evidence are distinct experiments.

| Evidence class | Result | Scope |
|---|---|---|
| Real controlled exec during image reads, cold and warm cache | 2/2 refusal regressions pass after both failed on baseline | Actual Linux processes; test hook controls timing, no kernel-event fabrication |
| Observer library + lifecycle/socket/container/blind-spot suites | 102 pass | Includes duplicate socket evidence, stale events, child/concurrent process identities and uncertainty; synthetic connector stimuli remain labeled |
| Core, reconciliation, gateway and offline-verifier suites | 455 pass | Includes trust/authority/signature/coverage/chronology/checkpoint negatives; not 455 live attacks |
| Final local signed sample originals/tamper/wrong-key/missing-health | 8 checks pass | Separate verifier processes, same administrator |
| Hosted required native qualification | 10 assertions + 2 archive checks pass | Real cgroup, fanotify, XDP test-run/verifier refusal, short-lived/exec connector, loss, socket-send and packet-capture tests |
| Local replay of hosted signed originals/tamper/wrong-key | 6 checks pass | Original manifests/source hashes match; unverified/degraded coverage remains absent |
| Pinned ContextForge, real HTTP/MCP upstream and Rust verifier | 27 checks pass | Wrong principal, wrong key, replay, concurrent calls, signing/journal outages; no live model or kernel claim for this separate trial |
| Hosted genuine model/authority/gateway/kernel same-run workflow | FAIL in recovery | Observed and interruption assertions pass with CannotProve verdicts; recovery lacks a Forwarded receipt |
| Bounded journal diagnostic | 4 tests pass | Actual temporary SQLite, no credentials exported; does not repair the missing receipt |
| Separate verifier replay of genuine observed/interrupted trials | 6 checks pass | Both original signed CannotProve results reproduce; missing receipts stay uncertain and wrong gateway anchors reject |

Hosted run [43582459564](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43582459564)
checked out exact source `5be83a8`, despite the PR's advancing base. Ubuntu
24.04.5, kernel `7.0.0-1014-aws`, image `20261111.127.1`. The raw provider ZIP
and extracted logs are retained, SHA-256
`f6859f1235aa10755df8949ceb6b4d055d9d452512a15194f1a7026497d21996`.
The hosted tests run with privilege on a disposable VM; this is not a
least-privilege deployment or independent collector administration.

Fresh live PID-reuse frequency, namespace switching, cgroup migration,
multi-agent shared-socket attribution, framework bypass, clock-skew workload,
full revocation/expiry workload matrix, collector lifecycle and high-load event
loss remain unqualified. Tests for related predicates do not close those gates.

Original failures are retained: both baseline image-race regressions; first
signed-sample compilation (incorrect helper namespace, fixed); first broader
offline build (uncached locked `hex` dependency, fetched with lock unchanged).
No assertions were removed or ignored to make the result pass. Focused reruns
overlap the suite totals and must not be summed as additional independent cases.

The new failure archive is retained unchanged at
`validation/p0_057/iteration-002/hosted/same-run-failure-original.zip`;
`same-run-summary.json` maps all three scenes, and `same-run-job.log.gz` retains
the original provider log. The first scene proves receipt/authority agreement
and seven matching process observations, while unsupported action causality
still yields `CannotProve`. Stopping the observer yields `WindowNotCovered`.
The final scene is refused before a signed reconciliation can be produced.

At diagnostic source `5a7d262`, hosted run `43583751360` passed all three actual
scenes and retained the new journal diagnostics. Every scene still reconciles
to CannotProve; interruption correctly reports WindowNotCovered. Its full ZIP
is `iteration-003/same-run-original.zip`. The earlier missing receipt did not
recur; no cause-specific fix was made, so it remains an unresolved intermittent
failure. These two workflow outcomes must be reported together.
