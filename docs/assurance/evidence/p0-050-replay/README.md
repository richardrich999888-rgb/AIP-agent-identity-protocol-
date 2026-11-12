# P0-050 applicability replay follow-up

12 November 2026. **Bounded component verification passes; release NOT READY.**
This continuation found the applicability repair already present at
`ef3d9d434e5ed55e5994331abc91c03833f997ff`; it does not implement that repair again.
Checkpoint `975b24507b42c92081a9b2dc708cd3d31104a629` arrived during verification
and was fast-forwarded after confirming that it changes only docs. Its original
evidence remains untouched in `../p0-050-iteration-1/`.

## One bounded item

Make acceptance replayable without trusting unsigned diagnostics. The new
`research/capability-learning/harness/verify_applicability.py` requires externally
selected tenant/task/expert, public key, capability byte hash and native binary
hash. OpenSSL verifies the existing Ed25519 suite encoding. The supplied native
`cap-check` recomputes every frozen case. Exact count, order, ID, expected label
and observed outcome must agree. Missing signature support fails; it never skips.

The verifier ignores packet `scoreboard.json` and `result.json`, snapshots the
capability bytes already checked and preserves a previous output directory.
Frozen ordered-case hashes are pinned from unchanged acceptance inputs. It
neither signs a diagnostic nor approves, activates, imports or exports a
capability. A synthetic evaluator key is not an authenticated expert identity.

Acceptance: holdout **12/12**, attacks **26/26**, frozen nonactivation **6/6**
(a subset of 26); signature verification and native outcome replay for both
retained CI and freshly recorded local suites; changed trust/bytes/cases,
forged summaries and incomplete verifier output must fail.

## Fresh results

| Check | Result | Original record |
|---|---|---|
| Fresh real CLI recorder | PASS_BOUNDED_B3; 12/12, 26/26, 6/6 subset | `acceptance/`, `local-acceptance.log` and `.json` |
| Copied-plural negative control | Rejected: 11/12 holdout; 18/26 attacks | Complete control suites and reports under `acceptance/` |
| OpenSSL signatures + native local replay | PASS: both suites | `replay-local-final/` and matching command records |
| OpenSSL + native replay of original CI packet | PASS: both suites | `replay-ci-final/` and matching command records |
| Full capability-learning suite | **375 passed**, no failed/skipped tests | `python-regression-final.log` and `.json` |
| New replay tests | **22 pass**, included in 375 | 1 positive and 21 refusal controls; earlier 18-case development run retained |
| Existing applicability tests | **29 pass**, included in 375 | Includes four targeted behavioral mutants, not an exhaustive campaign |
| Native runtime regression | **187 passed**, zero failed/ignored | `runtime-regression-retry.log` and `.json` |
| Formatting / Clippy warnings denied | Both exit 0 | `format.*`, `clippy.*` |
| Frozen data and expected-case comparison | Unchanged | `frozen-input-check.json` |

Counts overlap and are not additive. Tests use real Rust signatures and OpenSSL,
with three explicitly synthetic CLI-output fault controls. They reject wrong
tenant/task/expert/key/runtime/capability pins; modified signature/label;
deleted/duplicated/reordered/cross-tenant/missing suites; changed capability bytes;
duplicate JSON fields; prior output; absent OpenSSL; and zero/duplicate/wrong-ID
native results despite exit 0. A deliberately trusted mutant with the old broad
`V` applicability and forged PASS summaries still fails fa-3 on replay.

One host-plugin `PytestRemovedIn10Warning` from AnyIO's `CallSpec2` import is
retained, not suppressed; it is not a skipped test. Initial offline Cargo test
exits 101 because `errno` was not cached; `runtime-regression.*` retains it.
Connected locked preparation permits the retry and offline Clippy.
`preparation-attempts.json` records the initial missing `rusqlite` build,
test-runner installation and an evidence-receipt path error. Transcribed console
observations are labelled; they are not reconstructed original logs.

## Provenance and limits

Adjacent command `.json` files retain exact commands, UTC times, source state,
environment overrides, exit codes and durations. `environment-and-source.json`
binds tested source files, tool versions/hashes and hardware. `record_command.py`
is the recorder used here; absolute paths describe the original run. Portable
replay instructions are in `docs/demos/INDEPENDENT-VERIFICATION.md`.

The existing original CI ZIP `../p0-050-iteration-1/ci-teaching-original.zip`
is byte-identical to this continuation's independent download: SHA-256
`a35cecd3141759fb088df7bf1ac752b1f3ab909c5c227076ccbd7749c65f9489`, artifact
`13921671463`, workflow `43169880420`, source `ef3d9d4`. Every original extracted
member was compared byte-for-byte with `../p0-050-iteration-1/ci/`. A duplicate
download is not counted as new independent evidence. Replay uses two corrected
suites; all original failed controls and other suites remain retained.

`local-trust.json` and `ci-trust.json` select different synthetic evaluation keys,
the same reviewed capability bytes and the trusted replay binary. They are not
external expert authentication. Real trust must be provisioned independently.
Only suite inputs are signed; diagnostic verdicts remain unsigned and must be
recomputed. OpenSSL is a separate cryptographic implementation, but outcomes use
the same trusted native engine, not independently implemented domain semantics.

The local recorder used binary `99ef69bd...399d69f`; Cargo test rebuilt the CLI
before replay, which uses `48d7d078...3275ce9ec`. Full hashes are retained. Native
source did not change. No byte-reproducible-build claim is made, and the original
recording binary bytes are not included. Every replay checks its selected hash.

Local hardware: Linux 6.18.57 x86-64, nine available CPUs, host MemTotal
10,206,472 KiB; cgroup CPU/memory limits unavailable. The component recorder body
took **0.272866667 seconds**, child CPU **0.16412 seconds**, peak child RSS
**19,456 KiB**. Enclosing command: **0.405602888 seconds**. Final local and
CI-packet replays each took about 0.32 seconds on this same host; exact individual
times are retained. These are not product benchmarks or investor-demo durations.

The recorder reports loopback only, no external IPv4 route and zero counter
deltas. Dependency preparation used connected tooling. No packet capture,
independent firewall validation, initial-netns sensor, model, second machine,
Mac observation or genuinely fresh offline installation is proved. There is no
independent administration or complete expert approval. Full-mode credit is zero.

This optional evaluator helper adds no production runtime dependency. It uses
Python's standard library, a supplied native binary and preinstalled OpenSSL
**3.5.7**, whose binary hash and unchanged system copyright record are retained.
The latter lists Apache-2.0 and source exceptions; no licence is changed.
Canonical bytes follow existing `suite.rs`; SPKI follows
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html), verified with
[OpenSSL pkeyutl](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/).

Rust/Cargo **1.99.1** and the existing Cargo lock were reused. Missing pytest and
its four dependencies were installed with exact hashes from existing
`deploy/syntriass/requirements.lock`; subset/log retained. Preinstalled
NumPy/scikit-learn differ from the full lock. Actual versions/licence metadata
are recorded; this is not a fully reproduced research environment or offline
kit manifest. No downloads occur in the replay command.

`remote-review.json` retains repository/PR/CI observations and selected OVERLAY
branch/tree provenance. Its six historical W4/W5 revisions remain unavailable;
source was inspected through the connector, not built. At the recorded checkpoint
snapshot teaching CI passed, Security failed and full CI was running. Post-push
CI must be assessed separately.

Next: **S2, teaching sandbox/CI discrepancy**, without reducing coverage or
changing expected outcomes. Signed approval, packs, complete demonstrations,
sensor qualification and clean-machine offline acceptance remain open.
