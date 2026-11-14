# P0-051 iteration 1 — bound session diagnostic

**Component accepted; full release NOT READY.** Implementation
`5bc0c5f68690e5d2656716a97c2cfbb2ce105e08`; CI merge
`9892299fbbb4d76c8dfe62665a8ddd950221fe18`; both have tree
`751702c7f6472d52062040b942132c88341a31b5`. Later checkpoint `512fd4f` adds
concurrent S2 documentation/evidence and is preserved; it changes no runtime,
test or workflow bytes. The original runs here remain attributed to `5bc0c5f`.

## Acceptance and results

Regenerate the candidate from a verified stored session and original cited
source; reject stale/mismatched inputs; evaluate an independently signed suite;
link failed rows to exact regenerated questions/citations/edits. Preserve the
original rejected control and every existing applicability label. No activation.

Local clean-source results: 408 Python tests; 187 runtime and 102 sovereign Rust
tests (24 sandbox tests included); zero failures/skips/ignores in these scoped
suites. Hosted teaching run `43215328974` passes 230 focused Python checks and
the same relevant Rust suites. Counts overlap and must not be added. Format and
Python static checks pass. See raw logs rather than just this summary.

Both live session recordings retain the original control at 11/12, exit 3;
corrected validation 12/12, exit 0; corrected attacks 26/26, exit 0. Six frozen
nonactivation cases are included in 26. Source/data/task labels are unchanged.
The control's `val-09` links to the actual exclusion question and sentence.

Three local and three CI suite signatures verify with Python cryptography
50.0.0, independently of Rust. The existing applicability recordings also pass
OpenSSL signature checks and native replay. The original downloaded runner
bundle verifies in a separate local process; the one-byte mutation fails.
Independent observation remains CANNOT_PROVE. No private state is required.

## Retained originals

| File | Contents |
|---|---|
| `local-original.zip` | Original clean-source session, applicability and runner outputs; signed suites, public material, source/answers/diagnostics; replay outputs |
| `ci-teaching-original.zip` | Untouched GitHub artifact 13943332088 from run 43215328974; all four evidence directories |
| `development-original.zip` | Failed/partial development logs, original sandbox regression, superseded local patch, prepublication recordings and recovery |
| `ci-trivy-original.zip` | Untouched failing four-HIGH scanner report |
| `ci-audit-original.zip` | Untouched audit report under the existing advisory policy |
| `logs/` | Full published scoped test/build output, teaching job, signature/replay output and git checkout failure |
| `environment-and-source.json` | Source/tree/CI match, source hashes, actual hardware and explicit missing acceptance claims |
| `provider-*.json` | Provider metadata snapshots; pending is not passing |
| `local-trust.json`, `ci-trust.json` | Selected synthetic applicability pins for the recorded local replay binary |
| `comparison.json` | Local/CI diagnostic case agreement; this unsigned comparison is not signature verification |

Original CI ZIP SHA-256:
`9f7f02803e53e48b337ea96b24790e9cace6cce259db99e400f33e9c05b7ef38`.
Verify every retained file with `sha256sum -c SHA256SUMS` from this directory.
The manifest is unsigned; authenticate the source and public trust separately.
Archive members were checked for private-key fields. No model weights, passwords
or temporary signing-state files are distributed.

```bash
python3 research/capability-learning/harness/record_session_scoreboard.py \
  --binary target/debug/syntriass --out /tmp/p051-session-fresh
```

Run from the repository root with a staged trusted binary, Python and Git. This
is a fresh synthetic component run, not a reproduction of private-key custody.
See [independent verification](../../INDEPENDENT-VERIFICATION.md) for original
suite, frozen-case replay and runner-bundle commands. No download occurs in those
commands; staging/building dependencies is a separate prerequisite.

## Failures and limitations

The old sandbox regression failed as expected on `62db903`. A concurrent reviewed
repair landed at `6764c7e`; the overlapping local change was not published.
Its local tests are historical development checks, not the current implementation.
The new session tests initially reported two failures: an unsupported-number
mutation changed an unused field, and a raw-versus-corrected mutation did not
change the chosen holdout outcome. The later tests mutate used numbers/reading
selection and pass without changing acceptance labels. An initial full Python
run skipped two CLI tests because its default release binary was absent; explicit
`SYNTRIASS_BIN` then produced 408 passes with no skips. Failed logs are retained.

Local session recorder: 0.9302947449996282 s; hosted recorder:
0.7274345790000041 s. Hardware, binary hashes, CPU/RSS and counters are separate
in each original result. These are individual observations, not a range or a
three-minute show. The CI VM is connected and is not a clean offline installation.

Session example labels still need an explicit reviewed outcome mapping;
PDF/DOCX scoring remains open. Keys/answers are synthetic, with no authenticated
expert approval or independent administration. Reports/question links are unsigned.
There is no model inference, UI, pack, native sensor, PQ transport, packet capture,
complete kit, separate clean-machine test or final-mode rehearsal here.
Security CI still fails four HIGH retained-Helm findings. Original evidence was
not suppressed or deleted. Full-mode consecutive credit remains zero.
