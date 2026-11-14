# Iteration 002 — executable snapshot consistency

Runtime source: `5be83a87bec680d26510c2be93e66fdfda008b1e`.
The previous local commit `17523ef27dd827ab9ff8801770c9724491d232bb` has the
same tree, `fe4a962a670c092e9729817272e9513d87dffd46`. Connected Git-object
publication was used after shell credentials were unavailable. No force push.

`baseline-reproducer.patch` adds only the two deterministic real-exec
regressions and their scheduling hook to audit commit `ceb7682`. Both fail in
`baseline-image-race.log`. Cold cache mixes the old path with the new executable
hash; warm cache retains the stale image. Original failure files are unchanged.
`fixed-image-race.log` records the repair. `signed-image-race.log` is the retained
initial helper-namespace compilation failure; `signed-image-race-fixed.log`
records its correction. `scoped-regression.log` retains the uncached offline
dependency failure; the unchanged-lock successful run is in
`scoped-regression-online/`.

`final-signed-samples/` records exact final source hashes. `originals-final/`
contains genuine procfs measurements signed by an ephemeral in-memory collector.
No private key is present, no connector event or coverage health was fabricated.
`originals/` retains the earlier pre-format signed samples separately.
`offline-cold/` and `offline-warm/` each contain four verifier checks against the
final originals: signature integrity, one-byte mutation, wrong anchor and absent
health refusal. Mutations are explicitly labeled and never replace originals.

`observer-regression/`: 102 tests; `scoped-regression-online/`: 455 tests.
`clippy/` and `format-check/` retain actual commands and exits. These are scoped
test counts, not live-agent/adversarial-workload/independent-host counts.

`hosted/native-original.zip` is the exact provider artifact from run
43582459564, artifact 14109300530. Its retained source checkout is `5be83a8`;
the provider's PR merge context is recorded separately. Ten real native kernel
assertions plus two archive checks pass. `hosted/native/` is its extraction.
`hosted-replay/` records six public-key verification/mutation checks with all
19 manifest entries and nine source-file hashes checked. Unverified/degraded
coverage remains absent.

`gateway-runtime/` is a separate live pinned ContextForge/MCP trial: 27 checks,
27 signed receipts, 16 real upstream invocations. It does not run a model or
the kernel observer. Source/binary hashes, public anchors, synthetic inputs and
raw logs are preserved. Temporary signing material was deleted by the harness.

`hosted/same-run-failure-original.zip` is the untouched artifact from run
43582459576, artifact 14108683682. It preserves the successful observed and
interruption scenes and the failed recovery. The first two return CannotProve;
the third lacks a signed Forwarded receipt and is refused. The gateway journal
was not retained in this original run, so the cause remains unresolved.
`hosted/same-run-job.log.gz` is the entire unmodified provider job log compressed
with gzip mtime zero. Uncompressed SHA-256 is
`c34006d0eeedd4c7fe81717b4221928cb5e3ca4ccdbca8df82f1cf40b44b2018`.
Selected original manifests and single-trial resource measurements are copied
byte-for-byte under `hosted/same-run-selected/`; they are not comparative
overhead/discovery benchmarks. `same-run-replay/` independently reproduces both
original signed CannotProve evaluations exactly with a separately built verifier.
Missing receipts preserve uncertainty; wrong anchors reject: six checks.

`provider-checkpoint.json.gz` preserves the earlier provider snapshot. Its
uncompressed SHA-256 is
`603f63c2d8c05399a06d55391b79291e90c5609e1ff84706f704d0f7f490fc19`.
`provider-final.json` and the qualification ledger supersede its moving CI state.
Public anchors and unsigned checksum manifests require out-of-band review;
remote replay is not independently administered observation.
