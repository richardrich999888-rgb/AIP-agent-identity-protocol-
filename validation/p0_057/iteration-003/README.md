# Iteration 003 — diagnostic preservation, not a receipt repair

Source: `5a7d2625a861821e74f979cd0700fbbe6dbe1de1`.
Local pre-publication commit `1b4f8c39ac1ef01a63c057dfb548b0142d82c281`
has the identical tree `d9c2ada9464fc7e25b34c6637b91a1c61358600f`.

The existing same-run harness now preserves a bounded, read-only projection of
its replay journal after gateway termination, even on failure. Identifiers are
hashed; only fixed state names are exported. Missing, symlinked, corrupt,
oversized or malformed journals produce explicit unavailable diagnostics.
No private tables, keys, arguments, raw error strings or SQLite files are copied.
The result is unsigned gateway-local diagnostic data, never a substitute for
signed receipts, trusted observations or verification.

`diagnostic-tests/` records four actual temporary-SQLite tests.
`same-run-controls/` records 11 existing portable control tests. These do not
claim a live agent/kernel run. The original missing-receipt cause remains open.
`summary.json` records the changed source hashes; the qualification ledger
records the fresh hosted trial separately from the original failed trial.

The full artifact `same-run-original.zip` is from successful hosted workflow
43583751360, artifact 14109553449, SHA-256
`4351d0217fa5f616d46d6a59db34d2f0173d2715fbd6f372b98370225f846942`.
Observed, interruption and recovery scenes all pass their harness assertions,
with original journal diagnostics showing one Forwarded row each. All three
signed reconciliation results remain CannotProve. `selected/` copies the three
original manifests, resource records and diagnostics verbatim; `hosted-summary.json`
is a derived index. The original missing-receipt failure remains unresolved.
The final evidence checkpoint wires the four portable diagnostic tests into
the existing same-run workflow. Runtime sensor and gateway predicates remain
unchanged by this iteration.
