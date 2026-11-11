# P0-049 rehearsal ledger

**Required-mode acceptance: NOT READY.** This teaching branch had no master demo
rehearsal log. Historical W results remain in the original log at AIP commit
`6ad92ae`, `docs/demos/REHEARSAL_LOG.md`; they were not merged or overwritten.

| Historical W run | What was retained | P0-049 credit |
|---|---|---|
| Quantum 10/10, security 10/10, PQ 10/10 (7 Nov UTC) | Summary records and partial archives; original OVERLAY source unavailable | No final-release consecutive-pass credit |
| Pull-the-plug 10/10 (8 Nov UTC) | Log row; referenced full run directory not in tracked tree | No independent-host acceptance credit |
| Discarded banking 10/10 | Log says dirty-tree batch discarded | No credit; keep failure/re-run history |

New iteration-1 runs test only C1, not the full teaching or investor mode. They
contribute **zero** to the required ten/twenty consecutive rehearsal totals.

Development failures retained:

1. Recorder supplied `expected` to `suite-sign`, which requires `label`; CLI
   refused with `case.label`. Corrected the recorder, not the CLI contract.
2. Recorder used a non-existent corrected transformer fixture path. Corrected to
   the tracked `results/v02/postfix/` fixture; did not reconstruct missing data.
3. Recorder assumed cgroup-v2 files exist. This host exposes no such files.
   Hardware evidence now records UNAVAILABLE with the actual error instead of
   crashing or inventing resource limits.

The later successful recording retains the intentionally failed transformer
candidate (exit 3) alongside the passing motor and corrected transformer cases.
That is expected diagnostic acceptance, not a passed live teaching rehearsal.

Next qualifying run must retain exact source/binary/model hashes, host details,
full signed evidence, verification outputs, captures, counters, CPU/memory, timing,
exit status and failures/recovery. Reset each mode's consecutive count on failure.
W3 additionally requires twenty passes and a fresh offline install every fifth run
on supported CPU-only clean hardware.
