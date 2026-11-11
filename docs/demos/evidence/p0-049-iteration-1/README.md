# P0-049 iteration 1 evidence

**Release NOT READY.** This folder records a bounded C1 scoreboard check, not a
full teaching, offline-kit, sensor or external-evaluator acceptance run.

Implementation commit: `84d889f0c045a998150900e433541a976fdd1d69`.
Source tree: `557935e887f10328fb60355968503d8a619e3c1f`.
CI merge commit: `71ab878a1824364ac424b9895a6ffe12818ec842`, with the same tree.
Review: [draft PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21).

## Inspect and reproduce

- `scoreboard/`: clean local run; Linux 6.18.57, 9 visible CPUs, MemTotal 10206472 kB.
  Debug binary; 2.7071336839999276 s total wall, 1.037143 s child CPU, 12288 KiB
  peak child RSS. Only loopback in the network namespace; zero before/after
  byte/packet increments. No captures or sensor in this run.
- `scoreboard-ci/`: separate clean CI run; Linux 7.0.0-1017-azure, 4 visible CPUs,
  MemTotal 16367524 kB. Debug binary; 0.45960819999999103 s total wall,
  0.37376599999999993 s child CPU, 18416 KiB peak child RSS. Connected network with
  traffic; not offline proof. CI artifact digest was checked before extraction.
- Both retain 14/14 motor, expected 11/12 transformer rejection (exit 3), and
  12/12 corrected transformer. The rejection's `val-09` is preserved. Each run's
  `result.json` contains full precision timings, per-case status and hashes.
- `runtime-baseline.txt`, `runtime-final.txt`: 173 and 187 passing runtime tests;
  the latter includes 14 new scoreboard cases. `python-suite.txt` has 293 passes
  and two skips; `python-cli-followup.txt` runs those two successfully with the
  built binary. These are 295 distinct Python tests over two invocations.
- `verify_suite_signatures.py`: second Ed25519 implementation, requiring
  cryptography 50.0.0 already staged. Six retained suites verified; an altered
  expected label was refused with `InvalidSignature` and exit 1. Trust anchors
  here are synthetic test keys, not proof of external expert qualifications.
- `sniffer-retained-*.json`: existing W archive verified again (7 batches,
  86 events, 1 health record); altered archive refused. Health remains
  ContinuityUnverified. This is not a fresh live sensor run.
- `development-failure-*.txt`: the recorder's failed development attempts.
  The first is a labelled console transcription, not an invented raw log.
- `remote-state.json`: observed PR/branch/CI metadata. OVERLAY source is not
  copied here. Its six inaccessible demo commits remain unavailable evidence.
- `trivy-source.sarif` and `ci-supplychain-failure.txt`: unresolved CI findings.
  The latter is explicitly a log excerpt, with omitted sections marked. Full
  job logs are at the linked CI run, subject to GitHub retention.

From this directory:

```bash
sha256sum -c SHA256SUMS
(cd scoreboard && sha256sum -c SHA256SUMS)
(cd scoreboard-ci && sha256sum -c SHA256SUMS)
python3 verify_suite_signatures.py scoreboard --trusted-keys scoreboard/expert-public.json
python3 verify_suite_signatures.py scoreboard-ci --trusted-keys scoreboard-ci/expert-public.json
```

Use the independently provisioned expert mapping for a real acceptance check.
The root manifest and diagnostics are **unsigned**. An attacker who can replace
both data and manifest can make a checksum check pass. Suites have Ed25519
signatures, and the historical observer records have their existing signatures;
these authenticate only their defined bytes. Recompute validation from trusted
inputs; a signature does not establish the correctness of the expert's rule.

No private key is retained. No model was loaded, so the model hash list is empty.
No single-run value is converted to a range, and the two machines' measurements
are not combined. Neither row earns a required-mode consecutive rehearsal pass.
See `../../P0-049-FINAL-REPORT.md` and `../../OPEN-GAPS.md` for the release boundary.
