# P0-050 applicability evidence

Scope: one compiler applicability repair, not full W3 or release acceptance.
Implementation `ef3d9d434e5ed55e5994331abc91c03833f997ff`; tree
`d8e21fc9b2fa8ae4ad981036f0c082916fc51e86`. No model, activation, knowledge pack,
native sensor, packet capture or independent offline installer ran here.

| Retained material | Meaning |
|---|---|
| `baseline/` | Clean parent `925432b`, exit 3, 12/12 holdout and 25/26 attacks; original signed suites and failed fa-3 |
| `development/repaired-dev/` | First passing development-tree run, explicitly dirty |
| `development/clean-prebuilt/` | Clean implementation with the previously staged binary; not the fresh-build result |
| `local/` | Final fresh local build, clean implementation, exit 0; original four signed suites, complete diagnostics, counters and resource metadata |
| `ci/` | Unmodified extraction of original teaching artifact, including both scoreboard and exclusion recorders; connected CI host |
| `ci-teaching-original.zip` | Original 55-entry GitHub artifact, SHA-256 `a35cecd3141759fb088df7bf1ac752b1f3ab909c5c227076ccbd7749c65f9489` |
| `ci-teaching-source.log` | Full teaching job `131020362895`, workflow `43169880420`; includes 175 passing focused tests |
| `ci-*-original.zip`, `security/` | Original Security artifacts and extracted Trivy/audit output; no findings suppressed |
| `ci-baseline-sandbox-failures-excerpt.txt` | Explicitly labelled excerpt of parent main-CI job `131005200942`; not a full native evidence archive |
| `comparison-development-failure.txt` | Incorrect cross-session digest equality assumption in the first comparison tool; retained failure and described recovery |
| `compare_runs.py`, `comparison.json` | Independent standard-library consistency comparison; no compiler import and no authenticated-verdict claim |
| `signature-*.txt` | Separate Ed25519 verifier results, including exit-1 tampered-label control |
| `provenance.json`, `host-source.json` | Source hashes, commands/results, local hardware information and limitations |
| `remote-state-*.json`, `ci-*-metadata.json`, `ci-source-status.json` | Provider state/artifact snapshots with exact refs; historical results distinguished from fresh runs |

`SHA256SUMS` covers every retained file except itself; nested recorder manifests
are preserved unchanged. A hash detects changed bytes relative to the manifest,
but the root manifest is not a signed release. Only the synthetic expert suites
are signed. Session/answer edits/diagnostics are unsigned; a suite signature does
not authenticate an unsigned claimed result or a real expert's identity.

From this directory, after staging Python and `cryptography==50.0.0`:

```bash
sha256sum -c SHA256SUMS
python3 compare_runs.py baseline local ci/exclusion-evidence
python3 ../../../demos/evidence/p0-049-iteration-1/verify_suite_signatures.py local \
  --trusted-keys local/expert-public.json
python3 ../../../demos/evidence/p0-049-iteration-1/verify_suite_signatures.py ci/exclusion-evidence \
  --trusted-keys ci/exclusion-evidence/expert-public.json
```

Real acceptance must use independently provisioned trust anchors and rerun the
validator. Recorded timings are individual observations on labelled hosts;
their values are not combined into a range. The 6/6 frozen probes, 29 new tests,
four mutation controls and 175 CI tests overlap larger sets. No full-mode
consecutive rehearsal pass is earned by these checks.
