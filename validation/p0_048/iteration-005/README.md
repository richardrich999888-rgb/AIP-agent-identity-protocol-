# P0-048 iteration 005 evidence

Source parent: `61dd73013d02ea7869de104d953f330098df1c32`.
Scope: classify the six retained scanner findings while preserving raw reports,
historical bytes and rejection of new findings. No runtime product changes.

## Retained evidence

- `baseline/`: original locally reproduced Gitleaks and Trivy findings/logs.
  Both scanners exited 42, the dedicated findings code used for this experiment.
- `gitleaks-after.json` and `.log`: original five-commit PR range after applying
  the two exact false-positive fingerprints; exit 0.
- `trivy-after.sarif` and `.log`: complete unfiltered fresh scan; exit 42, four
  historical HIGH warnings, never rewritten to an empty report.
- `classification-after.json`: exact file/hash/location decision, including
  the retained findings and explicit lack of deployment qualification.
- `gate-tests.log`: 17 positive/negative classification controls.
- `scanner-controls.json`: actual scanner commands, exit codes and detection
  controls. Temporary generated token bytes were never retained.
- `current-chart.zip`: fresh enabled Helm rendering, raw Trivy report and
  command/exit metadata. All four HIGH warnings remain. This ZIP preserves a
  test output; it is not a release manifest or an installable image.
- `scanner-provenance.json`: official versioned download/checksum locations and
  measured archive/binary hashes; includes Helm used for the fresh rendering.
- `source-and-results.json`: reviewed parent, source hashes and observed results.
- `triage.json`: static finding classification. Archival-scope verdicts do not
  approve the current enabled Kubernetes profile.
- `SHA256SUMS`: hashes for the retained local evidence files.
- `hosted/`: original security/native provider ZIPs, scanner job transcripts,
  source/content verification, and the retained original coverage failure.
  Native signatures and health records remain inside the original provider ZIP.

## Reproduce

Install the Linux x86_64 tools into a temporary directory:

```sh
python3 -B validation/p0_048/install_security_scanners.py --prefix /tmp/p048-scanners
python3 -B validation/p0_048/test_security_gate.py
python3 -B validation/p0_048/security_gate.py --verify-inputs
```

Run Trivy without ignoring findings. Keep reports outside the scanned tree:

```sh
set +e
/tmp/p048-scanners/trivy fs --scanners secret,misconfig \
  --severity CRITICAL,HIGH --ignorefile '' --exit-code 42 \
  --format sarif --output /tmp/p048-trivy.sarif .
scan_exit=$?
set -e
python3 -B validation/p0_048/security_gate.py \
  --report /tmp/p048-trivy.sarif --scan-exit "$scan_exit"
python3 -B validation/p0_048/security_scanner_controls.py \
  --gitleaks /tmp/p048-scanners/gitleaks --trivy /tmp/p048-scanners/trivy \
  --output /tmp/p048-scanner-controls.json
```

Gitleaks reproduction uses `git --redact --exit-code 42 --log-opts
'4d0ce1e32c8dedde4e3a930abc2becf1f56b864e..HEAD'`, with `--report-format json`
and a report outside the repository. To reproduce the original two findings,
use an empty temporary ignore file with `--gitleaks-ignore-path`; do not delete
the committed classification or alter history.

## Publication status

Local checks passed. At implementation `ce7925c649fe3268ef0ba40b321058216c5e0c27`,
Security run `43581555606` passed all three jobs. Native run `43581555600`
passed ten assertions and two native archive checks. Original ZIP SHA-256s:

- Security: `52d1e798d77955cd83d70063b79c7dede7278199e71f40629f4c8d5296e5724c`.
- Native: `74fd24c0dc9c40885065721e86b553e7fcead750b515f31d30abe05dea54fcdf`.

The full coverage job at that source failed after the floating toolchain
selected Rust 1.100.0 and the reference sibling launcher could not resolve
Cargo's changed internal path. `hosted/toolchain-drift.json` and the original
compressed failure transcript preserve that failure. The follow-up pins the
quality/coverage jobs to qualified Rust 1.99.1 without excluding any tests.
The latest exact-head CI results are maintained in PR #20; no later run is
declared passed by inference from these retained implementation results.
