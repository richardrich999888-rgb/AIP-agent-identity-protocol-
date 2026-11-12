# Iteration 004 — native qualification host blockers

Parent: `9e7e9eec13f58a2b7689b66ca1e76ff65fb8bc8d`.
12 November 2026 (Asia/Kolkata); command records use UTC.

This item adds a strict disposable-host execution gate for the ten named native
checks in iteration-003's blocked/failure ledger. Production sensor, identity,
signature, coverage and verdict checks are unchanged. Source and acceptance are
described in [the report](../../../docs/research/P0-048-NATIVE-QUALIFICATION.md).

Acceptance result: **PASS for the selected native-host qualification item**.
The implementation commit is `ea5fe9e9ad10da0b490b411afc9f757e01259c73`;
[hosted run 43167021649](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43167021649)
executed all ten exact native cases and both original-archive checks successfully.
The final evidence update leaves the tested native sources and workflow unchanged.

Retained evidence:

- `gate-unit-final.*`: 15 gate/installer negative and positive controls pass.
- `local-capability-negative-final/`: actual existing binaries on the restricted host;
  nine BLOCKED, one BPF FAIL, two absent archives; overall exit 1, never PASS.
- `format.*`, `clippy.*`: formatting and scoped all-target Clippy with denied warnings.
- `build-tests.*`: exact Cargo build command; all dependency versions stay locked.
- `sensor-regression.*`: 92 executed passes; three locally blocked connector
  cases are excluded from that count and were exercised in the hosted run.
- `hosted-artifact.zip`: original 19,870-byte provider archive, SHA-256
  `cd0e919510fc5922de8638dacf98d11e22d82e84f6d6e5c1c3a8890ac1cca29c`.
- `hosted/p0-native-evidence/`: exact extracted logs, source/binary hashes,
  host metadata and original signed `t09`/`t15` batches and health.
- `hosted/p0-native-build/`: Cargo artifact manifest and verified compiler pins.
- `hosted-{artifacts,jobs}.json`, `hosted-job.log`: provider receipts and job log.
- `hosted-reverification-final/`: six local CLI assertions pass: two original
  archives accepted, two one-byte changes and two wrong public anchors rejected.
  Both originals remain without coverage; loss health remains `Degraded`.
- `hosted-reverification.*`: retained initial harness setup failure (duplicate
  probe-ID assumption); `tamper-harness-regression.*` records three controls for
  its correction. The final rerun uses separate output and preserves originals.
- `throughput-release.*`: explicitly executed, previously ignored timing test;
  one pass. See the report for scope; no sensor or host-capacity claim.
- `parent-ci.json` and `implementation-ci.json`: provider workflow status at
  inspection, including any broader CI still running and Security failures.

The first gate tests used 13 cases; two additional controls cover Rust's interleaved
nocapture output and rejection of changed toolchain bytes before installer execution.
Compiler/std and Cargo licence files were checked individually; their texts differ,
so the new pin manifest records each component's own hashes instead of assuming
one licence-file hash applies to every archive.

Reproduce with the pinned compiler on PATH, from the repository root:

```sh
python3 -B validation/p0_048/test_native_qualification.py
cargo test --locked --no-run --message-format=json -p aip-observe --test cgroup_live --test fanotify --test gate10_xdp_evaluation --test sniffer_dog --test socksend --test wiretap > /tmp/p0-native-artifacts.jsonl
cargo build --locked -p aip-observe-verify
python3 -B validation/p0_048/native_qualification.py --build-log /tmp/p0-native-artifacts.jsonl --verifier /path/to/target/debug/aip-observe-verify --out /tmp/p0-native-fresh
```

Recheck the retained signed originals and negative copies without downloading
dependencies (build or supply the native verifier separately):

```sh
python3 -B validation/p0_048/iteration-004/test_verify_hosted_evidence.py
python3 -B validation/p0_048/iteration-004/verify_hosted_evidence.py --verifier /path/to/aip-observe-verify --out /tmp/p0-native-reverification
sha256sum -c validation/p0_048/iteration-004/SHA256SUMS
```

The source-hash check intentionally requires the recorded tested sources; use
the evidence commit's checkout. The checksum manifest is relative to repo root.

The output directory must not exist. Run the native checks only on an authorized
disposable Linux host with the relevant capabilities. The workflow enforces its
GitHub-hosted/root/network-namespace preconditions. The runner itself does not
install software, change capabilities, mount tracefs, or relax host restrictions.
Source, executable and log hashes are evidence of supplied bytes, not proof of
independent administration. No private key is retained.

Previously published evidence and hashes remain unchanged. No merge is performed.
