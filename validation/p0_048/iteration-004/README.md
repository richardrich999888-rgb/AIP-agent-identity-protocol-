# Iteration 004 — native qualification host blockers

Parent: `9e7e9eec13f58a2b7689b66ca1e76ff65fb8bc8d`.
12 November 2026 (Asia/Kolkata); command records use UTC.

This item adds a strict disposable-host execution gate for the ten named native
checks in iteration-003's blocked/failure ledger. Production sensor, identity,
signature, coverage and verdict checks are unchanged. Source and acceptance are
described in [the report](../../../docs/research/P0-048-NATIVE-QUALIFICATION.md).

Local evidence:

- `gate-unit-final.*`: 15 gate/installer negative and positive controls pass.
- `local-capability-negative/`: actual existing binaries on the restricted host;
  nine BLOCKED, one BPF FAIL, two absent archives; overall exit 1, never PASS.
- `format.*`, `clippy.*`: formatting and scoped all-target Clippy with denied warnings.
- `build-tests.*`: exact Cargo build command; all dependency versions stay locked.
- Hosted results are pending at the implementation checkpoint. The next evidence
  update will retain the actual provider results and originals, without inventing
  a pass before those tests run.

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

The output directory must not exist. Run the native checks only on an authorized
disposable Linux host with the relevant capabilities. The workflow enforces its
GitHub-hosted/root/network-namespace preconditions. The runner itself does not
install software, change capabilities, mount tracefs, or relax host restrictions.
Source, executable and log hashes are evidence of supplied bytes, not proof of
independent administration. No private key is retained.

Previously published evidence and hashes remain unchanged. No merge is performed.
