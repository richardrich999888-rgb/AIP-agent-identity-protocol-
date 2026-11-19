# P0-051 iteration 5: fresh unsigned teaching review

13 November 2026 IST. Source `2d3a22697acbdcf4c3343a70f130f841bd722491`, tree
`ecbace941432cdf5c53ab779b8425ddf7baa82be`; parent `93c65bcd` includes seven
preserved sandbox/CI commits. Release **NOT READY**. No feature/main merge.

## Acceptance and results

A review is emitted only after fresh native signed-suite and original-example
replay passes. It commits the original TXT source (including header), verified
session, task, cited draft/questions/answers, explicit example map, signed suite,
evaluator public key, capability, native outputs and runtime binary digest.
It does not import a supplied scoreboard or authorize activation.

Full local teaching suite: **472 pass**, including **27 new tests**. Every bound
file's mutation rejects, as do missing files, symlinks, wrong pins and falsely
labelled approvals. Failed suites, failed examples, changed sources and absent
maps emit no review. Existing native binary was rebuilt from the reconciled
branch; no Rust source changed in this item. Frozen acceptance labels unchanged.

Source-pinned offline recorder: exit 0. Corrected holdout **12/12**, attacks
**26/26** (six nonactivation probes included), rejected control **11/12** unchanged.
Original examples **3/3 separately**, never additional suite cases. Two passing
reviews verify in separate processes. Original source/suite signatures and native
outputs are retained in `offline-originals.tar.gz`; no private keys are retained.
These are synthetic component results, not an independent evaluator acceptance.

The review digest is an unsigned commitment, not expert identity or approval.
The separate verifier checks pinned-byte integrity only. A malicious party can
make its own hash; authenticate the pin before relying on it. Existing native
`cap-approve` does not yet consume this review. Binding this digest into an expert
signature with native replay enforcement is the next bounded item, not complete.

## Reproduce

Stage the locked native/Python dependencies first; no installation is performed
by these commands. From repository root:

```sh
cargo build --locked --offline -p syntriass-runtime --bin syntriass
SYNTRIASS_BIN="$PWD/target/debug/syntriass" python3 -m pytest -q research/capability-learning/tests/test_teaching_review.py
```

From this evidence directory:

```sh
sha256sum -c SHA256SUMS
tar -xzf offline-originals.tar.gz
```

`verification.json` records the selected review digests and exact original
commands. Substitute the extracted `offline/replay/SCENARIO` folder for the
original absolute folder in each command; retain the pinned digest. Run the
repository `research/capability-learning/harness/teaching_review.py` with
`--expected-digest` and that folder. Expected status is explicitly
`UNSIGNED_REVIEW_INTEGRITY_VERIFIED`, activation_authorized false.

Metadata records source/tree, binary SHA-256, hardware, exact command, exit,
CPU-seconds, peak child RSS and network counters. Single offline component run:
**2.58046269499755 seconds**. Loopback only; zero counter bytes before/after.
Not an investor-demo duration or performance range. No model inference, packet
capture, native-sensor run, clean second machine or fresh installation occurred.
No failed run is omitted; local tests and this recorder passed. Qualifying
rehearsal credit remains **zero**.

## CI and gaps

Provider snapshots distinguish current source from baseline CI. Baseline main,
teaching, contracts and Agent Zero pass; Security fails. Current-source contracts
pass, other workflows pending at initial publication. Pending is not passing.
Previously retained HIGH Helm findings remain open; no suppression or weakened
gate. C2 operator authentication, signed review binding, transactional state,
packs, UI/API, OVERLAY, complete kit, second host and full rehearsals remain open.

Current source teaching CI 43395769022 now **PASS**: 314 Rust / 294 focused
Python (overlapping local counts). Original artifact 14022796863 is retained
unchanged as `ci-teaching-original.zip`, SHA-256
`fc1d9bf5564a95528c92434b3a7cce432e3b1eab766d5d983e7d506de7aafb80`.
Both hosted review commitments verify separately after download; selected pins
and results are in `ci-review-verification.json`. This checks integrity, not an
expert signature over the review or independent-administration acceptance.
