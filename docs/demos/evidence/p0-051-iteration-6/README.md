# P0-051 iteration 6 — native signed teaching-review approval

14 November 2026 IST. Source `42c1038f1ef7454821a9ecf32454f07554422866`, tree
`1f993e8383fe326828468c66dd6e85688112d869`. Hosted merge `0587f541d5994aa5b0a9b594fb7b64465f5c0edc`
has the same tree. Concurrent documentation-only Helm triage `f9ebf20` was
reviewed and preserved. No main merge, force push, licence change or deployment.

**Requested item implemented and scoped acceptance passes. Release NOT READY.**
Native approval now consumes the review commitment from iteration 5 and replays
its independent signed suite and mapped original examples before signing v3.
Saved PASS labels, consistent attacker-recomputed hashes and invented case counts
cannot replace native replay. The stored session, current corpus, capability,
tenant/domain/clearance, evaluator trust, reviewed and stored validation must agree.
Replay wall_micros may differ; all other validation fields must match. The exact
stored report is bound against changes between verification and signing.

The Ed25519 v3 payload commits capability/report hashes, expert ID, consequential
flag, decision time, authority-grant hash and teaching-review hash. The latter
commits source bytes, cited answers, example map and all review inputs. Authority
expiry/revocation/scope checks remain active. Missing or stripped review bindings
cannot activate/use when require_teaching_review is enabled. Signing leaves state
APPROVED; activation remains explicit. Existing v1/v2 signed bytes are unchanged.

## Fresh validation

- Full runtime **203 pass**, including two new use-time tests.
- Full teaching Python **490 pass, zero skips**, including 18 new actual CLI tests.
- Scoped Clippy (warnings denied) and formatting pass.
- Source teaching CI 43581109159 **PASS**, **316 Rust / 312 focused Python**.
  Counts overlap the local suites; do not add them together.
- Fresh corrected holdout **12/12**, attacks **26/26**, including six nonactivation
  probes; rejected control remains **11/12**. Three original examples pass
  separately and add no independent-suite cases. Frozen labels unchanged.
- Negative cases cover source/map byte changes, missing session/review/policy,
  unauthorized authority, altered stored validation, wrong tenant, forged suite,
  fake PASS/example outcomes/counts under recomputed hashes, stripped signature
  bindings and legacy activation. Refusals preserve capability-record bytes.
- Original local and hosted v3 approvals verify in separate OpenSSL processes.
  Seven separate archive-verification attacks reject signature-byte mutation,
  removed review, source mutation, changed report, wrong key, revoked authority
  and wrong tenant. No original agent runtime or private key is required.

## Retained originals and independent verification

`local-originals.tar.gz` retains development, final and source-pinned offline
originals, including the approved and active records, complete review inputs,
original signed suite, public policy/key, exact signature bytes and outputs.
`ci-teaching-original.zip` is the untouched hosted artifact 14108098165, SHA-256
`f663ccb050cd1b709d1e9511f59af493f8ae9e775e865a1ac31449ba463126d3`.
The CI archive also retains original sandbox and lifecycle evidence. No private
signing keys are distributed. Synthetic public pins are not production authority.

From this directory, with repository Python harness sources and OpenSSL staged:

```sh
sha256sum -c SHA256SUMS
mkdir local ci
tar -xzf local-originals.tar.gz -C local
unzip ci-teaching-original.zip -d ci
python3 verify_approval.py local/published-offline/signed-originals \
  --public-key EXTERNALLY_AUTHENTICATED_PUBLIC_HEX --policy synthetic-policy.json
python3 verify_approval.py ci/teaching-approval-evidence \
  --public-key EXTERNALLY_AUTHENTICATED_CI_PUBLIC_HEX --policy ci-synthetic-policy.json
```

The selected public test keys are in synthetic-public-trust.json and
ci-synthetic-public-trust.json. Authenticate those pins/policies independently;
never trust a key merely because an archive supplies it. The verifier reconstructs
signed bytes from the approved record, checks content/report/authority/review
bindings, then invokes OpenSSL. It does not trust the saved payload.bin. Its
output explicitly says lifecycle_history_authenticated false and
native_replay_reproduced false. Reproduce native replay with the source tests:

```sh
cargo build --locked --offline -p syntriass-runtime --bin syntriass
SYNTRIASS_BIN="$PWD/target/debug/syntriass" python3 -m pytest -q \
  research/capability-learning/tests/test_signed_teaching_review.py
```

Approval configuration/commands and limitations are in ../../APPROVAL-AUTHORITY.md.
Owner-controlled source/state and policy remain trusted; native replay evaluates
the bounded capability, not the Python draft/compiler pipeline. The expert signs
its exact review, and is responsible for reviewing cited corrections and scope.

## Offline measurement and failed setup attempts

A source-pinned component run in a fresh user/network namespace with only loopback
passed all 18 tests (exit 0, single command wall time **9.141896189000136 s**, child
CPU **9.159460000000001 s**, peak child RSS **83908 KiB**). The subsequent scoreboard
recorder passed in **2.4958095070001036 s**. These are separate single measurements,
not performance ranges or investor-demo duration. Network counters remain zero.
Exact commands, CPU/RAM, interpreter/packages, binary hash and routes/counters are
in host-and-source.json and the original archive. No packet capture, native sensor,
initial-netns isolation, live model, second clean machine or installation acceptance
is claimed. Qualifying demo/rehearsal credit remains **zero**.

The temporary workspace/toolchain had been cleared and was restored. Initial
format/Clippy invocations lacked the components; they were installed and rerun.
One initial Python run had 455 passes and one module skip (missing pypdf, hiding
32 ingestion tests); that is NOT full acceptance. A malformed temporary subset
of the dependency lock was refused; the corrected subset then correctly rejected
a CPython 3.12 lxml wheel against the repository's CPython 3.11 hash. System
Python 3.13 lacked ensurepip. All these logs are retained, not relabelled passes.

Final local tests used existing staged primary-runtime dependencies in a separate
system-site-packages venv: Python 3.12, pytest 8.3.5, pypdf 6.21.4, python-docx
1.2.0, Pillow 13.0.0, lxml 6.1.1. The deployment lock was NOT altered or bypassed
for installation. This developer test environment is not qualification of the
CPython 3.11 offline package. Full tests then passed without skips; final original
records and published offline rerun were retained separately.

## Remaining gates

Source teaching, contracts and Agent Zero CI pass; main CI is pending at this checkpoint.
Security still fails; existing HIGH host-network/PID/root/proc findings remain
open, with triage in the preserved P0-050 checkpoint. No scanner suppression or
sensor gate was weakened. See provider snapshots for source-specific state.

C2 operator-action authentication and transactional lifecycle updates remain open.
Policy/clock trust, rollback-resistant storage, per-approval revocation, signed
packs, UI/API, models/full kit, OVERLAY recovery/delivery, independent hosts and
required ten/twenty rehearsals still block release. Next bounded item:
authenticate activation/revocation actions rather than trusting actor/role strings.
