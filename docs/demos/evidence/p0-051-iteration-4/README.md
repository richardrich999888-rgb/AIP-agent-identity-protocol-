# P0-051 iteration 4 — native policy-bound approval

**Release NOT READY; C2 partial.** Source `00c06de1503785470a73a7a2f0890ad8f9c1ce84`;
source tree `e58a7c85b47a05f77a9f4e4a8246d16782d33f51`. Hosted teaching checkout
`2b5956d01d5f4a6be2e6bcef395268dbaab158f0` has the identical tree. No merge performed.

## Observed acceptance

- Full local runtime: **201 passing**, including seven new tests (three runtime,
  four actual CLI tests). Full teaching Python: **445 passing, no skips**.
- Scoped Clippy/format pass. Frozen task data is unchanged.
- Fresh teaching CI `43250976901`: **303 relevant Rust**, **267 focused Python**
  passing. These overlap local results; never add the counts together.
- Fresh signed-suite recorder: rejected control **11/12**, corrected **12/12**,
  adversarial **26/26** including the six nonactivation probes. Reviewed original
  examples **3/3 separately**, not additional suite cases.
- V2 signatures bind exact authority grants. Runtime and CLI reject expired,
  revoked, foreign-tenant/domain/expert/key, wrong scope, lowered clearance,
  below-floor versions, altered policy, removed policy and legacy downgrade.
  Changed source/report/capability and missing approval are refused.
- CLI rollback refusal preserves the current active record byte for byte.
- Separate Python cryptography verification of original suites and v1/v2
  approvals succeeds for local, offline and hosted records. Each contains 15
  synthetic fixture worlds from 11 tests, not 15 demos or independent evaluators.
- Six retained verification attacks reject signature mutation, stripped grant,
  altered source, altered signed suite, altered authority and wrong trust pin.

## Original evidence and verification

`ci-teaching-original.zip` is the untouched downloaded artifact `13957794230`,
SHA-256 `0ec8e8eff3dd83c380abdcb7fe95f142339e16a4291d13ce67aebc5d608d73a3`.
`local-originals.tar.gz` retains local runtime snapshots, suites, authority policy
inputs, session scoreboard originals and the source-pinned offline rerun.
Private keys are not retained. Public test keys are ephemeral synthetic fixtures,
not customer or production authority. Pins were selected during this audit;
a buyer must authenticate their distribution independently.

From this directory, with Python cryptography already installed:

```sh
sha256sum -c SHA256SUMS
mkdir local ci
tar -xzf local-originals.tar.gz -C local
unzip ci-teaching-original.zip -d ci
python3 verify_records.py local/final-originals --trusted-pins local-synthetic-trust-pins.json
python3 verify_records.py local/published-offline-final/originals --trusted-pins offline-synthetic-trust-pins.json
python3 verify_records.py ci/lifecycle-isolation-evidence --trusted-pins ci-synthetic-trust-pins.json
```

The verifier checks historical signatures/bindings and decision-time grants. It
is not a current-authority service, unsigned-history attestation, standalone
knowledge-pack verifier or independent human administration. Raw original files
remain available for native replay with the commands in the retained logs.

## Offline measurement and failed attempts

Source-pinned offline component run: **33 tests pass**, exit 0, single measurement
**0.945885991997784 seconds**, child CPU **3.0649200000000003 seconds**, child peak
RSS **92688 KiB**. Hardware, binary hash, exact command, routes and interface
counters are in `local/published-offline-final/metadata.json`. Counters before and
after show loopback only and zero bytes. Binary SHA-256:
`a6fd974b5de7b7f786a5f204aa1f0d8fdcb160c13127c34c80546a94cdc32e95`.

The first recorder failed because `/sys/class/net` is unavailable here; the
second failed because interface-name enumeration was denied. Their scripts and
tracebacks are retained unchanged. The final recorder reads `/proc/net/dev` and
keeps the original namespace/external-route refusal gate. No test executed in
those two failed attempts. No packet capture, live model, native sensor,
initial-network-namespace isolation, second machine or full demo is claimed.
Rehearsal credit remains **zero**. Do not use this component duration as the
investor-demo duration or combine it with hosted timing.

## CI and remaining gates

Teaching and contracts CI pass. At this checkpoint main CI remains pending;
Trivy has failed four HIGH findings KSV-0009/0010/0118/0121 in original retained
Helm output. `ci-trivy-original.zip` and logs preserve the new failure. No
finding, test, frozen label or sensor gate is suppressed. See provider snapshots
for exact workflow states; a pending workflow is not a pass.

Authenticated operator actions, the complete C1 session/full-document/example-map
approval envelope, trusted policy storage/clock, per-approval revocation and
transactional writes remain open. Legacy absent-policy mode is not C2-qualified.
Packs, UI/API/SDKs, original OVERLAY recovery/replacement, staged models/full
kit, clean-host installs, independent evaluation and ten/twenty rehearsals remain
release blockers. Next bounded item: bind the independent teaching replay and
reviewed example mapping to the signed approval envelope.
