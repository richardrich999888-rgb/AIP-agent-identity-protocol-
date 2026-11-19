# P0-051 iteration 2 — explicit example mapping

**Release NOT READY.** This checkpoint closes the bounded TXT outcome-mapping
mechanism, not C2 approval, full teaching/UI, packs or offline release acceptance.

Source `7c9a0b385d88460d19da100a4c99dd0ff3c2a2c0`; CI merge
`c6fd26a1468644b16261e16b2ef36ec9a94acb3b`; identical tree
`90f9291d7ec392db466c52016c581112815080b0`. Native binary hash and all changed
source hashes are in `source-and-environment.json`. This iteration changes no
Rust runtime bytes, frozen dataset or task file. The binary was built on the
prior implementation; current hosted Rust tests rerun on the combined source.

Acceptance: examples are replayed separately under an explicit input-bound map;
withheld/missing/ambiguous/out-of-domain answers never satisfy negative examples;
passing examples never override signed-suite failure; no activation occurs.

| Check | Observed result |
|---|---|
| Full local Python, clean published source | 445 passed, no skips; 37 mapping tests are new |
| Hosted teaching run 43220664054 | 267 focused Python and 289 relevant Rust passed; overlapping local/CI counts |
| Live session scenarios on both hosts | Control 11/12 remains rejected; corrected 12/12 and 26/26 pass; 3/3 examples separately in each |
| Frozen nonactivation probes | 6/6, included in the 26; never add them |
| Separate-process original replay | Local and downloaded CI source/session/answers/maps/suites recomputed; outcomes and non-timing validation fields match |
| Independent signature implementation | Python cryptography verifies six signature instances per host: three unique suites, duplicated before/after example review |
| Replay attacks | One-byte suite mutation and changed map exit 2; wrong key exits 3 with failed validation and zero expert cases passed; altered saved verdicts are ignored |
| Namespace counters | Local only loopback, zero bytes before/after; no packet capture or initial-netns sensor |
| Security run 43220664086 | Four HIGH retained Helm-render findings; audit and secret scanning pass; no suppression |

`local-original.zip` holds the clean local component, all original local/CI
replay outputs, tampering controls and command logs. `development-original.zip`
retains development outputs and the first replay-control failure. The untouched
GitHub artifact `ci-teaching-original.zip` is artifact **13944923074**, SHA-256
`e566d34a6294e8c37a35106d37b45e26a67e1ef4a8ad357e02cc8d55dcf87648`.
It contains all original teaching and signed runner evidence uploaded by that
workflow; runner signatures are not native Sniffer Dog observation. The original
Security artifact is `ci-trivy-original.zip`. Raw decoded teaching logs and
provider metadata accompany the ZIPs.

`retention-verification.json` records ZIP/inner-manifest checks and inspection for
private-key fields. Intentional attack copies retain their original input
manifests: one-byte suite, stale map and false verdict mutations correctly
produce the enumerated checksum mismatches. Unmodified originals match.
No private key is distributed. Hash manifests are unsigned; authenticate source,
archive and authority separately. Synthetic keys do not establish expert identity.

Failed attempts are retained in full. `first-regression.txt` records 67/68:
the new missing-input fixture omitted taught context and got NOT_APPLICABLE.
Its input was corrected, keeping frozen acceptance labels unchanged. The first
replay-control script expected exit 2 for a valid-shaped wrong public key;
native validation correctly rejected it with exit 3. The corrected control also
checks failed validation and zero expert cases passed. The first comparison
attempt included nondeterministic `wall_micros`; `comparison.json` preserves
both measured values and compares every non-timing validation field exactly.

The local component observation is 2.5933206640002027 seconds, child CPU
1.9584009999999996 seconds, peak child RSS 62592 KiB, on the recorded Linux host
while full Python regression ran concurrently. CI separately records
1.8950681390000028 seconds, child CPU 1.014322 seconds, RSS 67640 KiB. These are
individual component observations, not a range or full commercial sequence.

Follow [independent verification](../../INDEPENDENT-VERIFICATION.md) for exact
hash/signature/replay commands. `replay_retained_session.py` consumes original
inputs and an operator-selected binary hash/public-key map, never saved PASS
fields. The copied `check_replay_attacks.py` documents the controls used here;
to rerun it, copy both helpers to a fresh directory, extract the CI ZIP into its
`ci/` subdirectory, and run it from the repository root with staged prerequisites.
It refuses existing output directories. Nothing installs or downloads dependencies.

No approval, activation, model inference, native sensor, full signed knowledge
pack, clean-machine installation, external evaluator or qualifying full-mode
rehearsal ran. All final consecutive rehearsal counts remain zero. The next gate
is authenticated signed teaching approval, including the reviewed map digest,
expiry/revocation and authorization checks throughout lifecycle use.
