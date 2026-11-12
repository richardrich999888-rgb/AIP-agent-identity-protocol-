# P0-050 iteration 1 report

**Replay continuation, 12 November 2026:** the already-landed applicability repair
now has a reusable verifier with separately supplied trust/byte pins, OpenSSL
signature checks and native replay of every frozen outcome. Fresh local and
original CI packets pass 12/12 and 26/26 (6/6 subset). Fresh checks here:
**375 Python tests**, including **22 new replay controls**; **187 native runtime
tests**; formatting and Clippy pass. These overlap the earlier counts below and
must not be added together. Checkpoint `975b245` was preserved; no compiler,
lifecycle or acceptance data changed here. See [continuation evidence](evidence/p0-050-replay/README.md)
and the [portable command](../demos/INDEPENDENT-VERIFICATION.md).

This closes reliance on unsigned summaries for the bounded replay. It does not
prove expert identity, independent administration, an independent implementation
of domain rules, full sandbox CI, signed packs or offline-kit acceptance.
S2's sandbox/CI discrepancy remains next; complete release NOT READY.

**Bounded applicability repair accepted; complete release NOT READY.**
12 November 2026. This is an iteration report, not final commercial qualification.

## Item and acceptance

Prevent shared measurement units from routing an unrelated request into a taught
procedure. Preserve the frozen holdout and expected labels, pass all 26 attacks
and six frozen nonactivation probes, retain expert corrections/citations and
tenant/clearance/validation gates, and perform no implicit activation.

The existing compiler expanded a capability's applicability terms with quantity
units such as `V`, `kV` and resistance spellings. A battery-cell question containing
`V` and temperature therefore entered a transformer procedure and received
`INSUFFICIENT_INPUT`. The unchanged expected result is `NOT_APPLICABLE`.

Applicability now uses taught topic terms, explicitly declared input cues and
explicit exclusion terms. Units are still parsed and converted as before, but
the compiler does not introduce them as domain evidence. Explicit exclusions
route to the existing `OUT_OF_SCOPE` guard, which runs before missing-input or
decision rules. The existing minimum-measurement gate is preserved.

| Distinction | Observed bounded behavior |
|---|---|
| Out-of-domain request | Measurements without taught context: NOT_APPLICABLE |
| Explicit exclusion | Excluded equipment with qualifying measurements: OUT_OF_SCOPE |
| Missing input | Taught context with enough input to enter the procedure, but a required reading absent: INSUFFICIENT_INPUT |
| Too little context/input to enter | No measurement request or insufficient applicability gate: NOT_APPLICABLE |
| Ambiguous measurement | Conflicting readings: AMBIGUOUS |
| Missing required signed evidence | Applicable signed-record capability without a record: EVIDENCE_REQUIRED |
| Unsupported/untrusted evidence | Forged/unknown instrument record rejected; no plaintext fallback |
| Insufficient retrieved evidence | Existing withholding/source/clearance behavior remains unchanged; not relabelled as applicability |

This is a bounded lexical policy, not general intent understanding. A supplied
topic/cue can still match a mixed-context or quoted request. Expert-reviewed
scope and broader domain acceptance remain necessary. No equipment-specific
string exception was added to production code. A renamed synthetic topic/cue
test exercises the same rule independently of the transformer/battery names.

## Source and migration boundary

- Parent: `925432b181ea194565fa855b9d3d3c734723354b`.
- Implementation: `ef3d9d434e5ed55e5994331abc91c03833f997ff`.
- Tree: `d8e21fc9b2fa8ae4ad981036f0c082916fc51e86`.
- CI merge: `de0786e22a433512c50c402af4057d28564452d1`, independently fetched and
  confirmed to have the same tree.
- Draft [PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21)
  remains on `feature/airon-teach-demo`; no merge to main or force push.

Only `ir_compiler.py`, its existing repair-name assertion, the new applicability
tests and their inclusion in teaching CI changed. Runtime routing, parsing,
thresholds, rules, outcome labels, source citations and lifecycle code did not.
The retained comparison proves that **only `applicability` differs in the
compiled capability** and that all test inputs/labels remain byte-identical.

Existing serialized/signed capabilities are not rewritten by this fix. A freshly
compiled corrected capability has a new content hash
`1c39aff4e00384082cc9df6a296ec41712d41d9103640316c7eff00654fb2164`.
Recompile, revalidate, obtain a new authorized approval and explicitly supersede
under local policy before deployment. No existing approval is carried over.

## Fresh validation

| Check | Result | Qualification |
|---|---|---|
| Clean parent reproduction | Exit 3; holdout 12/12, attacks 25/26 | fa-3 failure retained before source change |
| Clean implementation, fresh local build | Exit 0; holdout 12/12, attacks 26/26 | Six frozen nonactivation cases are a subset, not six extra passes |
| Separate connected CI build | Exit 0; same 12/12 and 26/26, same capability hash | Independent host reproduction of component only |
| Copied-plural negative control | Holdout remains 11/12, exit 3; attack control 18/26 | Eight missing singular-exclusion cases still rejected as validation failures |
| Full capability-learning Python suite | **353 passed**, zero skips/failures | Includes 29 new tests; clean-build rerun 9.10 s |
| New applicability tests | **29 passed** | Positive, missing, excluded, unrelated, ambiguity, evidence and mutation cases; subset of 353 |
| Targeted behavioral mutants | **4/4 detected** | Restored unit scope; removed minimum-input gate; removed exclusions; removed evidence requirement. Not an exhaustive mutation campaign |
| Runtime + sovereign/corpus tests | **284 passed**, zero failed/ignored | 187 runtime + 97 sovereign/storage; includes 19 sandbox and two SQLite regression tests locally |
| Teaching CI focused Python tests | **175 passed** | Subset overlaps local tests; do not add counts together |
| Separate Ed25519 verifier | Eight local/CI suite signatures verify | Synthetic fixture keys, not proof of external expert authority |
| Modified signed suite | Exit 1 / rejected | Changed expected label; original signed bytes retained |
| Evidence consistency/hash checks | Pass | Original CI ZIP digest checked; all recorder manifests verified; frozen inputs unchanged |
| Lifecycle side effects | None | All recorded scoreboard runs retain unchanged capability state; zero model calls |

All newly added tests require a real binary and fail visibly if it is missing.
No frozen acceptance label, threshold, ignore list or security assertion was
weakened. The full repository's security/CI gates are **not** declared green.

## Hardware and individual measurements

These are single observations of the **component recorder**, not the three-minute
investor sequence, a performance range or a product benchmark.

| Run | Host | Wall seconds | Child CPU seconds | Peak child RSS KiB | Binary SHA-256 |
|---|---|---:|---:|---:|---|
| Fresh local build, isolated namespace | Linux 6.18.57 x86-64, 9 available CPUs, MemTotal 10,206,472 KiB | 0.4039170820005893 | 0.168796 | 15604 | `07e7aec9a95a3b6da2aed750898aad9fbc412e3afec8aebd80ed08a09541979f` |
| Connected CI | Linux 7.0.0-1017-azure x86-64, 4 CPUs, MemTotal 16,366,512 KiB | 0.22955532699999992 | 0.136628 | 22596 | `ec7d08a3cf185bdb6a9ee8ab017e258e9c4e4da6ca97e67757326019ddb69ac3` |

Cgroup CPU/memory files were unavailable and are recorded as such; reported host
memory is not a guaranteed allocation. The local namespace has only loopback,
no external route and zero byte/packet deltas. There is **no packet capture**,
native sensor, live model or initial-netns isolation proof in this run. The CI
runner was connected and downloaded build dependencies. Neither is a complete
offline-kit installation or an external evaluator acceptance.

## CI and retained failures

Teaching workflow [43169880420](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43169880420)
and contracts `43169880521` pass at the implementation. The original teaching ZIP
and full teaching job log are retained. Security
[43169880474](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43169880474)
fails Trivy with the same four HIGH findings, KSV-0009/0010/0118/0121, in the
historical `validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`.
Its audit and secret-scan jobs pass. Original SARIF/audit artifacts are retained.
Do not disable host observation or rewrite historical evidence to hide findings.

Main CI [43169880412](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43169880412)
**fails**, with fmt/clippy themselves passing and the test and coverage jobs
failing. Audit/deny, PostgreSQL, SDK and RED jobs pass. The implementation and
parent both fail the same three tests in
`sovereign/vanian-sovereign/tests/agent_execution.rs`: authorized output, loopback
inspection and changed exit-code rejection. The retained failure excerpt shows
empty output and a runner-attested Code(1) bundle; it does not by itself establish
the underlying sandbox cause. This local/CI discrepancy remains a priority gate.

Earlier attempts are retained: rejected clean parent, passing development tree,
clean source with the previously built binary, and the final fresh build. The
initial independent comparison script incorrectly required different sessions to
share the same questions digest. Its failure is retained. Inspection found only
the session ID differed; the repaired comparison verifies each session binding
and compares the actual cited questions/choices. No product expectation changed.

## Delivery and next iteration

The strategic matrix, scored roadmap, guide, verification instructions, rehearsal
ledger and open-gap report accompany original evidence under
`docs/assurance/evidence/p0-050-iteration-1/`. Diagnostic JSON is unsigned. Only
the expert test suites are signed; hashes and signed test inputs do not sign a
diagnostic verdict. Recompute outcomes for independent acceptance.

Next: reproduce and resolve the teaching branch's sandbox/CI discrepancy by
reviewing the existing PR #16 content and conflicts, without weakening tests.
Then address remaining Security findings and continue C1/approval dependencies.
No full-mode rehearsal credit is earned; all required ten-/twenty-run counts for
this final release remain zero. All unresolved requirements are in
[P0-050-OPEN-GAPS.md](P0-050-OPEN-GAPS.md).
