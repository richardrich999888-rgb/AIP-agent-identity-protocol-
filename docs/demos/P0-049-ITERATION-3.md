# P0-049 iteration 3 — explicit exclusion word forms

Implementation: `4d002accbf6759fe1845872ac5579815c8081631`.
Tree: `ac6a26bcfec23e8da962d2e30633a056c9694950`.
Delivery: [draft PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21).
Review date: 12 November 2026.

**Release NOT READY. Teaching attack gate FAILED.** The B3 word-form defect is
fixed for four explicit maintenance word pairs. The broader suite reveals an
existing applicability failure, retained locally and reproduced on CI. Neither
the failed case nor the gate was relaxed to make CI green.

## Reconciliation and bounded acceptance

Fetched AIP, read the current matrix, and refreshed OVERLAY's 24-branch inventory.
Started at `97ea6ea`; no divergent branch was merged. The original OVERLAY W4/W5
commits remain unavailable here. The prior head's workflows were queued at the
initial inspection. The historical Helm-render Trivy findings remain unresolved;
changing retained evidence or disabling sensor requirements would not fix them.

The next actionable teaching dependency was B3: a quoted `cables` exclusion did
not match `Cable`, while B2 refused that singular answer. Acceptance for this
bounded repair: explicit source-linked additions, retention of quoted forms,
literal runtime matching, no subject/input-cue expansion, unsupported answers
refused atomically, unchanged approval/tenant/clearance/validation gates, and
real compiled comparisons including false-activation probes.

## Implementation and policy

`harness/exclusion_terms.py` defines
`syntriass.maintenance-exclusion-word-forms/v1`: motor/motors, cable/cables,
generator/generators and dry-type transformer/dry-type transformers. These are
reviewed engineering vocabulary entries, not a general language algorithm.

B1 shows each optional form with its quoted source. B2 accepts it only for an
exclusion and only when its exact source form remains in the same answer. It
records the policy, source term, citation and owning question ID on the edit.
The regenerated questions digest binds the policy and choices; answers for old
wording/choices must be supplied again. No variant is inserted automatically.
Unknown vocabulary, synonyms and uncited forms remain refused. Topic terms and
input cues retain literal provenance. Both term questions now state the existing
32-character limit. The eight-item schema limit remains unchanged.

The runtime and IR compiler are unchanged. The new answers add four negative
guards without replacing source terms or changing thresholds. No capability is
approved or activated. Session and answer metadata remain unsigned; signed
per-answer receipts are still a separate open requirement.

## Actual results

The new recorder regenerates and hash-checks the pinned HU-TX-2 corpus, creates
a real CLI teaching session, independently checks its content hash, drafts the
IR, asks questions, applies scripted engineer answers, compiles and proposes the
candidate, then uses signed suites with the unchanged runtime scoreboard.
The engineer script is not an external domain expert or live UI interaction.

| Check | Result |
|---|---|
| Full capability-learning Python suite | 324 passed, zero failed/skipped |
| Runtime regression suite | 187 passed, zero failed/ignored |
| Focused answer-policy tests | 146 passed; overlap the full Python suite |
| Original copied-plural answers | 11/12, exit 3; Cable still wrongly ACCEPTed |
| Explicit quoted + variant answers | 12/12, exit 0 |
| Original answers on expanded attacks | 17/26, exit 3 |
| Explicit answers on expanded attacks | 25/26, exit 3 |
| Singular/plural, lower/upper-case exclusions | 16/16 OUT_OF_SCOPE |
| Whole-word matching controls | 4/4 retain ACCEPT |
| Frozen false-activation cases | 5/6; `fa-3` fails before and after |
| Independent Ed25519 checks | Four local and four CI suites verified; altered suite rejected, exit 1 |

The unresolved input is `Cell 7 floats at 2.22 V at 25 C with SG 1.215.`
Expected `NOT_APPLICABLE`, actual `INSUFFICIENT_INPUT`. This does not release
equipment, but it violates the frozen cross-domain nonactivation criterion.
The compiler adds unit/cue terms to the applicability alternatives and permits
two inputs; the battery voltage and temperature can enter the transformer path.
This is a separate applicability-policy dependency. Preserve the frozen label
and fix routing before teaching activation. Both control and corrected runs have
the same failure; no new attack failure was observed in these 26 probes.

The recorder returns **3**, prints **NOT READY**, and retains
`PARTIAL_B3_ADVERSARIAL_FAILURE`. The CI step propagates that exit. Passing the
12-case suite alone must not be presented as acceptance of this candidate.

## Reproduction, provenance and limits

With a staged binary, Python 3.10+ and Git/source checkout, this command makes no
downloads or builds and needs no third-party Python package:

```bash
python3 research/capability-learning/harness/record_exclusion_policy.py \
  --binary target/debug/syntriass --out /tmp/p0-049-b3-new
```

Use a new directory. At this revision, expect exit 3 and inspect the failed
attack report. Building the binary first may require network access to populate
Cargo's cache and is not an offline installer.

| One bounded execution | Source | Wall seconds | Child CPU seconds | Peak child RSS KiB |
|---|---|---:|---:|---:|
| Local, Linux 6.18.57; 9 CPUs; MemTotal 10206472 kB | Clean `4d002ac` | 0.8565336249998836 | 0.450454 | 15616 |
| Connected CI, Linux 7.0.0-1017-azure; 4 CPUs; MemTotal 16367516 kB | Clean merge `192acf0` | 0.26487211500000285 | 0.166703 | 22956 |

These are separate single-run observations, not a performance range or investor
demo measurement. The merge and implementation trees are identical. Both hosts
produce identical capability hashes and case outcomes. Model calls: zero;
model hashes: none. Cgroup limits are unavailable and labelled as such.

Local reproduction used the existing user/network-namespace wrapper: only
loopback, unchanged zero packet/byte counters, no external IPv4 route. No packet
capture or kernel sensor ran. CI was connected. Neither is a genuine clean-machine
offline installation or external-evaluator acceptance.

Evidence: `evidence/p0-049-iteration-3/`. Includes the full local run, downloaded
CI artifact, signed suites, public keys, source/draft/question/answer chain,
failed development attempt, raw tests/logs and SHA-256 manifests. The CI archive
digest matched `fed9e11be15b966e88c7c3a9ed6dd097e412cb6c2ea5e75c4fded16e54bc300b`.
Private signing keys were temporary and discarded. Hash manifests, diagnostics
and edit histories are unsigned; public synthetic keys are not independent
expert identity proof.

Self-review covered explicit selection, paired-source retention, question-digest
binding, provenance boundaries, no state mutation, failure retention and nonzero
CI propagation. This is not an external security review.

## CI and next item

[Teaching CI 43164083237](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43164083237)
passed the runtime/storage regressions, old scoreboard recorder and 146 focused
Python tests, then **failed** on `fa-3`, exit 3. The artifact upload succeeded.
The contract workflow passed. Source main CI's audit/deny job passed; its fmt/test
and coverage jobs were still running at the retained snapshot. Source Security
failed Trivy on the same four HIGH historical-render findings (KSV-0009/0010/0118/0121);
audit and secret scan passed. The retained audit JSON reports zero vulnerabilities
and warnings, with the existing RUSTSEC-2026-0097 ignore unchanged. The deny log
retains its existing unmatched-advisory warning. No full-CI green claim is made.
Later evidence-only heads require their own status inspection.

Next: repair the applicability gate against the unchanged false-activation set,
including cross-domain inputs, before completing C1's general answered-session
interface and exact failed-row/question linkage. Then continue C2 approval.
All remaining release gaps remain in the completion matrix. This iteration earns
zero full-mode rehearsal passes and does not close C1 or W3.
