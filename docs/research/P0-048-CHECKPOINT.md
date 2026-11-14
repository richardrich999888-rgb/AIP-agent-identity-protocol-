# P0-048 checkpoint — iteration 005

Branch: `codex/p0-048-snifferdog-enterprise-assurance`.
Integration base: `fix/vanian-end-to-end-green`, `4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
Parent: `61dd73013d02ea7869de104d953f330098df1c32`.
14 November 2026 (Asia/Kolkata).

The next selected item is security-CI finding classification and remediation,
with historical evidence preserved and no weakening of new-finding detection.
The parent has five successful workflows and one failed Security workflow.

## Implemented item and local acceptance

Reproduced both failures with the baseline scanner versions: two public
Qwen tokenizer-checksum matches and four HIGH warnings in the immutable
28 October Helm fixture. Gitleaks now classifies only the two original commit
fingerprints. Trivy still scans all files and retains its unfiltered SARIF;
a separate gate accepts only the four exact archived findings after checking
original bytes, paths, rule IDs and locations. New findings, copied manifests,
missing expected results and scanner failures remain blocking.

Local results: 17 classification controls and three real scanner controls pass.
The original Gitleaks PR range is clean under the exact false-positive
classification. Fresh Trivy output retains four archival HIGH warnings and
zero new findings. A newly rendered enabled Kubernetes chart still produces
all four HIGH warnings; no deployment qualification or risk waiver is claimed.

- [Classification, implementation and limitations](P0-048-SECURITY-CI.md)
- [Commands and retained results](../../validation/p0_048/iteration-005/README.md)
- [Prior native qualification](P0-048-NATIVE-QUALIFICATION.md)
- [Prior checkpoint](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/61dd73013d02ea7869de104d953f330098df1c32/docs/research/P0-048-CHECKPOINT.md)

Hosted results at the new published head are pending. Local acceptance is not
a claim that a future CI run passed. Native runtime code and prior signed
archives are unchanged; the ten native Linux assertions remain tied to their
recorded executed revisions.

## Checklist

| Workstream | Current state |
|---|---|
| A — audit | Completed to the recorded structural and targeted-review scope |
| B — sensor correctness | Socket multiplicity and delayed connector-event/cache corrections complete; ten native kernel assertions now pass on the recorded disposable host; executable/descriptor consistency, namespaces, concurrent attribution and broader interruption qualification incomplete |
| C — SPIFFE/SPIRE | Existing adapter qualification and lifecycle/binding guarantees pending |
| D — OTel GenAI | Existing cross-branch telemetry and full GenAI correlation pending |
| E — Tetragon | Optional evaluation on a supported host pending |
| F — policy/gateway | Complete fresh negative matrix pending |
| G — frameworks | Full framework task acceptance pending; historical failures remain |
| H — custody | Fresh socket/lifecycle and live connector/loss signatures and tamper checks complete; independent administration and full custody matrix pending |
| I — air gap | Complete bundle and clean-host/firewall qualification pending |
| J — performance | Bounded churn and one explicit component timing run retained; required performance matrix pending |
| K — demo | Full retained nine-scene demo acceptance pending |
| L — release | NOT MET: new-head hosted security/regression inspection pending; clean installation, independent custody and ten full rehearsals remain open |

## Next item and release limits

Publish this security-CI item, inspect actual new-head runs and retain provider
results. The next sensor correctness item is executable/descriptor consistency
under replacement and exit. Broader concurrent attribution and interruption
qualification, the C–K workstreams above and independent enterprise acceptance
remain incomplete. Keep PR #20 draft; no merge or production enforcement.
