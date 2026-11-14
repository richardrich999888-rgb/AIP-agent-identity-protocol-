# P0-048 iteration 005 — security finding classification

Reviewed parent: `61dd73013d02ea7869de104d953f330098df1c32`.
14 November 2026 (Asia/Kolkata). This item corrects the security CI decision
for two false-positive checksum matches and four immutable historical warnings.
It does not remediate or approve the enabled Kubernetes host-access profile.

## Findings and scope

| Finding | Evidence and decision |
|---|---|
| Gitleaks `generic-api-key`, inventory line 7515 | A public Qwen tokenizer file SHA-256 under `file_sha256`, copied from `integrations/interoperability/upstreams.lock.json`; not a credential. Classify only the original commit/path/rule/line fingerprint. |
| Gitleaks `generic-api-key`, inventory line 7516 | The adjacent public tokenizer configuration file SHA-256; same narrow classification. No new commit, path or line is exempted. |
| Trivy `KSV-0009` | Host networking in the retained 28 October Helm rendering. The warning is accurate; the immutable rendering is a historical fixture using an invalid example registry, not a deployed workload. |
| Trivy `KSV-0010` | Host PID access in that same historical rendering. Preserve the HIGH warning and original bytes. |
| Trivy `KSV-0118` | Root execution in the historical node probe. Preserve the HIGH warning and original bytes. |
| Trivy `KSV-0121` | Host `/proc` mount in the historical node probe. Preserve the HIGH warning and original bytes. |

There is no applicable root/scoped `SECURITY.md` in the inspected tree. Scope
comes from `deploy/enterprise/kubernetes/README.md`, the source chart and
`validation/enterprise/results/HELM_20261028T103133Z/report.json`. The latter
records rendering-only execution and synthetic image/configuration values.
Static triage is recorded separately in the iteration's `triage.json`.

The chart source still has the same elevated host-access profile. A fresh Helm
3.18.6 rendering is byte-identical to the historical fixture, and a fresh Trivy
scan of that new rendering returns all four HIGH warnings. Both components
remain disabled by default, with digest/configuration/separation prerequisites.
Those prerequisites do not prove a secure running cluster or separate key custody.
This branch does not deploy a cluster or claim those warnings were fixed.

## CI behavior

- Gitleaks keeps its default rules and existing configuration. Two exact
  immutable commit fingerprints are added to `.gitleaksignore`. The previously
  executed action revision is pinned; no rule or directory is disabled.
- Trivy scans the complete working tree with `secret,misconfig` and the same
  CRITICAL/HIGH threshold. No ignore file, excluded directory or blanket rule
  suppression is added. Its original SARIF is uploaded without filtering.
- A separate decision checks the exact historical artifact SHA-256, rule IDs,
  file path and line ranges. It reports `PASS_WITH_ARCHIVED_FINDINGS`, including
  all four warnings and `deployment_qualified: false`. A new finding, duplicate,
  missing expected warning, changed archive, scanner mismatch or malformed report
  fails the gate. A copied manifest does not inherit the original classification.
- Findings use scanner exit 42, distinct from operational errors. Errors, absent
  reports and inconsistent exit/report combinations fail. Artifact absence also
  fails upload. The Actions summary states the remaining deployment limitation.
- Trivy 0.76.2 and the Gitleaks 8.24.3 control binary are downloaded from their
  versioned official releases with pinned archive and executable SHA-256 checks.
  Pins were matched to the publishers' checksum files. This is transfer/content
  verification, not an independent publisher-signature attestation. Native
  product dependencies, authority, signatures, coverage and verdicts are unchanged.

The four archive warnings remain visible in the unfiltered report. Classifying
the archival artifact is not a production risk waiver. A fresh unsafe manifest
must fail regardless of whether its bytes match the old fixture.

## Executed local verification

| Check | Observed result |
|---|---|
| Original Gitleaks PR range, before classification | Exit 42; exactly the two reported checksum matches |
| Same Gitleaks range, with exact fingerprints | Exit 0; zero remaining matches |
| Unfiltered Trivy before/after the change | Exit 42; the same four HIGH archive warnings |
| Classification of the complete fresh report | PASS_WITH_ARCHIVED_FINDINGS; 4 archival, 0 new, deployment unqualified |
| Gate regression controls | 17 passed, including changed evidence, malformed scope, missing results and scanner errors |
| Real Trivy on an additional copied manifest | Four new HIGH warnings; classifier refuses them |
| Real Gitleaks on a new commit at inventory line 7515 | Synthetic provider-shaped token detected despite the old fingerprint |
| Independent Trivy secret scan | Same synthetic token detected; fake token bytes are not retained |
| Current chart rendered with Helm 3.18.6 | Identical original bytes; all four HIGH deployment warnings remain |

Evidence, commands, scanner pins and source hashes are retained in
[`iteration-005`](../../validation/p0_048/iteration-005/README.md).
Hosted CI at the new published source is recorded there separately; local
results do not imply a hosted pass. The parent head's five other workflows
completed successfully; its Security workflow was the reproduced failure.

## Remaining P0-048 work

The full loop is incomplete. The next sensor item is executable/descriptor
consistency under replacement and exit, followed by broader concurrent
attribution qualification. SPIFFE/SPIRE, GenAI telemetry, optional Tetragon,
policy/framework acceptance, independent collector administration, clean-host
air-gap installation, performance and full demo/release acceptance remain open.

Upstream configuration reference: [Gitleaks fingerprints](https://github.com/gitleaks/gitleaks#ignoring-findings).
The Trivy decision uses its unfiltered SARIF, not a scanner ignore policy.
