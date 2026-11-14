# P0-050 — retained Helm finding classification

14 November 2026 IST. Bounded item: classify four existing HIGH Trivy findings without modifying original evidence or suppressing the scanner. Static assessment at `940948ec30f754558672f79a2fa6693ed89ec319`; all concurrent teaching review changes preserved. No runtime code, deployment configuration, scanner gate or licence changed.

## Previous blocker closed at CI scope

Source 049f015 full CI 43357327167 and checkpoint 93c65bc full CI 43357780113 completed successfully. Current checkpoint 940948e full CI 43396261651 also passes, including coverage, debug/release tests, formatting/lint, audit/deny, PostgreSQL, Python SDK and RED job. Provider job metadata is retained in ci-jobs.json. These are completed hosted runs freshly inspected today, not newly executed local tests. Container/contract checks do not prove autonomous framework task success. Existing ignored/deferred kernel gates are not upgraded by a green workflow.

The source tree also includes P0-051 review commitments (2d3a226/940948e). This static deployment review does not independently accept those semantics or claim completed expert approval.

## Results in original scanner order

| Finding | Current template condition | Static verdict | Review rank |
|---|---|---|---:|
| KSV-0009 | hostNetwork true, line 32 | needs_review | 1 |
| KSV-0010 | hostPID true, line 31 | needs_review | 4 |
| KSV-0118 | Explicit runAsUser 0, lines 49–56 | needs_review | 2 |
| KSV-0121 | Host /proc mount, read-only, lines 60–69 | needs_review | 3 |

All four configuration conditions remain present in deploy/enterprise/kubernetes/chart/templates/runtime.yaml. The scanner's root wording calls it a default context, but source explicitly requests UID 0; this does not negate the root concern. No finding is dismissed as a false positive or accepted risk. HIGH scanner severities remain unchanged. Ranks prioritize the review of possible host effects, not measured exploit likelihood.

The chart defaults to disabled and README explicitly calls it an opt-in, runtime-unvalidated deployment template. Host visibility is intentional for the configured sensors. Drop-all-then-add PERFMON/NET_ADMIN, no token, read-only root/mounts and no privilege escalation constrain the configuration, but do not independently establish safe deployment. Admission policy, actual privileges, host firewall behavior, runtime isolation and independently administered collector custody are not proven. Kubernetes README warns ordinary NetworkPolicy may not cover hostNetwork traffic.

No root or applicable scoped SECURITY.md/AGENTS.md was found in the checkout. Boundary analysis uses Kubernetes README, values.yaml, runtime.yaml and deploy/enterprise/linux/README.md. The latter documents initial-network-namespace/CAP_NET_ADMIN requirements for connector and CAP_PERFMON for perf sensors; necessity for an actual supported Kubernetes deployment still requires experiments. Supplemental policy-resolver/static-assessment reference resources were unavailable; policy files were checked directly. triage.json records one result per input, uncertainties, rationale and next steps.

## Original provenance

Latest Security run 43396261719 failed. Its original artifact 14021914736 is retained as trivy-original.zip, SHA-256 b1c090ab755892c28267322c3575bfb6a96de0e18dc921090981ad805043b7f1. The extracted trivy-results.sarif preserves all four inputs. The reported path is validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml. Original archives, rendered YAML, chart and CI configuration were not rewritten or moved. SHA256SUMS pins this checkpoint's report and originals; checksums require an independently authenticated source and do not establish key custody.

## Acceptance and next bounded item

Classification COMPLETE; remediation and release NOT READY. No new build, test, installation, cluster operation or exploit execution was performed. This is a static triage iteration; no fresh sensor/benchmark/demo credit. Security remains failing. The workflow installs Trivy from a floating upstream installer: toolchain/scanner reproducibility remains unqualified and was not silently repaired within this item.

Next: define and implement a separately reviewed least-privilege probe evaluation configuration with explicit kernel/sensor coverage and host-egress acceptance. Test on an approved isolated Linux host before changing host flags or claiming a safe Kubernetes deployment. Preserve CANNOT_PROVE on lost coverage. Do not remove host visibility simply to turn the scanner green, and do not exempt historical evidence or current templates without an evidence-backed gate design. No production enforcement or deployment authorized by this report.
