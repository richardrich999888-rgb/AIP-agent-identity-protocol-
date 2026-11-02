# Final bce0037 CI results

Evaluated source: `bce0037d6ca5eb1b85a9f2d242f4b2650dd2e6d9`. All 22 PR jobs completed: **17 passed, 2 failed, 3 guarded skips**. The 18 component/security checks comprise **16 passed and 2 failed**; the ordinary same-run core job passed separately. The three PR skips concern the genuine Agent Zero task and local evidence-agent capture/offline jobs. Manual capture run 41508547378 is evaluated separately.

The complete CI suite was rerun. Debug unit/integration tests passed **3,268**, with 0 failures and 7 ignored; release passed **3,270**, with 0 failures and 5 ignored. Each profile also passed 2 doctests, with 2 ignored. Coverage repeated the debug 3,268/0/7 result. These overlapping runs are not added into a unique-test total.

The CannotProve regression g14_04, observer-binding b05, signed-envelope b13 and wrong-process-instance regression passed in both profiles. The focused release job passed all 20 g14_04 repetitions. Harness controls passed 138; actual OPA/SDK/Collector controls passed 21 with no skips; Python SDK passed 76; ContextForge passed 11 policy and 27 actual interoperability checks. RED reported 43 runnable, 2 notes, 10 blocked and 0 failed; blocked rows remain unexecuted.

**Strict security CI remains failed.** Gitleaks reported 217 results and Trivy 4 HIGH results. Their complete result-object multisets exactly match retained 75e75bb originals, with 0 new or missing results. This comparison does not waive either failed gate. Cargo audit passed with 0 reported vulnerabilities under the inherited RUSTSEC-2026-0097 exception; no exception was added.

The tested PR merge `671bc037be711debaea2f8c74b8759f638ad0fe7` and bce0037 have identical tree `1a2c0e9c881a4c4885367cf57a35bad0d1583c64`. This CI result does not establish separate collector custody, production approval or successful business tasks across all three frameworks.

Registry: [snifferdog-ci-bce0037-summary.json](bce0037-summary.json). Safe scanner comparison: [snifferdog-security-bce0037-summary.json](../security/bce0037.json). Selected test receipts: [snifferdog-ci-bce0037-receipts.json](bce0037-receipts.json). Full connector-decoded test logs remain in private staging; raw detector values are excluded.
