# Superseded CI candidate 19d1aa3

This is an explicitly incomplete snapshot, not an acceptance or successful-suite report. Source head: `19d1aa31b29997ffcbadcf6e5f52591ff41b5bca`. GitHub tested PR merge checkout `c4fa9543fd66f5c7554a21b7e9d65cf0175a2657`.

At capture: 22 jobs; 11 successful, 7 failed, 3 gated/skipped, 1 still running. The same-run genuine execution and interruption steps passed; recovery remained in progress and no public same-run artifact had been preserved yet.

Workspace format passed. Clippy, workspace debug, workspace release and coverage stopped at a missing ObservationBatch.filter_report fixture field before tests. The focused release regression passed 59 probe tests and three startup/binding tests, then could not compile the new verifier helper because ghost-demo lacked its serde_json development dependency. The requested twenty g14_04 repetitions did not execute; no verifier verdict was observed in that regression job.

Strict security gates remain failed: gitleaks 217 generic-api-key findings; Trivy four HIGH misconfigurations; cargo deny rejected chrono 0.4.45 under RUSTSEC-2026-0543. Cargo audit passed with its existing ignore but reported chrono unmaintained and rustix 1.1.5 unsound informational advisories. No waiver was added. See the safe security/audit summaries.

RBI rehearsal failed its full-system gate; detailed redirected runtime diagnostics were lost when artifact upload could not read root-owned attested.archive.jsonl. Its actual runtime root cause is unknown from preserved CI output. The fixed candidate needs a fresh run.

The hosted sensor component smoke passed with 55 signed batches, explicitly no autonomous workload claim. Package install/uninstall/reinstall passed only in a staging root. The green RED ledger job has 43 reproduced/runnable cases, two notes and ten blocked cases. These do not validate a full installed sensor service, a customer deployment or an independently administered collector.

No customer-pilot readiness or security readiness is asserted.
