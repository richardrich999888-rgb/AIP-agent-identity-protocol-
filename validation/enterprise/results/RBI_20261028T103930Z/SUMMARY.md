# Fresh hosted RBI rehearsal: all five scoped acts passed

Run [40672603812](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40672603812) completed successfully on commit `e9da41314c3851a92388a8ce80f1db9a3a696520` on 2026-10-28. Both `script-regressions` and `live-rehearsal` succeeded. The session transcript started at 10:31:55 UTC (16:01:55 IST); the workflow completed at 10:33:55 UTC (16:03:55 IST).

## What the five acts establish

| Act | Executed result | Scope |
| --- | --- | --- |
| 1 — honest path | PASS: collector-signed `Active` with non-null attested coverage | Real Linux sensors, probe and collector; synthetic process/network workload |
| 2 — interference | PASS: a real foreign eBPF gate on `sched:sched_process_exec` produced signed `IntegrityUnknown` and withdrew coverage | Live kernel experiment; detection/degradation, not attack prevention |
| 3 — unregistered destination | PASS: 11 resource-scoping tests, including unnamed host/port and ungranted-resource refusals | Decision-point library, not an actual bank network request |
| 4 — tool parameters | PASS: 26 gateway crate tests, including mismatch without an agent claim, wrong-key refusal and header disagreement; Act 4b executed the Rust stdio gateway and retained two different signed commitments | Library tests plus real first-party gateway invocation; no business transfer completion claim |
| 5 — offline verification | PASS: 77 batches, 3,475 kernel events and four signed health records verified; removing middle record 39 failed with both sequence and predecessor-head findings | Actual separate verifier process under the published observer anchor |

The outer transcript reports `REHEARSED`. Its library/system labels remain intact. The main system run reported ten checks. This conclusion is about that scoped hosted rehearsal, not completion of the enterprise milestone.

## Conditions and coverage

The workflow used a disposable GitHub-hosted `ubuntu-24.04` runner, x86_64 Linux `6.17.0-1022-azure`, root, readable tracefs and `sched_process_exec` tracepoint ID 272. Chrony reported a normal leap state and the explicit `timedatectl` gate returned `NTPSynchronized=yes`. All four signed health records stated a steered clock; the largest signed kernel error bound was 4,011 microseconds. This is clock evidence, not an application-performance measurement.

The signed timeline is:

- Sequence 0: `ContinuityUnverified`, no coverage.
- Sequence 24: `Active`, coverage `1793183521728..1793183549373` milliseconds.
- Sequence 50: `IntegrityUnknown`, coverage null under the foreign tracepoint gate.
- Sequence 77: `Active`, fresh coverage `1793183582140..1793183609615` milliseconds.

The source's control/recovery checker passed: control was Active with coverage and recovery did not backfill the unknown interval. The offline verifier reported three health heads cross-checked against the batch archive, two health records asserting coverage and two asserting none. The internal-removal negative control reported 76 retained batches and correctly rejected the gap at sequence 39.

## Evidence custody and local reproduction

This directory retains exact public transcripts/test outcomes, public observer key, reports and losslessly compressed signed batch/health/receipt streams. It excludes collector/probe/attack raw logs, general build logs, private keys, passphrases, JWTs and databases. The original 28-file allowlisted artifact remains in ignored `.local/rbi-rehearsal-40672603812`. File and decompressed-archive hashes are recorded in `manifest.json`; compression used `gzip -n -c` and changes no signed bytes.

A local invocation of the actual `aip-observe-verify` independently accepted the downloaded full batch and health archives with no findings. The control/recovery checker also passed locally. Exact commands are in `commands.txt`, and the verifier's structured output is in `local-offline-verification.json`.

The observer key is `42182ecf93d51273d99c7b80968237f61d1af353a995baebd06977019af921cc` for `collector.pilot.e2e`, key version 1. It was downloaded from the same workflow artifact: local recomputation confirms reproducibility, not independent institutional trust. Agree the anchor fingerprint with the evaluator through a separate trusted channel.

## Limits that remain

The probe and collector ran in separate processes on one hosted VM. This does not establish genuinely independent two-host administrative custody, an institutional pilot, a rehearsal of the actual presentation machine or a clean Linux package installation. The workload is synthetic; it does not replace a real autonomous banking-agent authorization/observation/verdict integration.

Acts 3 and 4 are library-level. Act 4b's first-party `banking.transfer` fixture and signed `Forwarded` receipt do not prove a bank transaction happened or completed. ContextForge validation has its own separate evidence.

Signatures and internal links establish what the anchored collector recorded, not truthful input from a compromised kernel. A valid archive prefix or suffix can still verify; detecting truncation needs an independently retained boundary checkpoint. No Kubernetes/container-runtime qualification, production HSM integration, institutional overhead measurement, independent security assessment or regulatory approval is established by this run.
