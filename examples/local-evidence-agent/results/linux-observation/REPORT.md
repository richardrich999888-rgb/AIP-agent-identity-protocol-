# Genuine observed local Qwen agent — validation result

The requested bounded evidence assistant **executed on Linux, produced fresh signed Sniffer Dog observations, passed offline verification, and is displayed in the local demo**. This closes the observed Q&A demo slice. It does not close the wider project's security, independent custody, customer deployment or other agent-business-task gates.

Execution source: `bce0037d6ca5eb1b85a9f2d242f4b2650dd2e6d9`.
[Final GitHub workflow 41508547378](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/41508547378): capture job `125494055489` and separate offline job `125497343733` both succeeded. The unrelated legacy workload job was deliberately guarded off for this selected workflow profile.

## Actual execution and evidence

The same LangChain/LangGraph EvidenceAgent used by the Mac demo ran as a restricted Linux user. It used the pinned public Hugging Face Qwen2.5-1.5B-Instruct model on CPU and an ephemeral AIP Reader credential. Four actual questions required eight completed model responses and twelve authenticated API reads. No paid model credential, simulated response, pre-recorded answer or fallback inference was used.

The API inputs are the three preserved `3e6c179` historical records. Their original dates and `CannotProve` findings remain intact. The new evidence observes the assistant executing those reads; it does not relabel the old inputs as fresh.

| Check | Actual result |
| --- | --- |
| Task interval, UTC | 2026-11-02 19:21:07.118 to 19:22:08.684 |
| Task exit | 0 |
| Actual questions / model responses / Reader GETs | 4 / 8 / 12 |
| Signed observation batches / health records | 93 / 6 |
| Kernel events in complete retained archive | 3,372 |
| Events bound to the measured agent process | 56 |
| Bound event kinds | 1 ProcessExec, 1 Exec, 20 SocketState, 28 SocketSend, 5 FileEvent, 1 Exit |
| Process binding | Boot ID, PID, process start ticks, executable hash, and PID/mount/network namespaces matched |
| Sensor coverage | All six sensor types Active for the complete task interval |
| Answer-file observation | All four output paths appeared in process-bound signed file observations |
| Independent Linux audit cross-check | One matching execution; no lost audit records, unresolved records or audit restart |
| Capture loss / missing event clock anchors | None reported |
| Actual model serving context | 8,192 tokens; CPU, zero VRAM bytes reported |
| Cleanup | No reported errors |

All configured sensor types were required: scheduler tracepoint, cgroup tracepoint, process connector, fanotify, socket-state tracepoint and socket-send tracepoint. The process was held briefly after answering until its output-file path events were observed. This hold is recorded and is not an ordinary performance claim.

The full signed chain was retained. Seven mutated archive copies were refused under the full signature/chain/checkpoint contract. Prefix/suffix removal requires the separately trusted checkpoint; a surviving signed fragment alone is not sufficient evidence of completeness.

## Offline verification and provenance

A fresh second Ubuntu runner downloaded the originals and ran the existing Rust verifiers through `fresh_verify.py` inside a network namespace with no network access. It had no model, API service or collector signing key. The same original files were then checked independently on this Mac without model/API/network use. **The complete Linux and Mac verification JSON objects are identical.**

The checks include signature/chain integrity, full retained-chain sealing, external checkpoint hashes, all-six full-task coverage, complete process identity, audit agreement, output-path observations, controller output associations, and exact execution source hashes. The public report is uploaded separately. No verifier rule was relaxed.

| Original GitHub artifact | ID | ZIP SHA-256 |
| --- | --- | --- |
| Observations and actual outputs | 13172577432 | `b6cef1a3e7ec0b6fa6e7d26d49086690e624481e8c8782ad0a835fffb1312b41` |
| Separate public controller trust/anchor/checkpoint | 13171583652 | `7b13f7fc3b8f0b7bd1081c6b6b836117f3c14258b44bce2a79ca284d95ac12c9` |
| Network-disabled verification result | 13171114228 | `30b3af4945687e93e2068d5f091a4a0aef3f5ef3b7173da78d35c76fe6649ea8` |

All ZIP bytes match GitHub's independently retrieved artifact digests. Extraction rejected unsafe paths, links, duplicate members and oversized contents, and checked ZIP CRCs. All 27 original public files match the separate controller inventory. Private signing keys, service state, credentials and private logs were not published.

The separate trust artifact has approved workflow provenance, but both it and the collector originated under the same runner administration. This is not independent administrative custody.

Originals, downloaded metadata, answer reviews and both verification reports are in [41508547378](41508547378/). The machine-readable decision is [acceptance.json](acceptance.json).

## Actual-answer review

[All four original answers passed review](41508547378/semantic-review.md). Every answer hash matches both the output manifest and the separate controller inventory. All twelve API response-content hashes reconstruct from the original input records. The model selected `kernel_action`, `kernel_action`, `record_integrity` and `business_outcome` respectively.

Observed and recovered input records retain `CannotProve / ActionEvidenceUnavailable`; the interrupted record retains `CannotProve / WindowNotCovered`. The request to falsely claim loan approval produced neither an approval nor a nonapproval claim. This validates these four bounded extractive questions, not general reasoning or universal prompt-injection resistance.

Collector signatures cover kernel observations. Model-response counts, answer contents, file hashes and their run association are controller application records. No new application-action authorization, gateway receipt, logical-delegation proof or business outcome was fabricated.

## Demo and reproducibility

Open **http://127.0.0.1:18765/**. The separate fresh-capture panel shows the source, actual UTC interval, archive and process-bound counts, all-six coverage, model-response count and output hash. Expand it to inspect provenance. The Q&A controls below still query the three historical API inputs, clearly labelled as such.

The actual browser check displayed the final `bce0037` capture and completed a live question with two local model responses and three API reads. Its answer retained `CannotProve`, missing authorization-window coverage and unknown business outcomes. The Mac adds no new kernel observations.

From the repository root, after the usual local model preparation:

```sh
./examples/local-evidence-agent/run.sh \
  --fresh-evidence examples/local-evidence-agent/results/linux-observation/41508547378/public \
  --fresh-trust examples/local-evidence-agent/results/linux-observation/41508547378/trust/controller-trust.json
```

To verify without starting the demo, model, API or collector, choose a new output file:

```sh
python3.12 examples/local-evidence-agent/fresh_verify.py \
  --package examples/local-evidence-agent/results/linux-observation/41508547378/public \
  --trust examples/local-evidence-agent/results/linux-observation/41508547378/trust/controller-trust.json \
  --tools target/debug --output /tmp/new-local-qa-verification.json
```

The original capture is displayed through offline verification. It is not admitted as a new `/v1/observations` record; the existing 512 KiB decoded-archive limit and RunBundle authorization rules remain unchanged.

## Tests and retained failed attempts

- Final Mac component/API suite: **81 passed, zero failed, zero skipped**. It includes actual API authorization checks and prepared local-model asset reuse.
- Final Linux component/API suite: **80 passed, zero failed, one skip** out of 81. The skipped Mac prepared-asset reuse test requires the Mac assets; actual Linux Qwen inference subsequently ran and passed.
- Genuine Linux four-question workload, seven archive mutations, separate network-disabled verification, independent Mac verification and final demo/browser inspection: **PASS**.
- Complete Rust CI: debug **3,268 passed / 0 failed / 7 ignored**; release **3,270 / 0 / 5**. Each also passed two doctests with two ignored. The discrepancy regression passed both profiles and twenty focused release repeats. See the [exact CI registry and receipts](ci/bce0037-report.md).
- Complete PR checks at execution source `bce0037`: **17 PASS / 2 FAIL / 3 guarded skips**, 22 completed, none pending. The two failures are security scanners, not waived. The 18 component/security subset is **16 PASS / 2 FAIL**.
- Gitleaks reports 217 findings; Trivy reports four. Complete scanner result objects exactly match the retained `75e75bb` baseline, with zero new or missing results at `bce0037`. Cargo audit passes under the existing `RUSTSEC-2026-0097` exception; this is not an unqualified vulnerability-free claim. See [sanitized security comparison](security/bce0037.json).

The first attempt, [41505855222](attempts/41505855222/failure.json), stopped before execution because seven API tests hardcoded the Mac-only `/private/tmp` directory. The portable temporary-directory fix preserved every control.

The second attempt, [41507100812](41507100812/attempt-status.json), completed a genuine workload and passed network-disabled and Mac verification, but the offline report upload failed because its root-owned output was unreadable to the uploader. Its original successful capture and failed publication record are preserved. The final workflow only made that verified public report readable; keys and private state remain excluded.

## What still requires infrastructure or separate acceptance

The hosted runner demonstrably supports this initial integration: privileged sensor setup, tracefs, fanotify, network and mount namespaces, cgroup limits, synchronized clocks, independent Linux audit, restricted CPU inference, signed capture and a separate network-disabled verifier. SSH access or a dedicated host was not needed for this slice.

For independent custody, provide **two separately administered Linux machines**: the agent/probe machine and a collector machine whose signing keys and evidence storage are inaccessible to the workload administrator. Approved enrollment/public-key anchors, clock synchronization, protected retention and independent verification must be established across that boundary.

Clean customer-host installation, persistent service privileges, fanotify startup/restart/recovery/uninstall, resilience and external customer acceptance still need their own validation. Logical delegation and concurrent-agent attribution also remain separate. This Q&A result does not validate Agent Zero's failed business workload or unexecuted DeerFlow/OpenHands business tasks, and does not constitute a swarm, production deployment, regulatory acceptance or YC endorsement.

The PR remains draft while the security and wider acceptance gates remain open.

The evidence-publication commit changes this report, README and retained results only. CI counts above refer to the exact executed implementation source `bce0037`; later publication checks are not silently substituted for that source.
