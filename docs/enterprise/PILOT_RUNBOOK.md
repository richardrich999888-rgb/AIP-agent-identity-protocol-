# Evaluation operator runbook

The confirmed discussion in the engineering brief is 29 October 2026,
15:00 IST. This engineering branch does not establish that a bank pilot has
been approved. Keep the RBI demonstration and enterprise integration tracks
separate.

## RBI track

Use the unchanged `validation/rbi_demo/run.sh` on the authorized disposable
Linux demonstration host. Require actual NTP synchronization, tracefs,
appropriate kernel capabilities and all five acts. The wrapper forces synced
collector clock policy and fails explicit skips. Preserve each run in a fresh
directory, including failed transcripts; never rewrite historical evidence.

```sh
python3 -B validation/rbi_demo/test_run.py
sudo env "PATH=$PATH" bash validation/rbi_demo/run.sh /var/tmp/rbi-evaluation-NEW-RUN
```

The 17 deterministic tests are control-flow checks, not a rehearsal. Acts 3
and 4 have library-level components; Act 4b exercises the original live stdio
gateway. A ContextForge integration test is additional evidence, not a
replacement for the kernel/interference/offline acts. The historical hosted
rehearsal for `0991fb1` succeeded at GitHub run `40409155305`; it does not
prove the actual presentation computer, a separate collector host or this
branch's new integrations.

Export stable archives and the independently agreed observer public anchor.
Have the evaluator run its own trusted `aip-observe-verify` build offline.
Record verification failure, `IntegrityUnknown`, clock error and coverage gaps
exactly. No observation coverage means no verified execution assertion.

## Enterprise track

Follow `BANK_INTEGRATION_GUIDE.md` and the runtime operations runbook.
Use a low-criticality synthetic read-only workload first. Prove Linux install,
sensor availability, confidential enrolled-probe transport, collector archive
durability/restart, archive admission, scoped SDK/MCP retrieval and offline
verification with public anchors. Exercise wrong credentials/tenant/key,
tamper/replay, observation silence and storage failures before acceptance.

The real ContextForge harness creates an isolated gateway, real MCP upstream,
test credentials and fixture authority; see `MCP_GATEWAY_INTEGRATION.md`.
It must not be pointed at production banking tools. Optional local LangGraph
and Ollama exercise genuine model-directed read calls but do not establish a
kernel-observed authorization reconciliation verdict.

## Stop and recover

On missing/failed sensors or integrity/clock loss, mark the affected coverage
unavailable, preserve signed health and logs, and notify the approved operator.
Do not kill workloads or change banking routes. On gateway signing/storage
failure, preserve pending journal entries as unresolved; do not issue a
successful receipt or retry a business operation merely to fill the gap.

Before a collector/service restart, retain consistent state/archive/database
backups and anchors. Never erase checkpoints to make a restart pass. Verify
restored chains and repeat negative controls on a separate approved host.
For a failed JSONL artifact append, recover the file from verified backups;
the service refuses further artifact writes rather than acknowledging
unpersisted records. Preserve legal holds and institutional retention policy.
