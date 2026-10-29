# Blockers — precise, with the exact unmet requirement

1. **NTP clock sync (environment).** Collector default demands a synchronized
   clock (CERT-In 20(3)/2022). This host: no chronyd/ntpd, `STA_UNSYNC`, 16 s
   max error, no NTP egress. The unmodified RBI rehearsal therefore cannot pass
   here (re-confirmed post-fix: `run_rbi_postfix_unmodified/`). All live system
   evidence in this directory uses `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0` with
   the 16 s bound signed. Unblock: chrony on a host with NTP reachability.
2. **CONFIG_KPROBES unset (kernel).** Kprobe-dependent claims BLOCKED.
3. **No LLM credentials / local model.** Model-driven agent tasks (M3) blocked.
4. **No host-separated collector custody.** Single host only.
5. **SoftHSM2 not installed.** 15 `aip-hsm` tests fail environmentally; the
   HSM custody path is unexercised here.

6. **`VERIFIED_EXECUTION` in the deployed pipeline (design decision).** The
   `aip-probe` daemon has no channel through which an agent's decision claim
   reaches it (`register_claim` is never called), and the operator authority
   tool signs only `tool_invoke`, which no sensor observes. Closing this needs
   an architecture decision on an untrusted-agent claim channel; not
   improvised here.
7. **CI same-run harness** requires a GitHub-hosted runner, an NTP clock, a
   pinned ContextForge checkout and a local model; its last failure
   (run 40748072732) is UNCONFIRMED as D2 because its artifact is behind this
   session's egress policy.
8. **Model-backed frameworks** (Agent Zero, DeerFlow, OpenHands) need model
   access, Docker images and a separate collector host.

Resolved this cycle (were blocking the honest path): D1 first-batch loss, D2
batch-boundary false `IntegrityUnknown` — see `EXECUTION_JOURNAL.md` cycle 2.
