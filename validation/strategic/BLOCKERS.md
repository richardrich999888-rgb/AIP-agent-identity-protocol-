# Blockers — precise, with the exact unmet requirement

1. **NTP clock sync (environment).** Collector default demands a synchronized
   clock (CERT-In 20(3)/2022). This host: no chronyd/ntpd/ntpdate, kernel
   `STA_UNSYNC`, 16 s max error, no NTP egress through the HTTPS proxy. Unmet.
   Workaround used for M1: `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0`, with the 16 s
   bound signed into the evidence. Production unblock: chrony per
   `deploy/pilot/chrony-cert-in.conf` on a host with NTP reachability.
2. **CONFIG_KPROBES unset (kernel).** Kprobe eBPF observation impossible on
   `6.18.44-fc-v180`. The Phase 1 sensors (sched/sockstate/socksend/connector)
   do not need it, so M1 is unaffected; any kprobe-dependent claim is BLOCKED.
3. **No LLM credentials / local model.** A genuinely model-driven agent task
   cannot run. M1's LangGraph subject needs none by design; M3's model-backed
   framework tasks would.
4. **No host-separated collector custody.** Single sandbox host only; collector
   is process-separated, not administered on an independent host.
