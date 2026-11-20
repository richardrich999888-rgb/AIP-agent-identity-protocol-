# Demo videos, 2026-11-20

Silent screen recordings of the SYNTRIASS demo console, captured in a real
browser while each demo ran live (`demos/console/`, driven by Playwright).
Nothing is mocked. Each frame carries the label "RECORDED live run 2026-11-20 ·
4 vCPU, 15 GB RAM, no GPU · AIP f665cab · OVERLAY 3d63f95". Show them as
recordings, never as live.

| File | Length | What happens |
|---|---|---|
| syntriass-investor-cut.mp4 | 3:26 | 2, then 1, then 3, joined |
| syntriass-1-pull-the-plug.mp4 | 2:16 | Offline questions. Qwen answers "7.1 millimetres per second RMS" with citations; the SCADA password is withheld; IBM Granite answers "105 degrees Celsius". 0 bytes out each time; the cloud app fails |
| syntriass-2-lying-agent.mp4 | 0:47 | Live run: the agent's log vs Sniffer Dog vs auditd; one-byte tamper REJECTED; ACCEPTANCE PASS |
| syntriass-3-quantum-xray.mp4 | 0:23 | Live scan: 4 planted weaknesses found, 0 invented; the one-page report |
| syntriass-4-pq-switch.mp4 | 1:00 | Proof of concept, six phases with packet capture; ACCEPTANCE PASS |
| syntriass-5-benchmark.mp4 | 0:19 | The benchmark tab: recorded result files, labelled RECORDED |

No voice. Add a human voice-over with `docs/demos/RECORDING_GUIDE.md`
(section 5 has the script). No synthetic voice.
