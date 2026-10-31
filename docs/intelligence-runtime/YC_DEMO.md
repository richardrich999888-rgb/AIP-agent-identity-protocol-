# YC demonstration — offline, real execution

Script: `research/intelligence-runtime/demo/run_demo.sh OUT [--propose]`.
Recorded run: `research/intelligence-runtime/demo/DEMO_OUTPUT.txt` (24 s on
2 vCPU, page cache warm; first-ever run on a cold disk adds ~75 s of model
loading). Every scene calls the real `syntriass` binary, the System One
sidecar and llama.cpp with pinned, hash-verified Qwen2.5 weights. Nothing is
simulated.

| Scene | What the audience sees (from the recorded run) | Status |
|---|---|---|
| 6 Offline (run first) | inside the runtime's namespace, 1.1.1.1 and 8.8.8.8 are unreachable; every later model call runs the same way | complete |
| 1 Private intelligence | Koravi engineer asks the EP-114 minimum; grounded answer "10 times (rated kV plus 1) megohms", sources ep-114 and ep-090; 14.1 s, 1 model call, llama 2.2 GB | complete — note the model quotes the rule instead of computing 76 MΩ |
| 2 Efficient computation | pump vibration report → priority 1 by exact rules, 2 ms, 0 model calls, runtime 6 MB | complete |
| 3 Learning | recorded model draft fails to compile (`minimum` undefined); 7 cited engineer corrections; expert-signed suite 14/14 with 4 counterexamples; signed approval; ACTIVE | complete, **with human correction** — autonomous proposal failed |
| 4 Reuse | new request (not in demos or suite) → PASS with the full arithmetic trace, 0.5 ms, 0 model calls; recorded comparison: B2 9.1 CPU-s per task at 12.5 % accuracy vs capability ≤ 0.01 at 90.6 %; break-even 54 uses | complete |
| 5 Security | other organisation invoking the capability → `NotPermitted`; same organisation at lower clearance → capability invisible, refused; stored capability tampered (REJECT rule weakened) → non-executable, request refused; audit chain verifies | complete |

## How to present it truthfully

- Say "an engineer taught it, and it validated and reused what was taught" —
  not "it learned by itself". The 1.5B model's own drafts all failed.
- Say "offline on a 2-core, 8 GB machine with 0.5–1.5B models" — not GPU,
  not large-model results.
- Show the 3 failures on the unseen set, not only the 37/40.
- The grounded answer in Scene 1 is supported by the source but does not do
  the arithmetic; Scene 4 is where arithmetic is exact.
