# SYNTRIASS demo console

One page, in the SYNTRIASS brand, that runs the real demos live on this
machine. Built for the IIT Madras meeting (2026-11-23).

```sh
sudo SYNTRIASS_BUNDLE=/path/to/bundle demos/console/start.sh      # → http://127.0.0.1:8770/
```

| Tab | What pressing the button does | Typical time (4 vCPU, no GPU) |
|---|---|---|
| Pull the plug | **Ask your own question:** the local runtime answers inside a namespace with no route out (Qwen2.5-1.5B or IBM Granite 3.3-2B); the cloud app fails. **Run the full check:** the 5 fixed questions with acceptance | ~6–10 s per question; ~30 s for the check |
| Catch the lying agent | Runs `demos/lying-agent/run.sh` with the honest control; shows the three witnesses | ~25 s |
| Quantum X-ray | Builds and scans the sample server; planted vs found; embeds the one-page report | ~2 s |
| Post-quantum switch | Two containers, six phases, packet capture per phase (proof of concept) | ~35 s |
| Taught-capability benchmark | **RECORDED**: the original result files beside the fresh rerun of 2026-11-19 | instant |

**Honesty rules the page follows:**
- Each LIVE result is read from the files that run wrote, and the page names the result file and the commit.
- The benchmark tab is the only recorded content, and it is labelled RECORDED.
- Each tab says what is not claimed.
- Answers and outputs are inserted as text, never as HTML.

**Local only:**
- binds `127.0.0.1` and refuses other Host headers;
- 16 KiB request cap;
- a Content-Security-Policy that allows only its own origin;
- a fixed asset list;
- one demo at a time.

`test_console.py` checks these and runs without models.

**Brand assets** (`assets/`) are cut from `website/assets/syntriass-logo.jpeg`
(branch `codex/val-ladder-sync`). The owner chose that logo; it was not
redrawn. The mark and wordmark are transparent PNG crops of it.

**Needs:** root; Docker and auditd (started by `start.sh` if installed);
built binaries (see each demo's README); the model bundle
(`demos/models/README.md`). `python3 demos/launch.py check` says what is
missing.

**Before the meeting:**
- Run every tab once.
- Ask the questions you plan to ask.
- Keep the laptop on mains power, so CPU timings are not throttled.
