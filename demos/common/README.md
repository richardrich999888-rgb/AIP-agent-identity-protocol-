# `demos/common` — shared demo harness

Standard-library Python. Every demo uses it so that "offline", "measured on"
and "live vs recorded" mean the same thing everywhere.

| Need | Call | Guarantee |
|---|---|---|
| Prove there is no network | `harness.py offline-check` | Exit 0 only if this network namespace has **no non-loopback route and no non-loopback interface** (read from `/proc/self/net`, which is namespace-accurate). Does not probe a public address. |
| Run a demo step offline | `harness.py run-offline -- CMD ...` | Fresh user+net namespace, loopback up, refuses (exit 3) unless the check above passes, then `exec`s `CMD`. Local pages on `127.0.0.1` still work. |
| Say what it ran on | `harness.py hardware` | Read live from `/proc`; memory rounded **down** to whole GiB. This sandbox reports `4 vCPU, 15 GB RAM, no GPU`. |
| Label a step | `harness.py label live TEXT` / `label recorded --source FILE TEXT` | Only `live` or `recorded`. A recorded step must name an existing file, and the banner shows it. |
| Keep the result | `harness.write_result(out_dir, demo, steps, measurements, started_utc)` | `<demo>-<UTC>.json` with UTC start/finish, commit SHA + dirty flag, hardware, offline status, and a label on every step; an unlabelled step is refused. |

Tests: `python3 -m unittest demos/common/test_harness.py` (12 tests). They
show both directions of the offline check on a real host: the host itself is
refused, the namespaced run is offline, an outbound connect fails inside it,
and loopback works.

## CI and the namespace tests

`.github/workflows/demos.yml` runs pyflakes and these tests on pull requests
into `feature/syntriass-runtime-v02`. It changes no other workflow.

The namespace test (`test_run_offline_runs_with_no_route_and_outbound_fails`)
needs `unshare --user --net`. Where that is refused — hosted Ubuntu runners
commonly restrict unprivileged user namespaces — it is reported as
`skipped 'SKIPPED, not passed: <reason>'`, and the workflow repeats that line
as a warning. **A skip is never counted as a pass. For that test the local run
below is the evidence:**

| Date | Host | Result |
|---|---|---|
| 2026-11-05 | sandbox, 4 vCPU, 15 GB RAM, no GPU, kernel 6.18.44, root | 12/12 passed, 0 skipped (namespace test executed) |

The skip path itself was checked locally by putting a refusing `unshare`
first on `PATH`: the test reported `skipped 'SKIPPED, not passed: unshare
--user --net refused here: …'`.
