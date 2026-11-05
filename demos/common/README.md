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

Not a project CI gate yet: the repository's workflows run on pull requests and
on pushes to `develop`/`main`, and none covers `demos/`.
