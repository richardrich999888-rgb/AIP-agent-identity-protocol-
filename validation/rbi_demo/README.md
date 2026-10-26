# The RBI evaluation session — rehearsal

Section 14 of the technical brief commits us **in writing** to demonstrating
five things to people whose job is to break them:

1. the honest path
2. an interfered-with observer
3. a refused unregistered destination
4. a mis-parameterised tool call against a signed receipt
5. offline verification performed by your side with keys you hold

Every other open item in the submission is a document. **This one fails in the
room.** `run.sh` is the rehearsal, and its transcript is the evidence that the
rehearsal happened.

```
validation/rbi_demo/run.sh
```

## Preliminary checks and local regression tests

The clock precondition requires a successful
`timedatectl show --property=NTPSynchronized --value` query returning `yes`.
`no` is unsynchronised; missing `timedatectl`, a failed query, or any other
value is unknown. Both states fail the precondition. A running chronyd, ntpd,
or systemd-timesyncd process is **not** sufficient evidence. Successful query
values and query errors are retained in `clock.log`. Hosts without
an accessible systemd time-status query cannot pass this check; no daemon-only
fallback is used.

The initial daemon/verifier build is checked by exit status, with all output in
`build.log`. A nonzero status stops the script before the acts and cannot print
that the binaries were built, even if stale binaries are present. Diagnostic
wording, colour, and empty output do not decide whether the build succeeded.

Run the deterministic regression suite without privilege or new dependencies:

```sh
python3 -B validation/rbi_demo/test_run.py
bash -n validation/rbi_demo/run.sh
```

The suite runs a copy of the actual script in a temporary tree with an
allowlisted PATH and simulated commands. Its 17 test methods cover 32 scenarios:
synchronised, unsynchronised and unknown clock evidence; missing/failed
queries; failed builds with several diagnostic formats; successful builds
with misleading log text; log redirection failure; and the full-system
pass/fail/explicit-skip result gates. Additional cases cover the child pilot's
build failure, stale gateway binaries, gateway exit/timeout after writing
receipts, malformed/missing/equal receipts, invalid or degraded control evidence,
quoted output paths, and recovery coverage spanning a blinded interval. The daemon fixture reports running even
when synchronisation is absent, to catch the former daemon-only fallback.

These are **control-flow tests only**. They do not run Cargo, the real gateway,
daemons, kernel sensors, the interference experiment, or offline verification.
Passing them is not a rehearsal. On the authorised Linux demonstration host,
run the complete script with system acts enabled and retain the transcript and
logs. Actual clock discipline, sensor access, `Active` with attested coverage,
interference/recovery, and independent offline verification still need that
run. A preliminary clock PASS alone does not establish those properties.
`AIP_DEMO_SKIP_SYSTEM=1` remains explicitly **skipped**, exits nonzero, and
cannot produce `REHEARSED`.

## Full-system RBI gate and hosted rehearsal

The generic pilot experiment permits a degraded control window. That is not
enough for the RBI wrapper's claim of an honest path with `Active` and attested
coverage. After the pilot passes (including offline signature verification and
the tampered-archive negative control), `check_control.py` also requires those
two properties in the saved control health record. It also checks signed batch
intervals against the health archive: recovery must not extend coverage across
a recorded IntegrityUnknown interval. Missing or malformed evidence fails the
RBI session. This JSON check supplements, and does not
replace, the pilot's cryptographic verification.

The RBI path forces `AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1`; the generic pilot
also now defaults to that production clock policy. No error budget is widened.
The child build and gateway build/execute/receipt checks all fail by status;
stale executables or receipts left before a failed process cannot earn a PASS.

`.github/workflows/rbi-rehearsal.yml` runs the shell regressions without
privilege and then the real rehearsal on a disposable GitHub-hosted Ubuntu VM.
It establishes real NTP synchronization, builds the actual binaries, and runs
the kernel observation/interference and offline verification paths. The job
fails if any requirement is unmet. It is independent of the workspace's cgroup
and coverage workflows. Its artifact allowlist retains diagnostics and signed
evidence even on failure, but excludes private keys and passphrases.

A hosted run is a development rehearsal on that VM, not a rehearsal of the
presentation computer and not a two-host regulated-entity pilot. The same
complete script must pass on the authorised machine used for the session.
For evaluator-side offline verification, provide `attested.archive.jsonl`,
`health.archive.jsonl`, and the public `observer.pub`; agree the public-key
fingerprint independently before using it as a trust anchor. The evaluator
runs their trusted build of `aip-observe-verify` with `--observer-id
collector.pilot.e2e --key-version 1 --pubkey-file observer.pub --batches
attested.archive.jsonl --health health.archive.jsonl`. A public key supplied
only inside the same bundle is not independently established trust.

## What each act actually is — and why that is labelled

| Act | Promise | Level |
|-----|---------|-------|
| 1, 2, 5 | honest path, interfered observer, offline verification | **full system** — two real daemons in separate processes, real kernel, real foreign-eBPF attack, offline verifier given two files and a public key |
| 3 | refused unregistered destination | **library** — the decision point is a library; exercised through its own suite against genuinely signed documents |
| 4 | mis-parameterised tool call | **library**, plus **4b live** — the real gateway binary signs a receipt per call with its own key |

Acts 3 and 4 are library-level because the decision point and the tool boundary
*are* libraries — the institution integrates them (blockers **B9** and **B10**).
Presenting them as a system demonstration would misrepresent what was shown,
which is the one thing this programme cannot afford to do.

## The 20 September rehearsal finding (historical)

**The demo host must have a synchronised clock, or Act 1 does not show what you
promised.**

On the first rehearsal the control run — no attack, clean workload — signed:

```
state:               IntegrityUnknown
continuity:          Verified          (no continuity break)
attested_coverage:   null              (coverage withheld)
collector log:       clock NOT synchronized (STA_UNSYNC), max_error 16000 ms
```

No foreign tracepoint gate was reported. The observer withheld coverage because
it could not vouch for the window. That is **correct, designed, fail-closed
behaviour** — the collector stamps and signs every attested batch, so its clock
discipline is the accuracy of all of it, and CERT-In Direction 20(3)/2022
requires NTP-synchronised clocks besides.

But it is **not the honest path the Department was promised**. Discovering it
live costs the session: you spend it explaining clocks instead of showing
accountability.

`run.sh` now checks this as a **precondition** and says plainly what will happen
if it is unmet. Fix with `deploy/pilot/chrony-cert-in.conf` and re-run until
Act 1 reports `Active`.

> Note on attribution: this environment is a sandboxed VM with no time daemon
> and restricted kernel introspection. The unsynchronised clock is established
> from the collector's own log. Whether the state was driven by the clock alone
> or also by a sensor whose gate check is *unverifiable* in this sandbox was not
> isolated — both are fail-closed by design, and both are fixed by rehearsing on
> the real demo host. **Do not present a transcript from a host where Act 1 did
> not report `Active`.**

## Status recorded on 20 September (historical)

- **Acts 3, 4, 4b — pass.** 11 resource-scoping assertions including outright
  refusal of an address the institution never named; 11 tool-boundary
  assertions including divergence with the agent's claim absent from evidence;
  and the gateway signing a distinct receipt for each of two calls, live.
- **Acts 1, 2, 5 — not demonstrated here.** Blocked by the precondition above,
  not by a fault in the system. A previously sealed `pilot_e2e` run
  (`validation/pilot_e2e/results/sealed/`) shows `Active` under an earlier
  protocol revision, before the attested clock was added in protocol 12.

**The session is not rehearsed until this script reports all five acts green on
the machine the demonstration will actually run on.**
