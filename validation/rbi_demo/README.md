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

## The finding this rehearsal produced

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

## Status of the last rehearsal on this host

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
