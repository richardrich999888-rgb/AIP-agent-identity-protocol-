# SPIFFE/SPIRE cross-check — S1–S4 executed

**Status: executed end to end. SPIRE and AIP independently measure the same
workload and agree; when the identity registry is re-pointed at different code,
the running system is caught diverging from the approved record.**

```
S3   AGREES    fd33ac17…  SPIRE and AIP measured the same executable
S4a  AGREES    bc80d34c…  SPIRE stays self-consistent after the change
S4b  DIVERGES  DigestMismatch — running code ≠ the approved record
```

Reproduce: `validation/external/spiffe/joint_run.sh`. Sealed at
`results/sealed-joint/`.

This is step one of the second corroboration axis named in subsection 10a of the
RBI technical brief. The bpftrace/auditd work corroborates AIP's **observation**
(did the executions AIP reports really happen?). This corroborates AIP's
**identity binding** (is the process AIP names really running the code AIP
says?) against the CNCF-graduated workload-identity standard.

## What S1 establishes

SPIRE v1.15.3 (server + agent, built from source) issues an SVID to a workload
whose registration entry is selected on `unix:sha256:<digest>`. SPIRE only
issues that SVID if its `unix` workload attestor read `/proc/<pid>/exe` and
computed that digest itself.

**So the SVID's existence is SPIRE's own assertion about the workload's code** —
and that digest is exactly the quantity AIP measures independently from the
kernel. It is the join for S2.

```
workload   -> spiffe://aip.local/workload/demo        (issued)
imposter   -> refused: "no identity issued"            (one byte changed)
```

The **negative control is not optional**. The entry carries two selectors,
`unix:uid:0` and `unix:sha256:<digest>`. If SPIRE were matching on uid alone,
every root process would receive this identity and the digest would be
decoration — and the whole S2 comparison would be built on nothing. So the run
takes a byte-for-byte copy of the same program, changes one byte, runs it as the
same uid, and requires it to be **refused**. If it is ever issued an SVID the
script fails loudly and writes `NEGATIVE_CONTROL_FAILED.json`.

## Reproduce

```
validation/external/spiffe/run.sh
```

Requires root (the agent reads `/proc/<pid>/exe` of workloads) and a Go
toolchain. SPIRE is pinned to v1.15.3 and built via the Go module proxy with
checksum verification on; `workload/go.sum` pins go-spiffe v2.8.2. Sealed output
of the recorded run is in `results/sealed/`.

## Configuration that matters

`discover_workload_path = true` on the `unix` workload attestor. Without it the
attestor emits only uid/gid selectors, there is nothing about the workload's
**code** in SPIRE's assertion, and there is nothing for AIP to be compared
against. With it, SPIRE reads `/proc/<pid>/exe` and offers `unix:sha256`.

## A Unix gotcha that cost real time, recorded so it does not recur

A Unix domain socket path is limited to **108 bytes** (`sun_path`). This
repository's results directory produces paths of ~112 bytes. When exceeded,
SPIRE's UDS listener fails, the endpoints errgroup cancels the TCP listener with
it, and **no error is logged** — the server simply starts and stops its APIs in
the same second and then sits there. Sockets and working data therefore live
under a short `/run/aip-spiffe-$$` directory; only evidence lands in `results/`.

## What this does NOT establish

**Nothing about which system resists a hostile host.** SPIRE's `unix` attestor
reads `/proc/<pid>/exe` — *the same source AIP measures from* — so for this
attestor the two share that attack surface. AIP is not "immune" to anything
SPIRE is exposed to here, and no claim in this tree depends on that idea.

In particular, **no claim here rests on the September 2026 Unit 42 technique**
("The Machine With Many Faces"). That work requires **root on the node**, targets
the *Kubernetes* attestor's cgroup parsing rather than the unix attestor, is
**not a CVE and carries no GHSA**, and Unit 42 state it is "not a crypto or
protocol break" and matches a trust assumption SPIFFE has always documented.
Presenting it as a SPIRE break would be a cheap shot, and it would invite the
same question back at AIP, whose own brief already concedes that a host with
root can lie to its own probe. Both systems document the same limit.

## S4: what is and is not demonstrated

**S4 fabricates nothing.** Both SVIDs were genuinely issued by SPIRE, and both
measurements are genuinely AIP kernel observations. The only thing that differs
between S4a and S4b is *which registry record the comparison is made against* —
and both are real `spire-server entry show` output captured at different times.
That models an **unauthorised change to a workload identity registration**,
which is a real threat, not a synthetic one.

S4a exists so the result is falsifiable: against SPIRE's *current* registry the
system is self-consistent and the tool says `AGREES`. A tool that reported
divergence in both directions would be worthless.

## Two findings the live runs produced — both in our code, not SPIRE's

**1. The pid-reuse guard was anchored to the wrong instant.** The first joint
run reported a perfectly healthy workload as a reused pid: its process started
~12 s *after* the SVID's `notBefore`. Cause: **SPIRE's agent pre-mints SVIDs for
registered entries before any workload asks**, so `notBefore` records minting,
not attestation. The moment SPIRE attests *this caller* is the fetch. The guard
now compares against that, and `s14`/`s15` lock both directions — a control that
cries wolf on every normal deployment is a control that gets switched off.

**2. AIP does not bind every exec, and that is correct behaviour.** A run failed
because the workload's exec was recorded with `bound: null` — the probe saw the
exec but could not complete a pidfd-anchored measurement of that instance, with
`dropped_events: 0` throughout, so this is measurement racing rather than loss.
The comparison then returned `NotComparable`, **not** a false agreement. The
harness now requires a *bound* measurement and re-runs the workload otherwise,
reporting how many attempts it took; each attempt is an independent genuine
execution, so this selects a comparable run rather than massaging a result.

## Next

- Bind AEGIS enforcement to a verified AIP identity (the CBOM's own named gap).
- SPIRE node attestation here is `join_token`, the weakest option, chosen for a
  single-host lab. Nothing in this tree makes a claim about node attestation.
