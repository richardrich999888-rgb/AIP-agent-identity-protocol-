# APPLICATION_LOG_SENSOR_DECISION — Gate 5 / Phase H

> **Status: DECIDED.** Application, database and proxy records are not
> admitted as observation. They may enter the system only as a distinct,
> explicitly labelled *supporting* tier that can never produce, upgrade or
> lower a reconciliation result, never count as coverage, and never carry
> attribution above `Claimed`. No adapter is built by this gate; what this
> gate builds is the executable fence (§6) that keeps the decision true.

## 1. The question

The plain-English description of the Sniffer Dog and the PR #3 branch both
speak of "ingesting actual database and proxy records out-of-band" and of
log-tail sensors (`JsonlAccessLog`, `JsonlEffectLog`) that read a tool
server's or an egress proxy's own logs and report tool invocations, egress
destinations and parameter digests "as recorded". The completion mandate's
Gate 5 asks for an explicit decision before any such sensor exists, under
the rule that self-reported logs are supporting evidence only.

## 2. What such a record is, and is not

An application, database or proxy log line is a statement **written by a
host-side process about what it did or saw**. Under the threat model it is:

| Property | Kernel-pushed source (Stages 6.5–7c, Gates 2–4) | Application / DB / proxy record |
|---|---|---|
| Who authors the content | the kernel, from its own state | the writing process, from its own program |
| Who can forge it without root | nobody | the writing process, or anyone with write access to the log |
| Attribution | a kernel-bound pidfd or a start-tick-anchored pid | whatever the writer chose to write (`Claimed` at best) |
| Loss signal | counted by the kernel (`PERF_RECORD_LOST`, `tp_drops`, `FAN_Q_OVERFLOW`) | none the observer can trust — a missing line is indistinguishable from a quiet period |
| Time | the kernel's clock (or the probe's read stamp, stated) | the writer's clock |
| Coverage | recomputable from batches | unknowable — the writer decides what to log |

Every row of the right-hand column is a claim. I16 says logs are not
observation; rule 18 of the mandate says application logs cannot silently
become independent truth; I22 says observed and authorized execution are
separate sources that neither derives from the other. A log written by the
agent's runtime is a self-report by the party under scrutiny. A log written
by a proxy or a database is a self-report by *another* party — a witness,
not a sensor — and a witness's statement is evidence about the witness's
state, not an observation of the agent.

## 3. The one thing such records can offer

Parameters. The kernel path never sees application content (I23): a
`ghost.net.send.v1` verdict names an endpoint and a byte count, a
`ghost.fs.write.v1` verdict names a path. A TLS-terminating proxy that
holds its own signing key, or a database that logs statements, can record
*what was asked* — a request line, a statement digest, a tool name and
argument digest. That is genuinely useful information, and it is exactly
the information whose provenance is weakest.

## 4. Decision

    DECISION:       Application, database and proxy records are NOT a
                    SourceMechanism, NOT a KernelLifecycleKind, NOT an
                    ObservedEffect, and NOT an input to compare_action.
                    They are not observation. If admitted at all, they are
                    admitted as a SUPPORTING tier with these fixed limits:
                      - strength ceiling Correlated (never Attested, never
                        Proven), so the warrant engine can never move past
                        Alert on their account (w02);
                      - attribution ceiling Claimed (the writer's word);
                      - never counted as coverage, never a party to
                        PHANTOM_CLAIM, never able to raise, lower or replace
                        a reconciliation result — a supporting record may
                        annotate a record, and the annotation is signed
                        alongside it, but result, strength and reason are
                        computed without it;
                      - every record signed by its writer under a domain of
                        its own (a proxy's key is a fifth trust root; an
                        agent-runtime log is signed by the party under
                        scrutiny and is SELF_DECLARED, nothing more);
                      - its own RED suite, its own observer protocol bump,
                        and a stream-integrity audit (offset, tail hash,
                        dev/inode rotation) harvested from PR #3
                        `attestation.rs` as design.
    THREAT:         a host process — the agent's runtime, a compromised
                    proxy, or an operator's log shipper — writes lines that
                    a verifier mistakes for independent observation, or
                    withholds lines that a verifier mistakes for coverage.
    ASSUMPTION:     nothing about a writer's honesty; only that a writer's
                    signature, when present, binds the writer to its own
                    words.
    MECHANISM:      a typed fence: the observer's mechanism vocabulary and
                    the reconciler's action derivation admit only
                    kernel-authored inputs, and the warrant engine caps
                    Correlated at Alert.
    IMPLEMENTATION: no adapter (none is admitted by this gate). The fence
                    is pinned by aip-observe/tests/gate5_no_log_sensor.rs
                    and by the existing warrant matrix.
    TEST:           gate5_no_log_sensor.rs g5a–g5d; aip-warrant w02–w04.
    LIMITATION:     parameters and content remain invisible to the kernel
                    path; the supporting tier, if ever built, adds
                    correlation, not proof. A proxy that terminates TLS is
                    itself a party with authority over the agent's traffic
                    and must be modelled as one (its own key, its own
                    domain, its own continuity), not as a sensor.
    DEPENDENCIES:   Skill 8 warrant ceiling (present); a signed record
                    format and a writer key lifecycle (absent).
    STATUS:         DECIDED — supporting tier only; adapter NOT BUILT.

## 5. Why not build the supporting tier now

The mandate orders Gates 6–9 (commitment, proof layer, continuity
semantics, containment) after this decision. A supporting tier adds a fifth
trust root and a new signed format; building it before the commitment layer
exists would commit nothing of it and prove nothing about it. It is deferred
with its preconditions stated (§4 DECISION) and its limits fixed so that no
later work can quietly widen them.

## 6. The fence, executable

`aip-observe/tests/gate5_no_log_sensor.rs`:

| Test | Pins |
|---|---|
| g5a | every `SourceMechanism` is kernel-pushed or a kernel table / procfs read under a pidfd; none is named for a log, a proxy or a database |
| g5b | every `KernelLifecycleKind` and `ObservedEffect` variant is kernel-authored state; a "record from a log" cannot be represented |
| g5c | a `Claimed` attribution on any observation confers no identity (`subject_identity_digest` is `None` without a bound instance) — the writer's word is a claim |
| g5d | the warrant engine holds `Correlated` at `Alert` whatever the severity (cross-reference to `aip-warrant` w02) |

If a supporting tier is ever admitted, these tests are the ones that must
be extended — never weakened — to show where the tier's records live and
that they still cannot reach `compare_action`, coverage, or `Attested`.

## 7. Claims this decision permits and forbids

Permitted: "the Sniffer Dog's positive results rest on kernel-authored
facts signed by an off-host collector; application, database and proxy
records are not among them."

Forbidden: "ingests database and proxy records as evidence"; "cross-checks
the agent's tool calls against the proxy log"; any statement that a log
line established what an agent did.
