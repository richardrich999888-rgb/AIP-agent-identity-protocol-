# OpenTelemetry — evaluation

Phase 6 of the real-world validation mandate. This document is about what OTel
could *prove*. For what installs, see `otel/STATUS.md`, which records the
`otelcol` collector binary being fetched and run successfully — a concurrent
result that does not change anything below.

## Availability

The Python OpenTelemetry **SDK** — the part that would instrument a subject —
is not installed in this image and the package index is unreachable:

```
$ python3 -c "import opentelemetry"
ModuleNotFoundError: No module named 'opentelemetry'
```

The **collector** (`otelcol` 0.111.0) does install; see `otel/STATUS.md`. The
distinction matters and is easy to blur: a collector that starts is a
collector, not evidence. Nothing in this experiment sends to it, and if
something did, the analysis below would be unchanged.

Status: **SDK BLOCKED for installation; collector TOOLING_READY and unused.**

## Why that changes nothing about the experiment

This is the finding that matters, and it is independent of whether the SDK
installs.

OpenTelemetry is an **instrumentation library that runs inside the process it
describes**. A span, a GenAI attribute, a trace id, a parent-child link — all of
it is emitted by the subject's own address space, by code the subject loaded,
about what the subject believes it did. A subject that misreports a tool call
misreports the span describing that tool call, identically and consistently.

That places OTel squarely in the same class as row 1 of
`../scenarios/INDEPENDENCE_MATRIX.md`:

> **Subject process self-report** — controlled by subject: fully — max
> provenance: self-report, never corroboration.

It is a *better-structured* self-report than an application log: causal
relationships are explicit, timestamps are consistent, and the schema is
stable. None of those properties makes it independent. Structure is not
provenance.

### Where it would genuinely help

Two places, neither of which is corroboration:

1. **As the left-hand side of a reconciliation.** A span tree is a rich,
   machine-readable statement of what the agent claims it did, and it is a
   better claim format than the ad-hoc event stream this experiment's subject
   emits. That is a claim-quality improvement, not an evidence one.

2. **When the collector is outside the subject's trust boundary and the
   transport is authenticated.** A collector run by a different principal, that
   the subject can send to but not edit, makes the claim *durable and
   non-repudiable* — the subject cannot later deny having said it. It still
   cannot make the claim *true*. Recording a claim faithfully makes it durable,
   not correct — the same rule that applies to rosbag2 in row 8 of the matrix.

### The trap this section exists to name

The mandate's warning applies here more than anywhere else: *never promote
evidence simply because multiple logs say the same thing.* An agent emitting
OTel spans, an application log, and an AIRI event stream produces three
artefacts that agree — and they are one source, because one process authored
all three. The correct label is **CORROBORATION_ONLY**, and calling three
self-reports three observers is the specific error this programme exists to
prevent.

## Conclusion

The OTel SDK is **BLOCKED** here and would be classified **SELF_REPORTED** if
it ran. The collector is installed and unused. No result in
`../../docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md` depends on either, and none
would have been stronger if both had been available — which is the whole point:
**a tool that installs is `TOOLING_READY`, never a validation result.**
