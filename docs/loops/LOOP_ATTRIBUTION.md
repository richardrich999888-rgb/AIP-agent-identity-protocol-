# Loop: structural attribution → trace verification → authority suspension

Run with `/loop follow docs/loops/LOOP_ATTRIBUTION.md` (no interval; self-paced).

> Numbering note: the structural-attribution design record is **ADR-019**.
> ADR-018 is already *Spend Authority* (2026-10-25).

---

You are the engineer finishing one outcome in this repository, working in a loop.
Each iteration does exactly one milestone step, proves it, records it, and stops
cleanly. Never skip a gate. Never claim more than the evidence shows.

## The outcome (done means all of these are true and committed)

1. **Attribution:** on the 105-`execve` busy-shell workload from XI-H2, and on a
   second, new workload of short-lived children under load, **≥ 95% of execs are
   bound to the authorising decision**, measured by a reproducible script whose
   output is sealed in `validation/`. Unbound execs are reported as such, never
   guessed.
2. **No new bypass:** a process that moves itself out of its decision's cgroup
   produces a signed `IDENTITY_DIVERGENCE`, and a test proves it.
3. **Authority suspension:** on an `Attested` negative verdict, the decision
   point stops issuing new authorisations to that agent, the gateway refuses
   calls without a matching authorisation, running work completes, and release
   is an explicit, signed operator action. Process freeze or kill stays gated on
   `Proven`. Tests prove all four properties.
4. **Verify the trace:** OpenTelemetry GenAI spans (pinned convention version)
   carrying `decision_id` in W3C trace context are joined to reconciliation
   verdicts. Each verdict is a **separate signed record** keyed by
   `(trace_id, span_id)`; the span attribute is only a pointer. Only tool and
   effect spans can be `VERIFIED_EXECUTION`; `invoke_agent` and chat spans are
   `CANNOT_PROVE` by construction, and a test asserts that.
5. **Overhead measured:** CPU and latency overhead of the sensor, cgroup setup
   and any exec-permission hold, published as a number with its method.
6. The workspace is green: `cargo fmt --all -- --check`, `cargo clippy
   --workspace --all-targets --all-features -- -D warnings`, and `cargo test
   --workspace --no-fail-fast` all pass (SoftHSM2 installed, not skipped).
   Mutation matrices for every new crate or module kill ≥ 95%, and every survivor
   is either closed with a named test or documented as a harness defect.

## Milestones, in order. Do not start one until the previous gate passes.

- **M0 — Land in-flight work.** Wait until any running mutation harness has
  finished and every file is confirmed byte-identical to its restore point
  (`git status` clean apart from intended changes). Close SP-06 with a test that
  hits the multiplication overflow; fix the AS-14 harness mutation and re-run.
  Re-run the AIBOM matrix so the committed results reproduce on current source.
  Commit and push. **Gate:** matrices reproduce from a clean checkout.
- **M1 — Design record ADR-019 "Structural attribution".** Invoke the skills
  `ghost-architecture-orchestrator`, `execution-binding-engineer` and
  `aip-protocol-change-guard` first and follow them. The ADR must decide:
  - cgroup v2 as a hard requirement; one cgroup per authorised decision,
    created by the decision point (systemd delegation or direct), named or
    tagged with the signed `decision_id`;
  - attribution carried in the event via `PERF_SAMPLE_CGROUP` (Linux ≥ 5.7)
    on the existing tracepoints, with no eBPF program;
  - exec-content measurement for short-lived processes via fanotify
    `FAN_OPEN_EXEC_PERM` (or IMA as the alternative), including its latency
    cost and its failure mode if the supervisor dies (fail closed vs open,
    stated explicitly);
  - cgroup migration detection via `cgroup:cgroup_attach_task`, and the verdict
    an unexpected migration produces;
  - nested containers, cgroup reuse after a decision expires, and clock and
    boot-id handling;
  - what remains `CANNOT_PROVE` after the change.
  **Gate:** the ADR lists every threat it closes and every one it does not;
  commit it before any implementation.
- **M2 — Implement cgroup-per-decision and in-event attribution.** Tests first:
  a short-lived child that exits within 1 ms is still bound; PID reuse never
  transfers identity; a decoy process with the same binary is not bound.
  **Gate:** new tests pass, existing 3,000+ tests still pass.
- **M3 — Implement exec measurement and migration detection.** Adversarial
  tests (use the `ghost-adversarial-tester` skill): cgroup escape, supervisor
  killed mid-run, permission-event queue overflow, exec of a binary replaced
  between open and exec. **Gate:** each attack lands in the documented class.
- **M4 — Measure attribution.** Re-run the XI-H2 workload and the new load
  workload at least 10 times each. Seal raw output, the script, kernel version
  and host description. **Gate:** ≥ 95% bound on both, or stop the loop and
  write `docs/audit/ATTRIBUTION_SHORTFALL.md` explaining the measured number,
  the cause and the options. Do not tune the workload to pass.
- **M5 — Authority suspension.** Use the `ghost-reconciliation-engineer` and
  `syntriass-ghost-containment` skills. Implement in the decision point and
  gateway, not in the observer. **Gate:** the four properties in outcome 3 are
  each proven by a named test, plus a test that suspicion alone never freezes or
  kills a process.
- **M6 — Verify the trace.** Pin the GenAI semantic-convention version in code
  and docs. Build the signed verdict record, the `(trace_id, span_id)` join and
  an OTLP ingest path. **Gate:** an end-to-end test with a real LangGraph agent
  emitting OTel spans shows tool spans `VERIFIED_EXECUTION`, an injected
  unauthorised tool call `UNATTRIBUTED_EFFECT`, and chat spans `CANNOT_PROVE`.
- **M7 — Overhead.** Un-ignore and extend `aip-observe/tests/throughput.rs` as
  an explicit benchmark run in `--release`. **Gate:** published numbers with
  method, hardware and kernel, in `docs/audit/OVERHEAD.md`.
- **M8 — Close out.** Update `STATUS.md`, `docs/security/ADVERSARIAL_RESULTS.md`
  and the OWASP Agentic Top 10 coverage (ASI01–ASI10) honestly, with each row
  citing a test or saying "not covered". Final full workspace run and mutation
  matrices. Commit, push, and stop the loop.

## Rules for every iteration

1. Start by reading `STATUS.md`, the latest ADRs, and `git log -20` on the
   working branch, and state which milestone and step you are on.
2. Work on the current feature branch. Never push to `main`, never force-push,
   never rewrite published history.
3. Never commit while a mutation harness or any script is rewriting source.
   Confirm restored files before committing.
4. Tests before code for every behaviour. A test that cannot fail is not a test:
   show it failing first.
5. Fail closed. Anything unobserved, unbound or ambiguous is `CANNOT_PROVE`,
   never a match and never an accusation.
6. No overclaims, in code comments, docs or commit messages: no "formal
   verification", no "kernel-enforced containment", no "Proven" for observed
   behaviour, no "production-ready", no competitor comparisons.
7. Do not edit `docs/architecture/AIRI_LIMITATIONS.md` silently; if a
   limitation changes, say so in the commit message and the ADR.
8. Changing any signed or hashed field, canonical encoding or wire format
   follows `aip-protocol-change-guard`, with a version bump and migration note.
9. If an environment capability is missing (CAP_NET_ADMIN, tracefs, cgroup v2,
   fanotify permission events), state it, mark the property NOT established in
   this environment, and do not fake it with fixtures.
10. If a gate fails twice on the same cause, stop the loop and write a short
    blocker note with the evidence instead of iterating blindly.

## Report at the end of every iteration (keep it to this shape)

```
Milestone / step:
Done this iteration:
Evidence (commands run, exact results, commit hashes):
Gate status: PASS | FAIL | NOT YET
Numbers that changed (tests, mutations, attribution %, overhead):
Claims now allowed / still forbidden:
Next step:
Blockers:
```

Stop the loop only when M8's gate passes, or when rule 10 or M4's shortfall
clause applies. When you stop, give a final summary: the attribution number,
the overhead number, what is now true that was not, and what remains
`CANNOT_PROVE`.
