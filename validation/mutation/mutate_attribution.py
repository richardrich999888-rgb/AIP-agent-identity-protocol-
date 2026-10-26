#!/usr/bin/env python3
"""Mutation matrix for structural attribution (ADR-019, M2).

Four layers, each mutated against its own package's tests:

- `aip-reconcile` placement rule: which events belong to a decision;
- `aip-placement`: the supervisor's only judgement, and the kernel calls;
- `aip-observe`: the in-event cgroup id, its copy into signed evidence,
  the cgroup tracepoint parsers, and the protocol-13 version gates.

Most mutations try to attribute what must not be: a placement made by
someone else, an event after a migration in, a chain with a gap, an exec in
another cgroup. Several need the running kernel; run with
`AIP_REQUIRE_LIVE=1` and tracefs mounted so a mutation of kernel-facing code
cannot "survive" because its live test skipped. The forensic machinery is
`mutate_core.run_matrix`.
"""
import os
import sys
import importlib.util
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mutate_core", _HERE / "mutate_core.py")
_core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

REPO = _core.REPO
STANDALONE = REPO / "aip-standalone"


def m(id_, pkg, file, invariant, old, new):
    return {"id": id_, "pkg": pkg, "file": STANDALONE / pkg / "src" / file,
            "invariant": invariant, "old": old, "new": new}


def pa(id_, invariant, old, new):
    return m(id_, "aip-reconcile", "placement.rs", invariant, old, new)


def pl(id_, file, invariant, old, new):
    return m(id_, "aip-placement", file, invariant, old, new)


def ob(id_, file, invariant, old, new):
    return m(id_, "aip-observe", file, invariant, old, new)


MUTATIONS = [
    # ── Placement rule ─────────────────────────────────────────────────
    pa("PA-01", "a chain is contiguous by sequence",
       "if next.sequence != prev.sequence + 1 || next.prev_head != prev.head() {",
       "if next.prev_head != prev.head() {"),
    pa("PA-02", "a chain is joined by head, not by counter",
       "if next.sequence != prev.sequence + 1 || next.prev_head != prev.head() {",
       "if next.sequence != prev.sequence + 1 {"),
    pa("PA-03", "a probe restart breaks coverage",
       "        if b.batch.probe_run_id != run {", "        if false {"),
    pa("PA-04", "the placement source must be live in every batch",
       "if !live || b.batch.dropped_events != Some(0) {", "if b.batch.dropped_events != Some(0) {"),
    pa("PA-05", "counted zero loss in every batch",
       "if !live || b.batch.dropped_events != Some(0) {", "if !live {"),
    pa("PA-06", "only the verifier's hierarchy holds placements",
       "if *hierarchy != policy.hierarchy || !names_decision(path, decision_id) {",
       "if !names_decision(path, decision_id) {"),
    pa("PA-07", "a creation counts only if it names this decision",
       "if *hierarchy != policy.hierarchy || !names_decision(path, decision_id) {",
       "if *hierarchy != policy.hierarchy {"),
    pa("PA-08", "the creator must run the supervisor binary",
       "Some(p) if p.exe_content_sha256 != policy.supervisor_exe_sha256 => {",
       "Some(p) if p.exe_content_sha256 == [1u8; 32] => {"),
    pa("PA-09", "an unanchored creator is not a creator",
       "None => creator_problem = Some(PlacementGap::CreatorNotAnchored),",
       "None => creator_problem = None,"),
    pa("PA-10", "two creations for one decision are ambiguous",
       "n => return Err(PlacementGap::Ambiguous { creations: n }),", "_ => {}"),
    pa("PA-11", "a descendant is under the placement's path, not a lookalike",
       "path.starts_with(&descendant_prefix)",
       "path.starts_with(descendant_prefix.trim_end_matches('/'))"),
    pa("PA-12", "a migration into the placement ends attribution",
       "first_migration_in_ns.get_or_insert(e.kernel_timestamp_ns);", "let _ = e;"),
    pa("PA-13", "an event outside the placement is not attributed",
       "    if !placement.members.contains(&cgroup_id) {", "    if false {"),
    pa("PA-14", "nothing precedes the placement's creation",
       "    if e.kernel_timestamp_ns < placement.created_at.kernel_timestamp_ns {", "    if false {"),
    pa("PA-15", "an event at the migration instant is not attributed",
       ".is_some_and(|t| e.kernel_timestamp_ns >= t)", ".is_some_and(|t| e.kernel_timestamp_ns > t)"),
    pa("PA-16", "an unsampled event is not attributed",
       "    let CgroupSample::Sampled { cgroup_id } = e.cgroup else {\n        return EventAttribution::NotSampled;\n    };",
       "    let cgroup_id = e.cgroup.id().unwrap_or(0);"),
    pa("PA-17", "a name is matched in full",
       "        .is_some_and(|d| &d == decision_id)", "        .is_some_and(|d| d[0] == decision_id[0])"),

    # ── Supervisor ─────────────────────────────────────────────────────
    pl("PL-01", "authorize.rs", "an unverified decision is not placed",
       "    verified.map_err(PlacementError::NotAuthorized)?;", "    let _ = verified;"),
    pl("PL-02", "authorize.rs", "a decision outside its window is not placed",
       "        TemporalStatus::Valid => Ok(ee.decision_id),\n        other => Err(PlacementError::NotValidAt(other)),",
       "        _ => Ok(ee.decision_id),"),
    pl("PL-03", "authorize.rs", "a decision point under the agent's key is refused",
       "        Some(agent) => verify_expected_execution_for_agent(ee, &authority.anchors, agent),",
       "        Some(_) => verify_expected_execution(ee, &authority.anchors),"),
    pl("PL-04", "spawn.rs", "work starts inside its placement",
       "flags: CLONE_PIDFD | CLONE_INTO_CGROUP,", "flags: CLONE_PIDFD,"),
    pl("PL-05", "cgroup.rs", "a populated placement is reported, never forced",
       "            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {\n                Err(PlacementError::StillPopulated(self.path.clone()))\n            }\n",
       ""),
    pl("PL-06", "mount.rs", "the v2 hierarchy is found by filesystem type",
       '        if *fstype != "cgroup2" {', '        if *fstype != "cgroup" {'),

    # ── Observation ────────────────────────────────────────────────────
    ob("OB-01", "perf.rs", "the cgroup id follows the raw block",
       "        let at = 36 + raw_size;", "        let at = 32 + raw_size;"),
    ob("OB-02", "probe.rs", "the probe copies the kernel's sample into signed evidence",
       "            cgroup: ev.cgroup,\n", "            cgroup: crate::observed::CgroupSample::NotSampled,\n"),
    ob("OB-03", "sched.rs", "the sched tracer asks the kernel for the cgroup id",
       "match PerfTracepoints::open_with(&names, SampleLayout::WITH_CGROUP) {",
       "match PerfTracepoints::open_with(&names, SampleLayout::BASE) {"),
    ob("OB-04", "cgroupev.rs", "a negative tracepoint field is refused",
       "    u32::try_from(v)\n", "    Ok::<u32, std::num::TryFromIntError>(v as u32)\n"),
    ob("OB-05", "attest.rs", "a v12 record cannot carry v13 content",
       "    if !b.batch.content_fits_version() {", "    if false {"),
    ob("OB-06", "observed.rs", "a v12 record encodes no cgroup field",
       "        if self.version >= CGROUP_PROTOCOL_VERSION {\n            self.cgroup.encode(&mut buf);",
       "        if true {\n            self.cgroup.encode(&mut buf);"),
    ob("OB-07", "observed.rs", "one batch, one version",
       ".all(|e| e.version == v && e.content_fits_version())", ".all(|e| e.content_fits_version())"),
    ob("OB-08", "observed.rs", "the cgroup mechanism is a v13 mechanism",
       "            SourceMechanism::ExecPermission | SourceMechanism::CgroupTracepoint => {",
       "            SourceMechanism::ExecPermission => {"),
    ob("OB-09", "observed.rs", "every cgroup kind is a v13 kind",
       "            | KernelLifecycleKind::CgroupRemoved { .. }\n            | KernelLifecycleKind::CgroupAttach { .. } => CGROUP_PROTOCOL_VERSION,",
       "            | KernelLifecycleKind::CgroupAttach { .. } => CGROUP_PROTOCOL_VERSION,"),
    ob("OB-10", "observed.rs", "sealed v12 identity digests do not move",
       "pub const OBSERVED_PROCESS_IDENTITY_VERSION: u16 = 12;",
       "pub const OBSERVED_PROCESS_IDENTITY_VERSION: u16 = 13;"),
    ob("OB-11", "observed.rs", "only sealed versions verify",
       "pub const VERIFIABLE_PROTOCOL_VERSIONS: [u16; 2] = [12, 13];",
       "pub const VERIFIABLE_PROTOCOL_VERSIONS: [u16; 2] = [13, 13];"),
]

if __name__ == "__main__":
    if not os.environ.get("AIP_REQUIRE_LIVE"):
        sys.exit("refusing to run: set AIP_REQUIRE_LIVE=1 so a skipped live test cannot read as a survivor's kill or a kill's survival")
    sys.exit(_core.run_matrix(
        MUTATIONS,
        REPO / "validation/mutation/ATTRIBUTION_MUTATION_RESULTS.json",
        sys.argv[1:] or None,
        ["aip-reconcile", "aip-placement", "aip-observe"],
    ))
