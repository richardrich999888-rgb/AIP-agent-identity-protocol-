//! The data inventory the Digital Personal Data Protection Act needs
//! (R20 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`, matrix row F6).
//!
//! # Why this is code and not a document
//!
//! A Data Protection Officer signs off on a list of what the system
//! collects. The risk with such a list is not that it is wrong when written
//! — it is that a field is added six months later and the list is not.
//! Whoever adds the field is not thinking about the DPO, and the DPO is not
//! reading the diff.
//!
//! So the inventory here is checked against the structure it describes. The
//! test derives the field set from a fully-populated [`ObservationBatch`] by
//! serialising it and walking the result, and refuses any field the
//! inventory does not name. **A new field fails the build until someone
//! writes down what it is and why it may be collected.** That is the only
//! mechanism that survives the six months.
//!
//! # What this inventory is about
//!
//! The observation batch: everything the probe sends off the observed host.
//! It is the complete set of what leaves the machine, so it is the complete
//! set a DPO must review. Authority tokens and decisions are the
//! institution's own records about its own agents and are inventoried with
//! the rest of its processing; the observation path is the part that is new,
//! and the part that runs on a host where other people's data lives.

use serde::{Deserialize, Serialize};

/// Whether a field can carry personal data, and on whose account.
///
/// The distinction that matters is not "is this personal data" — a field is
/// not personal data in the abstract — but "can this field, as this system
/// populates it, come to contain something about a natural person".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonalDataRisk {
    /// Cannot carry personal data by construction: a counter, a version, a
    /// kernel identifier, a hash of a binary.
    None,
    /// Identifies a *machine or process*, not a person. Personal only by
    /// linkage, and only where an institution assigns hosts to individuals.
    IndirectViaHost,
    /// Can carry personal data depending on deployment: an agent identifier
    /// an institution chose to derive from a person, a path under a home
    /// directory.
    PossibleByConfiguration,
    /// Carries personal data whenever it is populated.
    Direct,
}

impl PersonalDataRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::IndirectViaHost => "INDIRECT-VIA-HOST",
            Self::PossibleByConfiguration => "POSSIBLE-BY-CONFIGURATION",
            Self::Direct => "DIRECT",
        }
    }
}

/// One field of the observation batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRecord {
    /// Dotted path as the field appears in the serialised batch. Leaf paths
    /// only; a container is described by its leaves.
    pub path: &'static str,
    /// What the field holds, in words a DPO can act on.
    pub what: &'static str,
    pub risk: PersonalDataRisk,
    /// Why the system needs it. A field with no answer here should not be
    /// collected, and writing the answer is where that gets noticed.
    pub purpose: &'static str,
}

/// The inventory.
///
/// Ordered by path so the emitted artefact is stable and a diff is a change
/// in the system rather than a change in the run.
pub fn inventory() -> Vec<FieldRecord> {
    let mut v = vec![
        // ── Batch envelope ──
        FieldRecord {
            path: "version",
            what: "Observation protocol version.",
            risk: PersonalDataRisk::None,
            purpose: "A verifier refuses a version it does not implement rather than guessing field meanings.",
        },
        FieldRecord {
            path: "probe_id",
            what: "Operator-chosen name of the probe that produced the batch.",
            risk: PersonalDataRisk::PossibleByConfiguration,
            purpose: "Binds observations to a declared sensor. An institution that names probes after people makes this personal; naming them after hosts does not.",
        },
        FieldRecord {
            path: "batch_id",
            what: "Random 16-byte batch identifier.",
            risk: PersonalDataRisk::None,
            purpose: "Idempotency and de-duplication at the collector.",
        },
        FieldRecord {
            path: "probe_run_id",
            what: "Random identifier of one probe process lifetime.",
            risk: PersonalDataRisk::None,
            purpose: "A restart mid-window is visible as a coverage gap rather than invisible.",
        },
        FieldRecord {
            path: "probe_seq_first",
            what: "First probe sequence number in the batch.",
            risk: PersonalDataRisk::None,
            purpose: "Continuity: a gap in the sequence is a gap in coverage.",
        },
        FieldRecord {
            path: "probe_seq_last",
            what: "Last probe sequence number in the batch.",
            risk: PersonalDataRisk::None,
            purpose: "Closes the interval the batch accounts for, so the next batch's first sequence either continues it or exposes a gap.",
        },
        FieldRecord {
            path: "dropped_events",
            what: "Count of events the kernel ring buffer dropped.",
            risk: PersonalDataRisk::None,
            purpose: "Loss is stated rather than silent; the reconciler degrades on it.",
        },
        FieldRecord {
            path: "active_mechanisms",
            what: "Which sensor mechanisms were running.",
            risk: PersonalDataRisk::None,
            purpose: "A verdict about non-occurrence needs to know what was watching.",
        },
        FieldRecord {
            path: "mechanism_integrity",
            what: "Per-mechanism integrity findings (e.g. a foreign eBPF gate).",
            risk: PersonalDataRisk::None,
            purpose: "A blinded sensor says so; without this the observer would report silence as absence.",
        },
        FieldRecord {
            path: "claimed_from_ms",
            what: "Start of the window the probe claims to cover.",
            risk: PersonalDataRisk::None,
            purpose: "Bounds what the batch is evidence about.",
        },
        FieldRecord {
            path: "claimed_to_ms",
            what: "End of the claimed window.",
            risk: PersonalDataRisk::None,
            purpose: "Closes the interval, so a verdict can state that evidence covers the authorized window rather than part of it.",
        },
        FieldRecord {
            path: "clock_anchor",
            what: "Boot-clock to wall-clock anchor, when the probe could take one.",
            risk: PersonalDataRisk::None,
            purpose: "Places kernel timestamps on the wall clock an authorization is expressed in.",
        },
        // ── Per-observation ──
        FieldRecord {
            path: "observations.version",
            what: "Observation record version.",
            risk: PersonalDataRisk::None,
            purpose: "A record is refused rather than reinterpreted when its structure version is not one this verifier implements.",
        },
        FieldRecord {
            path: "observations.probe_id",
            what: "Probe that took this reading.",
            risk: PersonalDataRisk::PossibleByConfiguration,
            purpose: "Attributes the reading to a declared sensor, so a batch assembled from two probes is visible as such.",
        },
        FieldRecord {
            path: "observations.observed.process.pid",
            what: "Process identifier.",
            risk: PersonalDataRisk::IndirectViaHost,
            purpose: "Part of the process instance. Never identity on its own: PIDs are reused.",
        },
        FieldRecord {
            path: "observations.observed.process.pid_start_time_ticks",
            what: "Process start time in clock ticks since boot.",
            risk: PersonalDataRisk::IndirectViaHost,
            purpose: "Distinguishes two processes that held one PID within a boot.",
        },
        FieldRecord {
            path: "observations.observed.process.boot_id",
            what: "Kernel boot identifier.",
            risk: PersonalDataRisk::IndirectViaHost,
            purpose: "Distinguishes boots, so a process instance is unique in time.",
        },
        FieldRecord {
            path: "observations.observed.exe_content_sha256",
            what: "SHA-256 of the executable's contents.",
            risk: PersonalDataRisk::None,
            purpose: "Which program ran. A hash of a binary, never of user data.",
        },
        FieldRecord {
            path: "observations.observed.exe_path",
            what: "Filesystem path of the executable.",
            risk: PersonalDataRisk::PossibleByConfiguration,
            purpose: "Context for an operator. A path under a home directory carries a username; the path is excluded from identity for that reason, and an institution that objects can run agents from a system path.",
        },
        FieldRecord {
            path: "observations.attribution",
            what: "The agent identifier claimed to the observer, and by whom.",
            risk: PersonalDataRisk::PossibleByConfiguration,
            purpose: "Lets a verdict be about an agent. Personal only where an institution derives agent identifiers from people.",
        },
        FieldRecord {
            path: "observations.effect",
            what: "What was observed: a socket row, a process presence, a file write path.",
            risk: PersonalDataRisk::IndirectViaHost,
            purpose: "The observation itself. Addresses and ports, never payload; a file path where the fanotify sensor runs.",
        },
        FieldRecord {
            path: "observations.mechanism",
            what: "Which sensor produced this reading.",
            risk: PersonalDataRisk::None,
            purpose: "Bounds the evidence strength a verdict may claim.",
        },
        FieldRecord {
            path: "observations.claimed_decision_id",
            what: "The decision the orchestrator claimed this act was under.",
            risk: PersonalDataRisk::None,
            purpose: "The join key to an authorization. A claim, not a fact.",
        },
        FieldRecord {
            path: "observations.host_wall_clock_ms",
            what: "Host wall clock at the reading.",
            risk: PersonalDataRisk::None,
            purpose: "Places the reading in the window an authorization is expressed in.",
        },
        FieldRecord {
            path: "observations.probe_monotonic_ns",
            what: "Probe monotonic clock at the reading.",
            risk: PersonalDataRisk::None,
            purpose: "Ordering that survives wall-clock adjustment.",
        },
        // ── Per-kernel-event ──
        FieldRecord {
            path: "kernel_events.version",
            what: "Kernel event record version.",
            risk: PersonalDataRisk::None,
            purpose: "A record is refused rather than reinterpreted when its structure version is not one this verifier implements.",
        },
        FieldRecord {
            path: "kernel_events.probe_id",
            what: "Probe that received the event.",
            risk: PersonalDataRisk::PossibleByConfiguration,
            purpose: "Attributes the event to a declared sensor, so a batch assembled from two probes is visible as such.",
        },
        FieldRecord {
            path: "kernel_events.mechanism",
            what: "Which tracepoint or connector delivered it.",
            risk: PersonalDataRisk::None,
            purpose: "Kernel-pushed evidence is distinguishable from polled evidence.",
        },
        FieldRecord {
            path: "kernel_events.kind",
            what: "The event: fork, exec, exit, socket state change, send, file write.",
            risk: PersonalDataRisk::IndirectViaHost,
            purpose: "The event itself. Carries endpoints, byte counts and paths; never payload.",
        },
        FieldRecord {
            path: "kernel_events.cpu",
            what: "CPU the event was recorded on.",
            risk: PersonalDataRisk::None,
            purpose: "Per-CPU ring buffer ordering.",
        },
        FieldRecord {
            path: "kernel_events.kernel_timestamp_ns",
            what: "Kernel timestamp of the event.",
            risk: PersonalDataRisk::None,
            purpose: "Ordering and placement, from the kernel rather than the agent.",
        },
        FieldRecord {
            path: "kernel_events.probe_seq",
            what: "Probe sequence number of the event.",
            risk: PersonalDataRisk::None,
            purpose: "Continuity within the stream.",
        },
        FieldRecord {
            path: "kernel_events.bound",
            what: "The process instance the probe bound the event to, when it could.",
            risk: PersonalDataRisk::IndirectViaHost,
            purpose: "An unbound event names a PID, and a PID is not an instance.",
        },
        FieldRecord {
            path: "kernel_events.attribution",
            what: "The agent identifier claimed for the event.",
            risk: PersonalDataRisk::PossibleByConfiguration,
            purpose: "Lets a verdict be about an agent. The observer attests that the claim was made, never that it is true.",
        },
        FieldRecord {
            path: "kernel_events.claimed_decision_id",
            what: "The decision claimed for the event.",
            risk: PersonalDataRisk::None,
            purpose: "The join key to an authorization. A claim by the orchestrator, not a fact the kernel reported.",
        },
    ];
    v.sort_by_key(|r| r.path);
    v
}

/// CSV for a reviewer with a spreadsheet.
pub fn to_csv() -> String {
    let mut out = String::from("FIELD_PATH,WHAT,PERSONAL_DATA_RISK,PURPOSE\n");
    for r in inventory() {
        out.push_str(&format!(
            "{},{},{},{}\n",
            csv_cell(r.path),
            csv_cell(r.what),
            r.risk.as_str(),
            csv_cell(r.purpose)
        ));
    }
    out
}

pub fn to_json() -> String {
    serde_json::to_string_pretty(&inventory()).expect("inventory is serialisable")
}

fn csv_cell(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Every field path present in a serialised value, as dotted leaf paths.
///
/// Arrays contribute their element paths without an index, because the
/// inventory describes a *kind* of row rather than one row. An enum
/// serialised as an object contributes its variant's fields; the inventory
/// therefore names the enum itself as a leaf where the variants are the
/// content rather than the structure, which is why `effect` and `kind` are
/// single rows.
pub fn leaf_paths(value: &serde_json::Value, prefix: &str, stop_at: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                if stop_at.contains(&path.as_str()) {
                    out.push(path);
                } else {
                    out.extend(leaf_paths(v, &path, stop_at));
                }
            }
        }
        serde_json::Value::Array(items) => {
            // One element is enough: the inventory describes the row shape.
            if let Some(first) = items.first() {
                out.extend(leaf_paths(first, prefix, stop_at));
            } else if !prefix.is_empty() {
                out.push(prefix.to_string());
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.push(prefix.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Paths the inventory describes as a whole rather than field by field,
/// because their content is a closed vocabulary rather than a structure.
///
/// Each is still inventoried — as one row that says what the vocabulary can
/// carry. Splitting them per variant would make the artefact longer without
/// telling a DPO anything they could act on.
pub const AGGREGATED_PATHS: &[&str] = &[
    "active_mechanisms",
    "mechanism_integrity",
    "clock_anchor",
    "observations.attribution",
    "observations.effect",
    "observations.mechanism",
    "kernel_events.attribution",
    "kernel_events.kind",
    "kernel_events.mechanism",
    "kernel_events.bound",
];
