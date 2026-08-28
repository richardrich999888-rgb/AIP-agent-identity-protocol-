//! The deployable sentinel: everything this crate proves, wired into one
//! process an operator can actually run.
//!
//! The library half of this crate is deliberately pure — detectors read
//! data, the patrol is a function of its inputs, and every mechanism is
//! testable without a filesystem or a clock. But a watchdog nobody can
//! *run* detects nothing, and until now the wiring — tail the logs,
//! attest the streams, read the ledger, patrol, persist, repeat — existed
//! only inside the test suite. This module is that wiring, and the
//! `sentinel` binary is a thin argument-parser around it.
//!
//! # What one cycle does
//!
//! 1. Poll the access-log and effect-log tailers for new observations.
//! 2. Checkpoint each active sensor and seal the checkpoint onto the
//!    sentinel's own chain ([`Patrol::attest_sensor`]).
//! 3. Every `deep_verify_every` cycles, re-derive each stream's hash from
//!    disk against every checkpoint sealed so far — the pass that actually
//!    catches a retroactive edit.
//! 4. Read the evidence ledger and run the full patrol.
//! 5. Persist: snapshot [`PatrolState`] to the state file, then append the
//!    cycle's sealed anchors to the archive file.
//!
//! # Why the state file is written before the archive
//!
//! The two durable records are deliberately written in an order that makes
//! a crash between them read as [`ContinuityBreak::ArchiveTruncated`] — the
//! one variant whose documentation admits a benign explanation — rather
//! than as `RolledBack`, which accuses someone of restoring an old state.
//! A crash window should produce the mildest true alarm it can, not the
//! most damning one.
//!
//! # Startup is where the honesty lives
//!
//! On start the runtime resumes from the state file when one exists and
//! then audits its own continuity against the archive
//! ([`Patrol::audit_continuity`]). A missing state file with a non-empty
//! archive is the restart-to-forget signature and is returned to the
//! caller *and* reported on every subsequent patrol — the operator decides
//! whether to keep running, but they decide it knowing. A state file that
//! exists but does not parse is a hard error, never a silent fresh start:
//! silently discarding state is precisely the amnesia the state module
//! exists to prevent.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use serde_json::Value;

use crate::conformance::EffectPolicy;
use crate::observation::Sensor;
use crate::patrol::{Patrol, PatrolReport};
use crate::response::ResponsePolicy;
use crate::sensors::{read_evidence_ledger, JsonlAccessLog, JsonlEffectLog};
use crate::state::{ContinuityBreak, PatrolState};

/// The access-log sensor's registered name.
pub const ACCESS_SENSOR: &str = "tool-server-log";
/// The effect-log sensor's registered name.
pub const EFFECT_SENSOR: &str = "effect-log";

/// Everything a deployment states about how its sentinel runs.
pub struct RuntimeConfig {
    /// The sentinel's own DID — the identity its chain is sealed under.
    pub sentinel_did: String,
    /// The evidence ledger the governed gateway writes (JSONL of
    /// `{"kind": "packet"|"anchor", "record": …}` lines).
    pub ledger_path: PathBuf,
    /// A tool server's access log to tail, if one is deployed.
    pub access_log: Option<PathBuf>,
    /// An egress/spawn effect log to tail, if one is deployed.
    pub effect_log: Option<PathBuf>,
    /// Where [`PatrolState`] persists across restarts.
    pub state_path: PathBuf,
    /// Where the sentinel's own sealed anchors accumulate (JSONL, append).
    pub archive_path: PathBuf,
    /// Run the O(file) deep verification every N cycles; 0 disables it.
    pub deep_verify_every: u64,
    /// The response policy — advisory unless the operator says otherwise.
    pub policy: ResponsePolicy,
    /// The declared egress/spawn posture, or `None` when undeclared.
    pub effect_policy: Option<EffectPolicy>,
    /// Whether the operator vouches for the tailed sensors. Unvouched
    /// sensors still alert; they cannot get an agent quarantined.
    pub trust_sensors: bool,
    /// Tools the access-log sensor claims complete coverage of. Empty
    /// means the sensor observes but claims no coverage, so absence of an
    /// observation proves nothing — the honest default.
    pub covered_tools: Vec<String>,
}

/// What one cycle concluded, for the operator loop to print.
pub struct CycleReport {
    /// The patrol's findings and actions.
    pub report: PatrolReport,
    /// Observations consumed from the tailers this cycle.
    pub observations: usize,
    /// True when a tailed log rotated this cycle.
    pub rotated: bool,
    /// Checkpoints the deep-verify pass found no longer recomputing.
    pub tampered: usize,
}

/// The running sentinel.
pub struct SentinelRuntime {
    patrol: Patrol,
    access: Option<JsonlAccessLog>,
    effects: Option<JsonlEffectLog>,
    config: RuntimeConfig,
    cycles: u64,
}

impl SentinelRuntime {
    /// Builds the runtime: resume from durable state when it exists, then
    /// audit continuity against the archive. The returned break, if any,
    /// is also latched into the patrol so every report carries it.
    pub fn start(config: RuntimeConfig) -> Result<(Self, Option<ContinuityBreak>), String> {
        let mut patrol = match fs::read_to_string(&config.state_path) {
            Ok(text) => {
                let value: Value = serde_json::from_str(&text).map_err(|e| {
                    format!(
                        "state file {} is not valid JSON: {e} — refusing a silent fresh start",
                        config.state_path.display()
                    )
                })?;
                let state = PatrolState::from_json(&value)
                    .map_err(|why| format!("state file {}: {why}", config.state_path.display()))?;
                Patrol::resume(state, config.sentinel_did.clone())?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Patrol::new(config.sentinel_did.clone())
            }
            Err(e) => {
                return Err(format!(
                    "cannot read state file {}: {e}",
                    config.state_path.display()
                ))
            }
        };

        patrol = patrol.with_policy(config.policy.clone());
        if let Some(effect_policy) = config.effect_policy.clone() {
            patrol = patrol.with_effect_policy(effect_policy);
        }
        if config.access_log.is_some() {
            let mut sensor = Sensor::new(ACCESS_SENSOR);
            if config.trust_sensors {
                sensor = sensor.trusted();
            }
            let covered: Vec<&str> = config.covered_tools.iter().map(String::as_str).collect();
            if !covered.is_empty() {
                sensor = sensor.covering(&covered);
            }
            patrol = patrol.with_sensor(sensor);
        }
        if config.effect_log.is_some() {
            let mut sensor = Sensor::new(EFFECT_SENSOR);
            if config.trust_sensors {
                sensor = sensor.trusted();
            }
            patrol = patrol.with_sensor(sensor);
        }

        let archived = read_archive(&config.archive_path)?;
        let continuity_break = patrol.audit_continuity(&archived).cloned();

        let access = config
            .access_log
            .as_ref()
            .map(|path| JsonlAccessLog::new(path, ACCESS_SENSOR));
        let effects = config
            .effect_log
            .as_ref()
            .map(|path| JsonlEffectLog::new(path, EFFECT_SENSOR));

        Ok((
            Self {
                patrol,
                access,
                effects,
                config,
                cycles: 0,
            },
            continuity_break,
        ))
    }

    /// Runs one full cycle at `now_utc` (ISO-8601). Deterministic given the
    /// files on disk and the clock — which is what makes it testable.
    pub fn run_cycle(&mut self, now_utc: &str) -> Result<CycleReport, String> {
        self.cycles += 1;
        let mut observations = Vec::new();
        let mut rotated = false;
        let mut sealed_this_cycle: Vec<Value> = Vec::new();

        if let Some(tail) = self.access.as_mut() {
            let polled = tail.poll()?;
            rotated |= polled.rotated;
            observations.extend(polled.observations);
            sealed_this_cycle.push(self.patrol.attest_sensor(tail.checkpoint(now_utc), now_utc));
        }
        if let Some(tail) = self.effects.as_mut() {
            let polled = tail.poll()?;
            rotated |= polled.rotated;
            observations.extend(polled.observations);
            sealed_this_cycle.push(self.patrol.attest_sensor(tail.checkpoint(now_utc), now_utc));
        }

        // The deep pass: O(file) instead of O(delta), so it runs on a
        // cadence rather than every cycle. Cycle 1 always runs it — a
        // freshly resumed sentinel's first duty is to check that what it
        // attested before going down still recomputes.
        let mut tampered = Vec::new();
        let every = self.config.deep_verify_every;
        if every > 0 && (self.cycles == 1 || self.cycles % every == 0) {
            let checkpoints: Vec<_> = self
                .patrol
                .snapshot()
                .sensor_checkpoints
                .values()
                .flatten()
                .cloned()
                .collect();
            if let Some(tail) = self.access.as_ref() {
                tampered.extend(tail.deep_verify(&checkpoints)?);
            }
            if let Some(tail) = self.effects.as_ref() {
                tampered.extend(tail.deep_verify(&checkpoints)?);
            }
        }

        let (packets, anchors) = read_evidence_ledger(&self.config.ledger_path)?;
        let report = self.patrol.patrol_with_integrity(
            &packets,
            &anchors,
            &observations,
            &tampered,
            now_utc,
        );
        sealed_this_cycle.extend(report.sealed_anchors.iter().cloned());

        // Persist: state first, then archive — see the module doc for why
        // this order makes a crash window read as the mildest true alarm.
        write_state_atomically(&self.config.state_path, &self.patrol.snapshot())?;
        append_archive(&self.config.archive_path, &sealed_this_cycle)?;

        Ok(CycleReport {
            observations: report.observations_examined,
            rotated,
            tampered: tampered.len(),
            report,
        })
    }

    /// The sentinel's DID, for the operator loop's banner.
    pub fn sentinel_did(&self) -> &str {
        self.patrol.sentinel_did()
    }
}

/// Reads the sentinel's own anchor archive (JSONL, one anchor per line).
fn read_archive(path: &PathBuf) -> Result<Vec<Value>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read archive {}: {e}", path.display())),
    };
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// Appends sealed anchors to the archive, one JSON line each.
fn append_archive(path: &PathBuf, anchors: &[Value]) -> Result<(), String> {
    if anchors.is_empty() {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open archive {}: {e}", path.display()))?;
    for anchor in anchors {
        writeln!(file, "{anchor}").map_err(|e| format!("cannot append to archive: {e}"))?;
    }
    file.flush()
        .map_err(|e| format!("cannot flush archive: {e}"))
}

/// Writes the state file via a temp-and-rename so a crash mid-write can
/// never leave a half-written file that then hard-errors the next start.
fn write_state_atomically(path: &PathBuf, state: &PatrolState) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(&state.to_json()).unwrap(),
    )
    .map_err(|e| format!("cannot write state {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot commit state {}: {e}", path.display()))
}

/// The current wall clock as ISO-8601 UTC with milliseconds — the one place
/// this crate touches a real clock. Everything below the binary takes the
/// timestamp as an argument, which is what keeps patrols reproducible.
pub fn now_iso8601() -> String {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let millis_total = since_epoch.as_millis() as i64;
    let (days, rem_millis) = (
        millis_total.div_euclid(86_400_000),
        millis_total.rem_euclid(86_400_000),
    );
    // Civil-from-days (Howard Hinnant's algorithm), valid across the whole
    // range this system will ever see.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let (hour, rem) = (rem_millis / 3_600_000, rem_millis % 3_600_000);
    let (minute, rem) = (rem / 60_000, rem % 60_000);
    let (second, millis) = (rem / 1000, rem % 1000);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::FindingKind;
    use ot_accountability_core::chain::verify_anchor_chain;

    const DID: &str = "did:syntriass:sentinel:RUNTIME-1";
    const T1: &str = "2026-08-28T12:00:00.000Z";
    const T2: &str = "2026-08-28T12:01:00.000Z";
    const T3: &str = "2026-08-28T12:02:00.000Z";

    fn config(dir: &std::path::Path) -> RuntimeConfig {
        RuntimeConfig {
            sentinel_did: DID.into(),
            ledger_path: dir.join("ledger.jsonl"),
            access_log: Some(dir.join("access.jsonl")),
            effect_log: None,
            state_path: dir.join("state.json"),
            archive_path: dir.join("archive.jsonl"),
            deep_verify_every: 1,
            policy: ResponsePolicy::autonomous(),
            effect_policy: None,
            trust_sensors: true,
            covered_tools: vec!["send_command".into()],
        }
    }

    fn access_line(command: &str) -> String {
        format!(
            r#"{{"id":"req-1","timestampUtc":"2026-08-28T11:59:50.000Z","tool":"send_command","arguments":{{"command":"{command}"}},"agentDid":"did:syntriass:agent:AGT-1"}}"#
        )
    }

    #[test]
    fn a_first_run_catches_an_escape_and_leaves_durable_records() {
        let dir = tempfile::tempdir().unwrap();
        // A tool ran that no ledger accounts for — the escape signature.
        std::fs::write(
            dir.path().join("access.jsonl"),
            access_line("DEORBIT") + "\n",
        )
        .unwrap();

        let (mut runtime, break_) = SentinelRuntime::start(config(dir.path())).unwrap();
        assert!(break_.is_none(), "a first deployment is not a break");
        let cycle = runtime.run_cycle(T1).unwrap();

        assert_eq!(cycle.observations, 1);
        assert!(
            cycle
                .report
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::UnattributedEffect),
            "the ungoverned call was not caught"
        );
        assert!(dir.path().join("state.json").is_file(), "no durable state");
        assert!(dir.path().join("archive.jsonl").is_file(), "no archive");
    }

    #[test]
    fn a_restart_resumes_the_same_chain_and_passes_its_own_audit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("access.jsonl"),
            access_line("DEORBIT") + "\n",
        )
        .unwrap();

        let (mut first, _) = SentinelRuntime::start(config(dir.path())).unwrap();
        first.run_cycle(T1).unwrap();
        drop(first);

        // Process restart: same files, new runtime.
        let (mut second, break_) = SentinelRuntime::start(config(dir.path())).unwrap();
        assert!(
            break_.is_none(),
            "an honest restart accused itself: {break_:?}"
        );
        second.run_cycle(T2).unwrap();

        // The archive spans both processes and verifies as one chain.
        let archive = read_archive(&dir.path().join("archive.jsonl")).unwrap();
        assert!(
            archive.len() >= 2,
            "archive did not accumulate across restart"
        );
        assert!(
            verify_anchor_chain(&archive).valid,
            "the sentinel's chain broke across the restart"
        );
    }

    #[test]
    fn deleting_the_state_file_is_caught_as_amnesia_on_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("access.jsonl"),
            access_line("DEORBIT") + "\n",
        )
        .unwrap();

        let (mut first, _) = SentinelRuntime::start(config(dir.path())).unwrap();
        first.run_cycle(T1).unwrap();
        drop(first);
        std::fs::remove_file(dir.path().join("state.json")).unwrap();

        let (mut amnesiac, break_) = SentinelRuntime::start(config(dir.path())).unwrap();
        assert_eq!(
            break_.expect("the wiped state must be caught").as_str(),
            "AMNESIA"
        );
        // And it is reported on the patrol itself, not just returned once.
        let cycle = amnesiac.run_cycle(T2).unwrap();
        assert!(cycle
            .report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::SentinelContinuityBreak));
    }

    #[test]
    fn an_edit_made_while_the_sentinel_was_down_is_caught_after_resume() {
        let dir = tempfile::tempdir().unwrap();
        let original = access_line("DEORBIT");
        let edited = access_line("SAFE_OK");
        assert_eq!(original.len(), edited.len(), "same length on purpose");
        std::fs::write(dir.path().join("access.jsonl"), original + "\n").unwrap();

        let (mut first, _) = SentinelRuntime::start(config(dir.path())).unwrap();
        first.run_cycle(T1).unwrap();
        drop(first);

        // While nothing is watching, the attested line is rewritten.
        std::fs::write(dir.path().join("access.jsonl"), edited + "\n").unwrap();

        let (mut resumed, _) = SentinelRuntime::start(config(dir.path())).unwrap();
        let cycle = resumed.run_cycle(T2).unwrap();
        assert!(cycle.tampered >= 1, "the offline edit went undetected");
        assert!(cycle
            .report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::SensorTampered));
    }

    #[test]
    fn a_corrupt_state_file_is_a_hard_error_not_a_silent_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("state.json"), "{ not json").unwrap();
        let error = match SentinelRuntime::start(config(dir.path())) {
            Err(error) => error,
            Ok(_) => panic!("corrupt state must not start"),
        };
        assert!(error.contains("refusing a silent fresh start"), "{error}");
    }

    #[test]
    fn deep_verify_cadence_still_runs_on_the_first_cycle_after_resume() {
        // deep_verify_every=5: cycle 1 must still verify, or a sentinel
        // restarted repeatedly before its fifth cycle never checks at all.
        let dir = tempfile::tempdir().unwrap();
        let original = access_line("DEORBIT");
        let edited = access_line("SAFE_OK");
        std::fs::write(dir.path().join("access.jsonl"), original + "\n").unwrap();

        let mut cfg = config(dir.path());
        cfg.deep_verify_every = 5;
        let (mut first, _) = SentinelRuntime::start(cfg).unwrap();
        first.run_cycle(T1).unwrap();
        drop(first);

        std::fs::write(dir.path().join("access.jsonl"), edited + "\n").unwrap();

        let mut cfg = config(dir.path());
        cfg.deep_verify_every = 5;
        let (mut resumed, _) = SentinelRuntime::start(cfg).unwrap();
        let cycle = resumed.run_cycle(T3).unwrap();
        assert!(cycle.tampered >= 1, "first-cycle deep verify did not run");
    }

    #[test]
    fn the_clock_formats_a_parseable_iso8601_instant() {
        let now = now_iso8601();
        assert!(
            crate::time::parse_iso8601_millis(&now).is_some(),
            "the runtime's own clock does not parse by the crate's own parser: {now}"
        );
    }
}
