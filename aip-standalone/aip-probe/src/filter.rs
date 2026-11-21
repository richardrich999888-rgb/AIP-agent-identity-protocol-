//! Retain only explicitly enrolled process instances before transport/spooling.
//!
//! The kernel sensors still observe their configured host/mount/interface
//! scopes internally. This is a privacy boundary on exported records, not a
//! kernel isolation mechanism and not an identity attestor. Unassignable
//! events are withheld and counted, never guessed into a target.

use std::io::Read;
use std::path::Path;

use aip_observe::{
    AgentFilterScope, BatchFilterReport, ObservationBatch, ObservedProcess,
    OBSERVE_PROTOCOL_VERSION,
};

const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct AgentFilter {
    scope: AgentFilterScope,
}

impl AgentFilter {
    pub fn from_scope(scope: AgentFilterScope) -> Result<Self, String> {
        scope.validate().map_err(str::to_owned)?;
        Ok(Self { scope })
    }

    /// Open once, refuse symlinks, limit bytes, and validate the descriptor's
    /// metadata. The selection cannot silently change during a probe run.
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("cannot open filter scope {}: {e}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("cannot inspect filter scope: {e}"))?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err("filter scope must be a regular file no larger than 256 KiB".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // A root-controlled file may grant read access to the dedicated
            // probe group. No group write/execute or access by others.
            // SAFETY: geteuid has no preconditions and returns a value only.
            let uid = unsafe { libc::geteuid() };
            if (metadata.uid() != 0 && metadata.uid() != uid)
                || !matches!(metadata.mode() & 0o7777, 0o600 | 0o640)
            {
                return Err(
                    "filter scope must be owned by root or the probe user, with mode 0600 or 0640"
                        .into(),
                );
            }
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read filter scope: {e}"))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err("filter scope exceeds 256 KiB".into());
        }
        Self::from_scope(
            serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid filter scope JSON: {e}"))?,
        )
    }

    /// Enroll the actual live incarnation with a pidfd-anchored measurement.
    /// The output is an operator selection, never a verified agent binding.
    #[cfg(target_os = "linux")]
    pub fn enroll(label: &str, pid: u32) -> Result<Self, String> {
        let probe = aip_observe::ProcfsProbe::new("filter-enrollment");
        let anchored = probe
            .measure_anchored(pid)
            .map_err(|e| format!("cannot enroll live process: {e:?}"))?;
        if !anchored.is_alive() {
            return Err("process exited during filter enrollment".into());
        }
        let p = &anchored.process;
        // Linux enrollment always pins measured namespaces too. If they
        // cannot be read, ask the operator to fix access, not omit a check.
        let container = p
            .container
            .ok_or("cannot enroll without measured process namespaces")?;
        Self::from_scope(AgentFilterScope {
            version: aip_observe::FILTER_SCOPE_VERSION,
            targets: vec![aip_observe::AgentFilterTarget {
                agent_label: label.into(),
                process: p.process,
                exe_content_sha256: p.exe_content_sha256,
                container: Some(container),
            }],
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enroll(_label: &str, _pid: u32) -> Result<Self, String> {
        Err("filter enrollment requires a live Linux process".into())
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.scope)
            .map_err(|e| format!("cannot encode filter scope: {e}"))
    }

    pub fn scope(&self) -> &AgentFilterScope {
        &self.scope
    }

    fn classify(&self, p: Option<&ObservedProcess>) -> Selection {
        let Some(p) = p else {
            return Selection::Unassigned;
        };
        if self.scope.matches(p) {
            return Selection::Retain;
        }
        // A missing namespace measurement is uncertainty, not evidence of
        // different placement. PID reuse and changed executable hashes do
        // not match the enrolled process; a bare claimed agent label never
        // participates in this comparison.
        if self.scope.targets.iter().any(|t| {
            t.process == p.process
                && t.exe_content_sha256 == p.exe_content_sha256
                && t.container.is_some_and(|wanted| {
                    p.container.is_none_or(|actual| {
                        actual.pid_ns_inode == 0
                            || actual.mnt_ns_inode == 0
                            || actual.net_ns_inode == 0
                            || (wanted.cgroup_id.is_some() && actual.cgroup_id.is_none())
                    })
                })
        }) {
            Selection::Unassigned
        } else {
            Selection::Exclude
        }
    }

    pub fn apply(&self, mut batch: ObservationBatch) -> Result<ObservationBatch, String> {
        if batch.version != OBSERVE_PROTOCOL_VERSION || !batch.content_fits_version() {
            return Err("filter requires a valid current-version observation batch".into());
        }
        if batch.filter_report.is_some() {
            return Err("refusing to filter an already filtered batch".into());
        }
        let original_records = (batch.observations.len() as u64)
            .checked_add(batch.kernel_events.len() as u64)
            .ok_or("filter record count overflow")?;
        let mut excluded_records = 0;
        let mut unassigned_records = 0;
        let mut retain = |selection| match selection {
            Selection::Retain => true,
            Selection::Exclude => {
                excluded_records += 1;
                false
            }
            Selection::Unassigned => {
                unassigned_records += 1;
                false
            }
        };
        batch
            .observations
            .retain(|o| retain(self.classify(Some(&o.observed))));
        batch.kernel_events.retain(|e| {
            // A contradictory or absent task context is unassignable,
            // even if a malformed record supplies a selected bound field.
            let selection = if e
                .bound
                .as_ref()
                .is_some_and(|p| e.kind.subject_pid() != Some(p.process.pid))
            {
                Selection::Unassigned
            } else {
                self.classify(e.bound.as_ref())
            };
            retain(selection)
        });
        // Leave original sequence range, timestamps, source loss, mechanism
        // declarations and integrity findings untouched. The collector can
        // still see source gaps; excluded host data never enters the spool.
        batch.filter_report = Some(BatchFilterReport {
            scope: self.scope.clone(),
            original_records,
            excluded_records,
            unassigned_records,
        });
        debug_assert!(batch.content_fits_version());
        Ok(batch)
    }
}

#[derive(Clone, Copy)]
enum Selection {
    Retain,
    Exclude,
    Unassigned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{
        verify_attested_batch, verify_signed_health, AgentAttribution, AgentClaim, CgroupSample,
        CollectorSigner, CoverageWindow, KernelLifecycleEvent, KernelLifecycleKind,
        ObservationAvailability, ObservedEffect, ObserverAttestor, ObserverTrustAnchors,
        ProcfsProbe, SourceMechanism,
    };

    fn target() -> aip_observe::AgentFilterTarget {
        serde_json::from_value(serde_json::json!({
            "agent_label":"customer-agent", "process":{"pid":12345,"pid_start_time_ticks":888,
            "boot_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]},
            "exe_content_sha256": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
            "container":{"pid_ns_inode":91,"mnt_ns_inode":92,"net_ns_inode":93,"cgroup_id":94}
        }))
        .unwrap()
    }
    fn filter() -> AgentFilter {
        AgentFilter::from_scope(AgentFilterScope {
            version: 1,
            targets: vec![target()],
        })
        .unwrap()
    }
    fn process() -> ObservedProcess {
        let t = target();
        ObservedProcess {
            process: t.process,
            exe_content_sha256: t.exe_content_sha256,
            exe_path: "/approved/agent".into(),
            container: t.container,
        }
    }
    fn observation_batch(probe: &mut ProcfsProbe, id: u8, p: ObservedProcess) -> ObservationBatch {
        let o = probe.observation(p, ObservedEffect::ProcessPresent, None, (id as u64) * 100);
        probe.batch([id; 16], (id as u64) * 100, (id as u64 + 1) * 100, vec![o])
    }
    fn kernel_event(seq: u64, bound: Option<ObservedProcess>) -> KernelLifecycleEvent {
        KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "probe".into(),
            mechanism: SourceMechanism::ProcConnector,
            kind: KernelLifecycleKind::Exec {
                pid: 12345,
                tgid: 12345,
            },
            cpu: 0,
            kernel_timestamp_ns: 999,
            probe_seq: seq,
            bound,
            attribution: AgentAttribution::NotEstablished,
            claimed_decision_id: None,
            cgroup: CgroupSample::NotSampled,
        }
    }

    #[test]
    fn exact_scope_excludes_pid_reuse_wrong_boot_image_namespaces_and_self_claims() {
        let mut probe = ProcfsProbe::new("probe");
        let mut variants = vec![process(); 6];
        variants[0].process.pid_start_time_ticks += 1;
        variants[1].process.boot_id = [3; 16];
        variants[2].exe_content_sha256 = [3; 32];
        variants[3].container.as_mut().unwrap().net_ns_inode += 1;
        variants[4].container.as_mut().unwrap().cgroup_id = Some(95);
        variants[5].process.pid += 1;
        let claim = AgentClaim {
            agent_id: "customer-agent".into(),
            claim_source: "untrusted self-report".into(),
            decision_id: None,
        };
        let mut observations =
            vec![probe.observation(process(), ObservedEffect::ProcessPresent, None, 100)];
        observations.extend(variants.into_iter().map(|mut p| {
            p.exe_path = "private-other-agent-path".into();
            probe.observation(p, ObservedEffect::ProcessPresent, Some(&claim), 100)
        }));
        let original = probe.batch([1; 16], 100, 200, observations);
        let filtered = filter().apply(original.clone()).unwrap();
        assert_eq!(filtered.observations, original.observations[..1]);
        assert_eq!(filtered.filter_report.as_ref().unwrap().excluded_records, 6);
        assert!(!serde_json::to_string(&filtered)
            .unwrap()
            .contains("private-other-agent-path"));
        assert_eq!(
            filtered.observations[0].attribution,
            AgentAttribution::NotEstablished
        );
        assert_eq!(
            (filtered.probe_seq_first, filtered.probe_seq_last),
            (original.probe_seq_first, original.probe_seq_last)
        );
    }

    #[test]
    fn unbound_and_namespace_unreadable_records_are_counted_without_export() {
        let mut probe = ProcfsProbe::new("probe");
        probe.record_lost_events(7);
        let mut batch = observation_batch(&mut probe, 1, process());
        let mut unreadable = process();
        unreadable.container = None;
        let mut missing_cgroup = process();
        missing_cgroup.container.as_mut().unwrap().cgroup_id = None;
        batch.kernel_events = vec![
            kernel_event(2, None),
            kernel_event(3, Some(unreadable)),
            kernel_event(4, Some(missing_cgroup)),
            kernel_event(5, Some(process())),
        ];
        batch.probe_seq_last = 5;
        let filtered = filter().apply(batch.clone()).unwrap();
        let report = filtered.filter_report.as_ref().unwrap();
        assert_eq!(
            (
                report.original_records,
                report.excluded_records,
                report.unassigned_records
            ),
            (5, 0, 3)
        );
        assert_eq!(filtered.kernel_events, batch.kernel_events[3..]);
        assert_eq!(filtered.dropped_events, Some(7));
        assert_eq!(filtered.claimed_from_ms, batch.claimed_from_ms);
        assert_eq!(filtered.claimed_to_ms, batch.claimed_to_ms);
        assert!(filter().apply(filtered).is_err());
    }

    #[test]
    fn unrelated_or_subjectless_payloads_cannot_borrow_a_selected_bound_identity() {
        let mut probe = ProcfsProbe::new("probe");
        let mut batch = observation_batch(&mut probe, 1, process());
        let mut other = kernel_event(2, Some(process()));
        other.kind = KernelLifecycleKind::ProcessExec {
            pid: 99999,
            old_pid: 99999,
            filename: "/private/another-agent".into(),
        };
        let mut subjectless = kernel_event(3, Some(process()));
        subjectless.kind = KernelLifecycleKind::Other { what: 123 };
        batch.kernel_events = vec![other.clone(), subjectless, kernel_event(4, Some(process()))];
        batch.probe_seq_last = 4;
        let filtered = filter().apply(batch).unwrap();
        assert_eq!(filtered.kernel_events.len(), 1);
        assert_eq!(
            filtered.filter_report.as_ref().unwrap().unassigned_records,
            2
        );
        assert!(!serde_json::to_string(&filtered)
            .unwrap()
            .contains("/private/another-agent"));

        // The signed schema also refuses such a payload from a probe that
        // bypassed its local filter. It is not enough to trust the producer.
        let mut injected = filtered;
        injected.kernel_events.push(other);
        let report = injected.filter_report.as_mut().unwrap();
        report.unassigned_records -= 1;
        assert!(!injected.content_fits_version());
        let kp = aip_crypto::generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new("collector", 1, &kp.private_key, &kp.public_key).unwrap();
        assert!(signer.attest_at(injected, 1000).is_err());
    }

    #[test]
    fn filtered_batches_verify_but_never_grant_continuous_or_absence_coverage() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new("collector", 1, &kp.private_key, &kp.public_key).unwrap();
        let anchors = ObserverTrustAnchors::new().trust("collector", 1, &kp.public_key);
        let mut probe = ProcfsProbe::new("probe");
        probe.declare_source(SourceMechanism::ProcConnector);
        for id in 1..=3 {
            let mut p = process();
            if id == 2 {
                p.process.pid_start_time_ticks += 1;
            }
            let batch = filter()
                .apply(observation_batch(&mut probe, id, p))
                .unwrap();
            if id == 2 {
                assert!(batch.observations.is_empty());
                assert!(batch.has_stream_records());
            }
            let attested = signer.attest_at(batch, 1000).unwrap();
            verify_attested_batch(&attested, &anchors).unwrap();
        }
        assert!(
            signer.probe_faults().is_empty(),
            "intentional filtering must not manufacture source loss"
        );
        let health = signer.health(1000).unwrap();
        verify_signed_health(&health, &anchors).unwrap();
        assert_eq!(health.health.attested_coverage, None);
        assert!(health.health.covered_by.is_empty());
        assert!(!health.covered_by_kernel_pushed_source());
        assert!(matches!(
            health.availability_for(
                &CoverageWindow {
                    from_ms: 200,
                    to_ms: 300
                },
                1000,
                100
            ),
            ObservationAvailability::Unavailable { .. }
        ));
    }

    #[test]
    fn scope_counters_and_targets_are_signed_and_legacy_injection_is_refused() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new("collector", 1, &kp.private_key, &kp.public_key).unwrap();
        let anchors = ObserverTrustAnchors::new().trust("collector", 1, &kp.public_key);
        let mut probe = ProcfsProbe::new("probe");
        let batch = filter()
            .apply(observation_batch(&mut probe, 1, process()))
            .unwrap();
        let attested = signer.attest_at(batch.clone(), 1000).unwrap();
        let mut changed = attested.clone();
        changed.batch.filter_report = None;
        assert!(verify_attested_batch(&changed, &anchors).is_err());
        let mut changed = attested.clone();
        changed.batch.filter_report.as_mut().unwrap().scope.targets[0].agent_label =
            "different-label".into();
        assert!(verify_attested_batch(&changed, &anchors).is_err());
        let mut changed = attested.clone();
        let report = changed.batch.filter_report.as_mut().unwrap();
        report.original_records += 1;
        report.excluded_records += 1;
        assert!(verify_attested_batch(&changed, &anchors).is_err());
        for version in [12, 13] {
            let mut injected = attested.clone();
            injected.version = version;
            injected.batch.version = version;
            // Even a freshly signed legacy record must not carry unencoded scope.
            injected.attestation = aip_crypto::sign_ed25519(
                &kp.private_key,
                "collector",
                &injected.signing_preimage(),
            )
            .unwrap();
            assert!(
                matches!(verify_attested_batch(&injected,&anchors),Err(aip_observe::VerifyError::ContentNotInVersion(v)) if v==version)
            );
        }
        let mut bad = batch.clone();
        bad.filter_report.as_mut().unwrap().original_records += 1;
        assert!(signer.attest_at(bad, 1001).is_err());
        let mut bad = batch;
        bad.observations[0].observed.process.pid_start_time_ticks += 1;
        assert!(signer.attest_at(bad, 1001).is_err());
    }

    #[test]
    fn source_loss_with_filtering_remains_a_collector_fault() {
        let kp = aip_crypto::generate_ed25519_keypair();
        let mut signer =
            CollectorSigner::new("collector", 1, &kp.private_key, &kp.public_key).unwrap();
        let mut probe = ProcfsProbe::new("probe");
        probe.record_lost_events(2);
        let batch = filter()
            .apply(observation_batch(&mut probe, 1, process()))
            .unwrap();
        signer.attest_at(batch, 1000).unwrap();
        assert!(matches!(
            signer.probe_faults(),
            [aip_observe::ProbeStreamFault::EventsLost { n: 2 }]
        ));
    }

    #[test]
    fn strict_schema_rejects_unknown_nested_fields_duplicates_empty_and_zero_targets() {
        let base = serde_json::to_value(filter().scope()).unwrap();
        for path in [
            vec!["unexpected"],
            vec!["targets", "0", "unexpected"],
            vec!["targets", "0", "process", "unexpected"],
            vec!["targets", "0", "container", "unexpected"],
        ] {
            let mut value = base.clone();
            let mut cursor = &mut value;
            for key in &path[..path.len() - 1] {
                cursor = if *key == "0" {
                    &mut cursor[0]
                } else {
                    &mut cursor[*key]
                };
            }
            cursor[path[path.len() - 1]] = serde_json::json!(true);
            assert!(serde_json::from_value::<AgentFilterScope>(value).is_err());
        }
        let mut duplicate = filter().scope;
        duplicate.targets.push(target());
        assert!(AgentFilter::from_scope(duplicate).is_err());
        let mut empty = filter().scope;
        empty.targets.clear();
        assert!(AgentFilter::from_scope(empty).is_err());
        let mut zero = filter().scope;
        zero.targets[0].process.pid_start_time_ticks = 0;
        assert!(AgentFilter::from_scope(zero).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_enrollment_matches_the_measured_incarnation_and_refuses_pid_zero() {
        let filter = AgentFilter::enroll("live-self", std::process::id()).unwrap();
        let probe = ProcfsProbe::new("self-enrollment-check");
        let actual = probe.measure_anchored(std::process::id()).unwrap();
        assert!(actual.is_alive());
        assert!(filter.scope().matches(&actual.process));
        assert!(filter.scope().targets[0].container.is_some());
        assert!(AgentFilter::enroll("missing", 0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn loader_refuses_symlink_public_permissions_oversize_and_live_file_changes() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!(
            "aip-filter-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("scope.json");
        std::fs::write(&path, filter().to_json().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = AgentFilter::load(&path).unwrap();
        std::fs::write(&path, "{}").unwrap();
        assert!(AgentFilter::load(&path).is_err());
        assert_eq!(
            loaded.scope().targets[0],
            target(),
            "the loaded scope is immutable during a run"
        );
        std::fs::write(&path, filter().to_json().unwrap()).unwrap();
        let link = dir.join("link.json");
        symlink(&path, &link).unwrap();
        assert!(AgentFilter::load(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(AgentFilter::load(&path).is_ok());
        for mode in [0o644, 0o750, 0o700, 0o660, 0o4600] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(AgentFilter::load(&path).is_err(), "accepted mode {mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![b' '; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(AgentFilter::load(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
