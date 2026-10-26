//! The evidence layer behind the transport: deserialize an authenticated
//! batch, bind it to the authenticated probe id, attest it under the wrapped
//! evidence key, persist the new chain position, and **keep the attested
//! batch**.
//!
//! # Why the attested batch is written down
//!
//! The collector used to attest a batch, take its sequence number for the
//! acknowledgement, and drop it. That made the pilot's own Phase 1 exit gate
//! unreachable: it asks that "a real agent process is observed; its batch is
//! signed by a collector on a different host; **the verifier accepts it
//! offline**" — and there was nothing left on disk for a verifier to accept.
//! The chain position was persisted, which proves a batch existed, but a
//! position is not the evidence; the signed batch is.
//!
//! So each `AttestedBatch` is appended to `attested.archive.jsonl` in the
//! collector's state directory, one JSON object per line, in attestation
//! order. That file is what an auditor verifies with the collector's public
//! key and nothing else — no service, no network, no trust in this daemon.

use std::sync::{Arc, Mutex};

use aip_observe::{CollectorRuntime, MechanismIntegrity, ObservationBatch, SourceMechanism};
use aip_transport::{BatchAckData, BatchSink, SinkError};

/// Bridges [`aip_transport`]'s [`BatchSink`] to a shared [`CollectorRuntime`].
/// The lock is held only for the attest+persist of one batch, so concurrent
/// probe connections serialize per batch rather than per connection.
pub struct RuntimeSink {
    runtime: Arc<Mutex<CollectorRuntime>>,
    /// Where attested batches are appended. `None` keeps the old
    /// drop-after-ack behaviour, which exists only so a deployment that has
    /// its own sink can opt out deliberately rather than by omission.
    archive: Option<std::path::PathBuf>,
}

impl RuntimeSink {
    /// A sink that attests and keeps nothing. Prefer [`Self::with_archive`];
    /// this exists for tests and for a deployment that consumes batches by
    /// another route and says so.
    pub fn new(runtime: Arc<Mutex<CollectorRuntime>>) -> Self {
        Self {
            runtime,
            archive: None,
        }
    }

    /// A sink that appends every attested batch to `archive`.
    pub fn with_archive(
        runtime: Arc<Mutex<CollectorRuntime>>,
        archive: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            runtime,
            archive: Some(archive.into()),
        }
    }

    /// Append one attested batch, one JSON object per line.
    ///
    /// A failure here is returned rather than logged and swallowed. The
    /// batch has been attested and the chain has moved; if the evidence
    /// cannot be written, the probe must learn that its batch was not
    /// durably kept instead of being told everything is fine.
    fn archive_batch(&self, attested: &aip_observe::AttestedBatch) -> Result<(), SinkError> {
        let Some(path) = self.archive.as_ref() else {
            return Ok(());
        };
        use std::io::Write;
        let mut line = serde_json::to_vec(attested)
            .map_err(|e| SinkError(format!("cannot encode attested batch: {e}")))?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| SinkError(format!("cannot open {}: {e}", path.display())))?;
        f.write_all(&line)
            .map_err(|e| SinkError(format!("cannot append to {}: {e}", path.display())))?;
        f.sync_all()
            .map_err(|e| SinkError(format!("cannot flush {}: {e}", path.display())))?;
        Ok(())
    }
}

impl BatchSink for RuntimeSink {
    fn accept_batch(
        &mut self,
        probe_id: &str,
        _seq: u64,
        batch_bytes: &[u8],
    ) -> Result<BatchAckData, SinkError> {
        let batch: ObservationBatch = serde_json::from_slice(batch_bytes)
            .map_err(|e| SinkError(format!("batch is not a valid ObservationBatch: {e}")))?;

        // Bind the transport-authenticated identity to the batch's own claim: a
        // probe that authenticated as X may not submit a batch labelled Y. The
        // collector's registry further bounds which mechanisms probe X may
        // claim; this closes the identity half of that binding.
        if batch.probe_id != probe_id {
            return Err(SinkError(format!(
                "batch probe_id {:?} does not match the authenticated probe {:?}",
                batch.probe_id, probe_id
            )));
        }

        let mut batch = batch;

        // Cross-sensor divergence (Phase 0), applied BEFORE the runtime
        // absorbs the batch's own integrity reports. The missing-report rule
        // below catches a probe that declared a gate-able sensor active and
        // said nothing about it. It does not catch a sensor hooked on its
        // delivery path: there the probe reports the sensor live and
        // `Verified`, because the kernel's loss counter is touched only on a
        // genuinely full ring, not on a hook that drops above the accounting.
        // The one signal that survives such a hook is a gate-independent
        // connector exec with no corroborating perf exec. When the collector
        // finds that, it records its own finding into the batch's integrity
        // reports — as the attesting authority it may override a probe's
        // too-rosy self-report — so the runtime absorbs `Unverifiable` rather
        // than the probe's `Verified` and the signed state is
        // `IntegrityUnknown`. A later batch with no divergence carries the
        // probe's `Verified` again and recovery proceeds normally.
        for report in
            aip_observe::detect_cross_sensor_divergence_default(&batch).integrity_reports()
        {
            match batch
                .mechanism_integrity
                .iter_mut()
                .find(|r| r.mechanism == report.mechanism)
            {
                Some(existing) => existing.integrity = report.integrity,
                None => batch.mechanism_integrity.push(report),
            }
        }

        let mut rt = self
            .runtime
            .lock()
            .map_err(|_| SinkError("collector runtime lock poisoned".into()))?;

        // Completeness of the probe's integrity reports. `aip-probe` reports
        // a finding for every perf-tracepoint sensor it has open, every
        // cycle. A batch that declares such a sensor active and carries no
        // finding for it is therefore a probe that did not check — an older
        // build, a misconfiguration, or a host-side party editing the batch
        // before it left — and the collector cannot tell which. It fails
        // closed: the missing mechanism is noted `Unverifiable`, which the
        // signer treats exactly like a found gate, so the signed state is
        // `IntegrityUnknown` until a batch arrives that does report it. The
        // rule lives here, at the daemon boundary, because it is a property
        // of this deployment's probe, not of every batch producer.
        for m in batch
            .active_mechanisms
            .iter()
            .copied()
            .filter(SourceMechanism::shares_perf_tracepoint_gate)
        {
            let reported = batch.mechanism_integrity.iter().any(|r| r.mechanism == m);
            if !reported {
                rt.signer_mut()
                    .note_mechanism_integrity(m, MechanismIntegrity::Unverifiable);
            }
        }

        let attested = rt
            .attest(batch)
            .map_err(|e| SinkError(format!("attest refused: {e:?}")))?;
        let head = rt.snapshot().head.unwrap_or([0u8; 32]);
        // Keep the evidence, not just the position it advanced the chain to.
        self.archive_batch(&attested)?;
        Ok(BatchAckData {
            attested_sequence: attested.sequence,
            head,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{
        CollectorKey, CollectorStore, ContinuityPolicy, ObserverState, ProcfsProbe, Started,
    };

    fn dev_runtime(observer_id: &str, tag: &str) -> Arc<Mutex<CollectorRuntime>> {
        let dir = std::env::temp_dir().join(format!(
            "aip-sink-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CollectorStore::open(&dir).unwrap();
        let custodian = CollectorKey::development().into_custodian();
        let started = CollectorRuntime::start_with_custodian(
            store,
            observer_id,
            1,
            custodian,
            ContinuityPolicy::Strict,
        )
        .unwrap();
        match started {
            Started::Running(rt, _) => Arc::new(Mutex::new(rt)),
            Started::Refused(brk) => panic!("fresh dev runtime refused: {brk:?}"),
        }
    }

    fn batch_bytes(probe_id: &str) -> Vec<u8> {
        let mut probe = ProcfsProbe::new(probe_id);
        serde_json::to_vec(&probe.batch([1u8; 16], 100, 200, vec![])).unwrap()
    }

    #[test]
    fn accepts_a_batch_whose_probe_id_matches_the_authenticated_probe() {
        let mut sink = RuntimeSink::new(dev_runtime("obs", "match"));
        let bytes = batch_bytes("probe-1");
        assert!(sink.accept_batch("probe-1", 1, &bytes).is_ok());
    }

    // ── Phase 0 exit gate: a delivery-path hook, caught cross-sensor ──────
    //
    // The scenario the report calls decisive. A rootkit hooks the perf
    // submission path for a target pid: the exec never reaches the perf
    // tracepoint consumer, but the kernel's loss counter is never touched, so
    // the probe honestly reports SchedTracepoint live and `Verified`. The
    // gate-independent netlink connector, on a different facility, still
    // delivers the exec. Nothing in the probe's own books is wrong, so the
    // missing-report rule above does not fire — the ONLY thing that can catch
    // this is the cross-sensor divergence check.

    use aip_observe::{KernelLifecycleKind, ProcEvent};

    /// A batch in which the connector saw an exec the perf tracepoint did not,
    /// with the probe still reporting the perf sensor healthy — the on-wire
    /// picture a delivery-path hook produces.
    fn hooked_perf_batch(probe_id: &str, connector_pid: u32, sched_delivers: bool) -> Vec<u8> {
        let mut probe = ProcfsProbe::new(probe_id);
        probe.declare_source(SourceMechanism::ProcConnector);
        probe.declare_source(SourceMechanism::SchedTracepoint);
        // The probe's own integrity check finds nothing wrong: the hook drops
        // above the loss accounting, so from the sensor's books it is healthy.
        probe.declare_mechanism_integrity(
            SourceMechanism::SchedTracepoint,
            MechanismIntegrity::Verified,
        );
        let exec = |pid, ts| ProcEvent {
            cgroup: aip_observe::CgroupSample::NotSampled,
            kind: KernelLifecycleKind::Exec { pid, tgid: pid },
            cpu: 0,
            timestamp_ns: ts,
        };
        probe.ingest_kernel_event(exec(connector_pid, 1_000_000));
        if sched_delivers {
            probe.ingest_sched_event(exec(connector_pid, 1_001_000));
        }
        serde_json::to_vec(&probe.batch([9u8; 16], 100, 200, vec![])).unwrap()
    }

    #[test]
    fn a_delivery_path_hook_that_fools_the_sensors_own_books_lands_on_integrity_unknown() {
        let rt = dev_runtime("obs", "hook");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        // Connector delivered the exec; perf did not; perf reported healthy.
        let bytes = hooked_perf_batch("probe-1", 4242, false);
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_eq!(
            state_of(&rt),
            ObserverState::IntegrityUnknown,
            "a connector exec the perf tracepoint missed must force IntegrityUnknown even though \
             the probe's own integrity report said Verified"
        );
        // The finding is in the signed bytes, and coverage is withdrawn.
        let h = rt.lock().unwrap().health(300).unwrap();
        assert_eq!(h.health.state, ObserverState::IntegrityUnknown);
        assert_eq!(h.health.attested_coverage, None);
    }

    #[test]
    fn when_both_sensors_deliver_the_exec_there_is_no_false_integrity_finding() {
        let rt = dev_runtime("obs", "agree");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        let bytes = hooked_perf_batch("probe-1", 4242, true);
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_ne!(
            state_of(&rt),
            ObserverState::IntegrityUnknown,
            "corroborated execs must not raise a divergence finding"
        );
    }

    #[test]
    fn refuses_a_batch_labelled_with_a_different_probe_id() {
        // Authenticated as "probe-authed" but the batch claims "probe-other":
        // the transport identity is bound to the batch's own claim.
        let mut sink = RuntimeSink::new(dev_runtime("obs", "mismatch"));
        let bytes = batch_bytes("probe-other");
        let err = sink
            .accept_batch("probe-authed", 1, &bytes)
            .expect_err("a probe_id mismatch must be refused");
        assert!(err.0.contains("does not match"), "{}", err.0);
    }

    fn batch_with(
        probe_id: &str,
        declare: &[SourceMechanism],
        reports: &[(SourceMechanism, MechanismIntegrity)],
    ) -> Vec<u8> {
        let mut probe = ProcfsProbe::new(probe_id);
        for m in declare {
            probe.declare_source(*m);
        }
        for (m, i) in reports {
            probe.declare_mechanism_integrity(*m, *i);
        }
        serde_json::to_vec(&probe.batch([1u8; 16], 100, 200, vec![])).unwrap()
    }

    fn state_of(rt: &Arc<Mutex<CollectorRuntime>>) -> ObserverState {
        rt.lock().unwrap().state()
    }

    // The finding the two-host deployment could not previously express: the
    // probe on the agent host saw a foreign eBPF program on a sampled
    // tracepoint; the collector on another host must sign IntegrityUnknown.
    #[test]
    fn a_gate_reported_by_the_probe_makes_the_off_host_state_integrity_unknown() {
        let rt = dev_runtime("obs", "gate");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        let bytes = batch_with(
            "probe-1",
            &[SourceMechanism::SchedTracepoint],
            &[(
                SourceMechanism::SchedTracepoint,
                MechanismIntegrity::ForeignTracepointGate {
                    foreign_programs: 1,
                },
            )],
        );
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_eq!(state_of(&rt), ObserverState::IntegrityUnknown);
        // The finding is inside the attested bytes: the signed health says so.
        let h = rt.lock().unwrap().health(300).unwrap();
        assert_eq!(h.health.state, ObserverState::IntegrityUnknown);
        assert_eq!(h.health.attested_coverage, None);
    }

    #[test]
    fn a_verified_report_for_every_open_sensor_keeps_the_state_active() {
        let rt = dev_runtime("obs", "verified");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        let bytes = batch_with(
            "probe-1",
            &[SourceMechanism::SchedTracepoint],
            &[(
                SourceMechanism::SchedTracepoint,
                MechanismIntegrity::Verified,
            )],
        );
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_ne!(state_of(&rt), ObserverState::IntegrityUnknown);
    }

    // A probe that declares a gate-able sensor active and says nothing about
    // its integrity did not check; the daemon fails closed rather than sign a
    // false Active.
    #[test]
    fn a_missing_report_for_an_active_tracepoint_sensor_fails_closed() {
        let rt = dev_runtime("obs", "omitted");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        let bytes = batch_with("probe-1", &[SourceMechanism::SchedTracepoint], &[]);
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_eq!(state_of(&rt), ObserverState::IntegrityUnknown);
    }

    // The gate-independent sources do not share the tracepoint submission
    // gate; a batch built from them alone owes no integrity report.
    #[test]
    fn a_batch_without_tracepoint_sensors_owes_no_report() {
        let rt = dev_runtime("obs", "no-tracepoint");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        let bytes = batch_with("probe-1", &[SourceMechanism::ProcConnector], &[]);
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_ne!(state_of(&rt), ObserverState::IntegrityUnknown);
    }

    // A Verified report for a sensor the batch does not declare active cannot
    // clear a slot: the probe would otherwise clear a gate finding for a
    // sensor it stopped running.
    #[test]
    fn a_verified_report_for_an_inactive_sensor_does_not_clear_a_gate() {
        let rt = dev_runtime("obs", "stale-clear");
        let mut sink = RuntimeSink::new(Arc::clone(&rt));
        let gated = batch_with(
            "probe-1",
            &[SourceMechanism::SockStateTracepoint],
            &[(
                SourceMechanism::SockStateTracepoint,
                MechanismIntegrity::ForeignTracepointGate {
                    foreign_programs: 2,
                },
            )],
        );
        sink.accept_batch("probe-1", 1, &gated).unwrap();
        assert_eq!(state_of(&rt), ObserverState::IntegrityUnknown);
        let clear_without_running = batch_with(
            "probe-1",
            &[],
            &[(
                SourceMechanism::SockStateTracepoint,
                MechanismIntegrity::Verified,
            )],
        );
        sink.accept_batch("probe-1", 2, &clear_without_running)
            .unwrap();
        assert_eq!(state_of(&rt), ObserverState::IntegrityUnknown);
    }

    #[test]
    fn refuses_bytes_that_are_not_an_observation_batch() {
        let mut sink = RuntimeSink::new(dev_runtime("obs", "garbage"));
        let err = sink
            .accept_batch("probe-1", 1, b"not json")
            .expect_err("garbage must be refused");
        assert!(err.0.contains("not a valid ObservationBatch"), "{}", err.0);
    }
}
