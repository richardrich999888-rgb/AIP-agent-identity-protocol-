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

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use aip_crypto::sha256;
use aip_observe::{verify_attested_batch, AttestedBatch, ObserverTrustAnchors};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct BatchIdentity([u8; 32], [u8; 16], [u8; 16]);

/// Bounded pilot receipt retention. Never evict a receipt and accidentally
/// re-attest a delayed replay. Exhaustion refuses new batches before signing;
/// already committed retries can still drain probe spools.
/// 1,000,000 batches is about 11.6 days at one batch/second across all probes.
pub const MAX_REPLAY_RECEIPTS: usize = 1_000_000;
const MAX_ARCHIVE_RECORD_BYTES: u64 = 16 * 1024 * 1024;

impl BatchIdentity {
    fn of(batch: &ObservationBatch) -> Self {
        Self(
            sha256(batch.probe_id.as_bytes()),
            batch.probe_run_id,
            batch.batch_id,
        )
    }
}

#[derive(Debug, Clone)]
struct Receipt {
    digest: [u8; 32],
    ack: BatchAckData,
    offset: u64,
    record_bytes: u64,
    record_digest: [u8; 32],
}

#[derive(Debug, Default)]
struct ArchiveIndex {
    receipts: HashMap<BatchIdentity, Receipt>,
    bytes: u64,
    failed: bool,
}

impl ArchiveIndex {
    /// Rebuild only from signatures anchored in this collector's configured
    /// evidence key and a complete chain matching its persisted position. A
    /// raw JSON receipt cache is never a source of acknowledgement authority.
    fn load_with_limit(
        path: &std::path::Path,
        runtime: &CollectorRuntime,
        limit: usize,
    ) -> Result<Self, SinkError> {
        let mut index = Self::default();
        let snapshot = runtime.snapshot();
        let signer = runtime.signer();
        let anchors = ObserverTrustAnchors::new().trust(
            signer.observer_id(),
            signer.key_version(),
            signer.public_key(),
        );
        let mut sequence = 0u64;
        let mut head = [0u8; 32];
        match archive_options().read(true).open(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(SinkError(format!(
                    "cannot read replay archive {}: {e}",
                    path.display()
                )))
            }
            Ok(file) => {
                if !file
                    .metadata()
                    .map_err(|e| SinkError(format!("inspect replay archive: {e}")))?
                    .is_file()
                {
                    return Err(SinkError("replay archive must be a regular file".into()));
                }
                let mut reader = BufReader::new(file);
                loop {
                    // A bounded line reader refuses hostile/corrupt local
                    // storage before allocating an unbounded JSON record.
                    let mut line = Vec::new();
                    let count = reader
                        .by_ref()
                        .take(MAX_ARCHIVE_RECORD_BYTES + 1)
                        .read_until(b'\n', &mut line)
                        .map_err(|e| SinkError(format!("read replay archive: {e}")))?;
                    if count == 0 {
                        break;
                    }
                    if count as u64 > MAX_ARCHIVE_RECORD_BYTES || line.last() != Some(&b'\n') {
                        return Err(SinkError(
                            "oversized or torn replay archive record; refusing recovery".into(),
                        ));
                    }
                    if index.receipts.len() >= limit {
                        return Err(SinkError("replay receipt capacity exhausted; archive retained, new collector epoch requires operator planning".into()));
                    }
                    let attested: AttestedBatch = serde_json::from_slice(&line)
                        .map_err(|e| SinkError(format!("invalid replay archive record: {e}")))?;
                    verify_attested_batch(&attested, &anchors).map_err(|e| {
                        SinkError(format!("untrusted replay archive record: {e:?}"))
                    })?;
                    if attested.sequence != sequence + 1 || attested.prev_head != head {
                        return Err(SinkError(
                            "replay archive chain is not contiguous; refusing recovery".into(),
                        ));
                    }
                    sequence = attested.sequence;
                    head = attested.head();
                    let receipt = Receipt {
                        digest: sha256(&attested.batch.canonical_bytes()),
                        ack: BatchAckData {
                            attested_sequence: sequence,
                            head,
                        },
                        offset: index.bytes,
                        record_bytes: count as u64,
                        record_digest: sha256(&line),
                    };
                    let id = BatchIdentity::of(&attested.batch);
                    if index.receipts.insert(id, receipt).is_some() {
                        return Err(SinkError(
                            "duplicate batch identity in archive; refusing ambiguous recovery"
                                .into(),
                        ));
                    }
                    index.bytes += count as u64;
                }
            }
        }
        let archive_position = if sequence == 0 {
            (None, None)
        } else {
            (Some(sequence), Some(head))
        };
        if archive_position != (snapshot.sequence, snapshot.head) {
            return Err(SinkError("replay archive does not match the collector's persisted chain position; refusing recovery".into()));
        }
        Ok(index)
    }
}

fn verify_retained_receipt(
    path: &std::path::Path,
    expected_bytes: u64,
    receipt: &Receipt,
) -> Result<(), SinkError> {
    let mut file = archive_options()
        .read(true)
        .open(path)
        .map_err(|e| SinkError(format!("cannot confirm retained replay evidence: {e}")))?;
    let metadata = file
        .metadata()
        .map_err(|e| SinkError(format!("cannot inspect retained replay evidence: {e}")))?;
    if !metadata.is_file()
        || metadata.len() != expected_bytes
        || receipt.record_bytes > MAX_ARCHIVE_RECORD_BYTES
    {
        return Err(SinkError(
            "retained replay archive changed; ACK refused".into(),
        ));
    }
    file.seek(SeekFrom::Start(receipt.offset))
        .map_err(|e| SinkError(format!("cannot seek retained replay evidence: {e}")))?;
    let mut bytes = vec![0u8; receipt.record_bytes as usize];
    file.read_exact(&mut bytes)
        .map_err(|e| SinkError(format!("cannot read retained replay evidence: {e}")))?;
    if sha256(&bytes) != receipt.record_digest {
        return Err(SinkError(
            "retained replay evidence is corrupt; ACK refused".into(),
        ));
    }
    Ok(())
}

fn archive_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}

use aip_observe::{CollectorRuntime, MechanismIntegrity, ObservationBatch, SourceMechanism};
use aip_transport::{BatchAckData, BatchSink, SinkError};

/// Bridges [`aip_transport`]'s [`BatchSink`] to a shared [`CollectorRuntime`].
/// The lock is held only for the attest+persist of one batch, so concurrent
/// probe connections serialize per batch rather than per connection.
#[derive(Clone)]
pub struct RuntimeSink {
    runtime: Arc<Mutex<CollectorRuntime>>,
    /// Where attested batches are appended. `None` keeps the old
    /// drop-after-ack behaviour, which exists only so a deployment that has
    /// its own sink can opt out deliberately rather than by omission.
    archive: Option<std::path::PathBuf>,
    /// Shared by all connections; the runtime lock serializes archive commits
    /// with attestations, and this index makes ACK-loss replay idempotent.
    index: Arc<Mutex<Option<ArchiveIndex>>>,
    receipt_limit: usize,
}

impl RuntimeSink {
    /// A sink that attests and keeps nothing. Prefer [`Self::with_archive`];
    /// this exists for tests and for a deployment that consumes batches by
    /// another route and says so.
    pub fn new(runtime: Arc<Mutex<CollectorRuntime>>) -> Self {
        Self {
            runtime,
            archive: None,
            index: Arc::new(Mutex::new(None)),
            receipt_limit: MAX_REPLAY_RECEIPTS,
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
            index: Arc::new(Mutex::new(None)),
            receipt_limit: MAX_REPLAY_RECEIPTS,
        }
    }

    /// Validate the durable replay index before accepting connections. A
    /// cloned sink shares the same validated index and failure latch.
    pub fn initialize_archive(&mut self) -> Result<(), SinkError> {
        if let Some(path) = self.archive.as_ref() {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| SinkError("collector runtime lock poisoned".into()))?;
            let mut index = self
                .index
                .lock()
                .map_err(|_| SinkError("collector archive lock poisoned".into()))?;
            if index.is_none() {
                *index = Some(ArchiveIndex::load_with_limit(
                    path,
                    &runtime,
                    self.receipt_limit,
                )?);
            }
        }
        Ok(())
    }

    /// Append one attested batch, one JSON object per line.
    ///
    /// A failure here is returned rather than logged and swallowed. The
    /// batch has been attested and the chain has moved; if the evidence
    /// cannot be written, the probe must learn that its batch was not
    /// durably kept instead of being told everything is fine.
    fn archive_batch(
        &self,
        attested: &aip_observe::AttestedBatch,
        expected_bytes: u64,
    ) -> Result<(u64, [u8; 32]), SinkError> {
        let Some(path) = self.archive.as_ref() else {
            return Ok((0, [0; 32]));
        };
        use std::io::Write;
        let mut line = serde_json::to_vec(attested)
            .map_err(|e| SinkError(format!("cannot encode attested batch: {e}")))?;
        line.push(b'\n');
        let mut f = archive_options()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| SinkError(format!("cannot open {}: {e}", path.display())))?;
        let metadata = f
            .metadata()
            .map_err(|e| SinkError(format!("cannot inspect {}: {e}", path.display())))?;
        if !metadata.is_file() || metadata.len() != expected_bytes {
            return Err(SinkError(
                "archive changed outside the serialized collector writer".into(),
            ));
        }
        f.write_all(&line)
            .map_err(|e| SinkError(format!("cannot append to {}: {e}", path.display())))?;
        f.sync_all()
            .map_err(|e| SinkError(format!("cannot flush {}: {e}", path.display())))?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| SinkError(format!("cannot flush archive directory: {e}")))?;
        }
        Ok((line.len() as u64, sha256(&line)))
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

        // Idempotent retry is permitted only for a signed, durably archived
        // batch with identical canonical content. It does not call attest,
        // refresh health, widen coverage, or clear any probe/clock fault.
        if !batch.content_fits_version() {
            return Err(SinkError(
                "batch carries content outside its signed protocol version".into(),
            ));
        }
        let id = BatchIdentity::of(&batch);
        let digest = sha256(&batch.canonical_bytes());
        let mut shared_index = self
            .index
            .lock()
            .map_err(|_| SinkError("collector archive lock poisoned".into()))?;
        if let Some(path) = self.archive.as_ref() {
            if shared_index.is_none() {
                *shared_index = Some(ArchiveIndex::load_with_limit(
                    path,
                    &rt,
                    self.receipt_limit,
                )?);
            }
        }
        if let Some(index) = shared_index.as_ref() {
            if index.failed {
                return Err(SinkError(
                    "collector archive failed; restart and integrity recovery required".into(),
                ));
            }
            if let Some(receipt) = index.receipts.get(&id) {
                if receipt.digest != digest {
                    return Err(SinkError(
                        "batch identity reused with different content; replay refused".into(),
                    ));
                }
                // A cached receipt is not proof that its durable record
                // still exists. Check the exact signed bytes originally
                // verified/committed before acknowledging a retry.
                let path = self
                    .archive
                    .as_ref()
                    .expect("archive index has an archive path");
                if let Err(error) = verify_retained_receipt(path, index.bytes, receipt) {
                    if let Some(index) = shared_index.as_mut() {
                        index.failed = true;
                    }
                    return Err(error);
                }
                return Ok(receipt.ack.clone());
            }
        }

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

        if shared_index
            .as_ref()
            .is_some_and(|index| index.receipts.len() >= self.receipt_limit)
        {
            return Err(SinkError("replay receipt capacity exhausted; archive and receipts retained; refusing new batches before signing".into()));
        }
        let before = rt.snapshot();
        let attested = match rt.attest(batch) {
            Ok(attested) => attested,
            Err(error) => {
                // A persistence error may have advanced the signer before the
                // position reached disk. Refuse all further ACKs until strict
                // recovery; do not improvise another sequence on retry.
                // Malformed/unauthorized submissions rejected before chain
                // advancement do not poison all other probe sessions. Store
                // failures and any signer advance remain fatal to replay.
                let after = rt.snapshot();
                if matches!(error, aip_observe::RuntimeError::Store(_))
                    || (before.sequence, before.head) != (after.sequence, after.head)
                {
                    if let Some(index) = shared_index.as_mut() {
                        index.failed = true;
                    }
                }
                return Err(SinkError(format!("attest refused: {error:?}")));
            }
        };
        let ack = BatchAckData {
            attested_sequence: attested.sequence,
            head: attested.head(),
        };
        let expected_bytes = shared_index.as_ref().map(|i| i.bytes).unwrap_or(0);
        let (record_bytes, record_digest) = match self.archive_batch(&attested, expected_bytes) {
            Ok(record) => record,
            Err(error) => {
                if let Some(index) = shared_index.as_mut() {
                    index.failed = true;
                }
                return Err(error);
            }
        };
        if let Some(index) = shared_index.as_mut() {
            index.bytes = expected_bytes + record_bytes;
            index.receipts.insert(
                id,
                Receipt {
                    digest,
                    ack: ack.clone(),
                    offset: expected_bytes,
                    record_bytes,
                    record_digest,
                },
            );
        }
        Ok(ack)
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

    struct ReplayDirectory(std::path::PathBuf);
    impl ReplayDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aip-replay-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn archive(&self) -> std::path::PathBuf {
            self.0.join("attested.archive.jsonl")
        }
        fn start(
            &self,
            private: &[u8],
            public: &[u8],
        ) -> (Arc<Mutex<CollectorRuntime>>, RuntimeSink) {
            let started = CollectorRuntime::start(
                CollectorStore::open(&self.0).unwrap(),
                "replay-test",
                1,
                private,
                public,
                ContinuityPolicy::Strict,
            )
            .unwrap();
            let runtime = match started {
                Started::Running(rt, _) => Arc::new(Mutex::new(rt)),
                Started::Refused(reason) => panic!("strict restart refused: {reason:?}"),
            };
            let sink = RuntimeSink::with_archive(runtime.clone(), self.archive());
            (runtime, sink)
        }
    }
    impl Drop for ReplayDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn assert_same_receipt(left: &BatchAckData, right: &BatchAckData) {
        assert_eq!(left.attested_sequence, right.attested_sequence);
        assert_eq!(left.head, right.head);
    }

    #[test]
    fn lost_ack_replay_across_sessions_returns_original_receipt_without_new_health_or_chain_position(
    ) {
        use aip_observe::ObserverAttestor;
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        let bytes = batch_bytes("probe-1");
        let first = sink.accept_batch("probe-1", 7, &bytes).unwrap();
        let second = sink
            .accept_batch("probe-1", 8, &batch_bytes("probe-1"))
            .unwrap();
        let archive = std::fs::read(dir.archive()).unwrap();
        let before = rt.lock().unwrap().signer().health(999).unwrap();
        // A new confidential transport session starts its own frame sequence.
        let mut reconnect = sink.clone();
        let retry = reconnect.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_same_receipt(&first, &retry);
        assert_eq!(
            rt.lock().unwrap().snapshot().sequence,
            Some(second.attested_sequence)
        );
        assert_eq!(
            before.health,
            rt.lock().unwrap().signer().health(999).unwrap().health
        );
        assert_eq!(archive, std::fs::read(dir.archive()).unwrap());
    }

    #[test]
    fn collector_restart_rebuilds_ack_only_from_the_trusted_complete_signed_archive() {
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let bytes = batch_bytes("probe-1");
        let first = {
            let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
            let receipt = sink.accept_batch("probe-1", 1, &bytes).unwrap();
            rt.lock().unwrap().health(300).unwrap();
            receipt
        };
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        rt.lock()
            .unwrap()
            .signer_mut()
            .begin_live_coverage_epoch(500);
        sink.initialize_archive().unwrap();
        let retry = sink.accept_batch("probe-1", 1, &bytes).unwrap();
        assert_same_receipt(&first, &retry);
        let health = rt.lock().unwrap().health(600).unwrap();
        assert_eq!(health.health.attested_coverage, None);
        assert_eq!(health.health.state, ObserverState::Recovering);
        assert_eq!(health.health.sequence, first.attested_sequence);
        assert_eq!(
            std::fs::read_to_string(dir.archive())
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[test]
    fn reused_batch_identity_with_changed_content_is_refused_without_poisoning_other_batches() {
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        let bytes = batch_bytes("probe-1");
        sink.accept_batch("probe-1", 1, &bytes).unwrap();
        let mut altered: ObservationBatch = serde_json::from_slice(&bytes).unwrap();
        altered.claimed_to_ms += 1;
        assert!(sink
            .accept_batch("probe-1", 2, &serde_json::to_vec(&altered).unwrap())
            .unwrap_err()
            .0
            .contains("different content"));
        assert_eq!(rt.lock().unwrap().snapshot().sequence, Some(1));
        sink.accept_batch("probe-1", 3, &batch_bytes("probe-1"))
            .unwrap();
        assert_eq!(rt.lock().unwrap().snapshot().sequence, Some(2));
    }

    #[test]
    fn malformed_version_rejection_does_not_poison_the_durable_writer() {
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        sink.initialize_archive().unwrap();
        let mut batch: ObservationBatch = serde_json::from_slice(&batch_bytes("probe-1")).unwrap();
        batch.version = 65535;
        assert!(sink
            .accept_batch("probe-1", 1, &serde_json::to_vec(&batch).unwrap())
            .is_err());
        assert_eq!(rt.lock().unwrap().snapshot().sequence, None);
        sink.accept_batch("probe-1", 2, &batch_bytes("probe-1"))
            .unwrap();
    }

    #[test]
    fn receipt_capacity_refuses_before_signing_and_preserves_earlier_ack_retries() {
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        sink.receipt_limit = 2;
        let bytes = batch_bytes("probe-1");
        let first = sink.accept_batch("probe-1", 1, &bytes).unwrap();
        sink.accept_batch("probe-1", 2, &batch_bytes("probe-1"))
            .unwrap();
        let saved = std::fs::read(dir.archive()).unwrap();
        assert!(sink
            .accept_batch("probe-1", 3, &batch_bytes("probe-1"))
            .unwrap_err()
            .0
            .contains("capacity exhausted"));
        assert_eq!(rt.lock().unwrap().snapshot().sequence, Some(2));
        assert_eq!(saved, std::fs::read(dir.archive()).unwrap());
        assert_same_receipt(&first, &sink.accept_batch("probe-1", 1, &bytes).unwrap());
        assert!(
            ArchiveIndex::load_with_limit(&dir.archive(), &rt.lock().unwrap(), 1)
                .unwrap_err()
                .0
                .contains("capacity exhausted")
        );
    }

    #[test]
    fn torn_archive_is_retained_and_refuses_replay_reconstruction() {
        use std::io::Write;
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        sink.accept_batch("probe-1", 1, &batch_bytes("probe-1"))
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.archive())
            .unwrap()
            .write_all(b"{\"version\":")
            .unwrap();
        let saved = std::fs::read(dir.archive()).unwrap();
        assert!(ArchiveIndex::load_with_limit(
            &dir.archive(),
            &rt.lock().unwrap(),
            MAX_REPLAY_RECEIPTS
        )
        .unwrap_err()
        .0
        .contains("torn"));
        assert_eq!(saved, std::fs::read(dir.archive()).unwrap());
    }

    #[test]
    fn mutated_or_missing_durable_record_cannot_be_acknowledged_from_cache() {
        for delete in [false, true] {
            let dir = ReplayDirectory::new();
            let key = aip_crypto::generate_ed25519_keypair();
            let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
            let bytes = batch_bytes("probe-1");
            sink.accept_batch("probe-1", 1, &bytes).unwrap();
            if delete {
                std::fs::remove_file(dir.archive()).unwrap();
            } else {
                let mut saved = std::fs::read(dir.archive()).unwrap();
                saved[5] ^= 1;
                std::fs::write(dir.archive(), saved).unwrap();
            }
            assert!(sink.accept_batch("probe-1", 1, &bytes).is_err());
            assert!(sink
                .accept_batch("probe-1", 2, &batch_bytes("probe-1"))
                .unwrap_err()
                .0
                .contains("archive failed"));
            assert_eq!(rt.lock().unwrap().snapshot().sequence, Some(1));
        }
    }

    #[test]
    fn rewritten_signed_content_or_truncated_complete_archive_refuses_recovery() {
        for truncate in [false, true] {
            let dir = ReplayDirectory::new();
            let key = aip_crypto::generate_ed25519_keypair();
            let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
            sink.accept_batch("probe-1", 1, &batch_bytes("probe-1"))
                .unwrap();
            sink.accept_batch("probe-1", 2, &batch_bytes("probe-1"))
                .unwrap();
            let data = std::fs::read_to_string(dir.archive()).unwrap();
            let mut records: Vec<AttestedBatch> = data
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            if truncate {
                records.pop();
            } else {
                records[0].batch.claimed_to_ms += 1;
            }
            let data = records
                .iter()
                .map(|r| serde_json::to_string(r).unwrap() + "\n")
                .collect::<String>();
            std::fs::write(dir.archive(), &data).unwrap();
            assert!(ArchiveIndex::load_with_limit(
                &dir.archive(),
                &rt.lock().unwrap(),
                MAX_REPLAY_RECEIPTS
            )
            .is_err());
            assert_eq!(data.as_bytes(), std::fs::read(dir.archive()).unwrap());
        }
    }

    #[test]
    fn failed_archive_append_latches_before_any_retry_can_advance_again() {
        let dir = ReplayDirectory::new();
        let key = aip_crypto::generate_ed25519_keypair();
        let (rt, mut sink) = dir.start(&key.private_key, &key.public_key);
        sink.initialize_archive().unwrap();
        std::fs::create_dir(dir.archive()).unwrap();
        let bytes = batch_bytes("probe-1");
        assert!(sink.accept_batch("probe-1", 1, &bytes).is_err());
        let position = rt.lock().unwrap().snapshot();
        assert!(sink
            .accept_batch("probe-1", 2, &bytes)
            .unwrap_err()
            .0
            .contains("archive failed"));
        assert_eq!(position, rt.lock().unwrap().snapshot());
    }
}
