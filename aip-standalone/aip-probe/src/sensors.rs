//! The probe's sensor set: opens the configured kernel sources — the
//! perf-tracepoint tracers, the netlink process-event connector, the
//! fanotify mount watch and the `AF_PACKET` device tap — and
//! drains them into a [`ProcfsProbe`] each cycle, producing an
//! [`ObservationBatch`]. The probe holds no key; the batch it produces is
//! unsigned and becomes evidence only when the off-host collector attests it.
//!
//! The Linux path drives the real `aip-observe` tracers. On non-Linux the crate
//! still compiles, but [`SensorSet::open`] refuses — the probe is a Linux
//! runtime component and does not pretend otherwise.

use aip_observe::{ObservationBatch, ProcfsProbe};

use crate::config::SensorConfig;

/// Per-poll wait when draining a tracer's ring (milliseconds).
#[cfg(target_os = "linux")]
const POLL_MS: i32 = 5;
/// Cap on each bounded sensor drain, so a burst cannot make a
/// single batch unbounded; the remainder is carried by the next cycle.
#[cfg(target_os = "linux")]
const MAX_EVENTS_PER_DRAIN: u32 = 4096;

// Acquisition grace only: no evidence-validity or coverage decision. Across
// BOTH exec sources this adds at most 256 real events to the initial two
// 4096-event drains (8448 total), at most eight additional drain rounds, and
// a 20 ms elapsed-time budget. Each round gives each source at most 16 events
// before switching, so a sched burst cannot spend the connector's entire
// acquisition opportunity. Reads are nonblocking; the requested idle wait
// is at most 1 ms per round. OS scheduling/measurement can finish late, but no
// further read starts after any budget expires. The existing batch interval
// and each event's original kernel timestamp/sequence remain unchanged.
#[cfg(any(target_os = "linux", test))]
const EXEC_RENDEZVOUS_EVENTS: usize = 256;
#[cfg(any(target_os = "linux", test))]
const EXEC_RENDEZVOUS_ROUNDS: usize = 8;
#[cfg(any(target_os = "linux", test))]
const EXEC_RENDEZVOUS_SOURCE_CHUNK: usize = 16;
#[cfg(any(target_os = "linux", test))]
const EXEC_RENDEZVOUS_TIME: std::time::Duration = std::time::Duration::from_millis(20);

#[cfg(any(target_os = "linux", test))]
fn exec_rendezvous_has_budget(rounds: usize, events: usize, elapsed: std::time::Duration) -> bool {
    rounds < EXEC_RENDEZVOUS_ROUNDS
        && events < EXEC_RENDEZVOUS_EVENTS
        && elapsed < EXEC_RENDEZVOUS_TIME
}

/// Whether the current unsent exec witnesses have their real counterpart in
/// both directions. This private readiness hint only requests more acquisition;
/// it never changes events or decides integrity, attribution or coverage. The
/// collector still applies its existing strict predicate to the actual batch.
#[cfg(any(target_os = "linux", test))]
fn pending_exec_witnesses_paired(events: &[aip_observe::KernelLifecycleEvent]) -> bool {
    use aip_observe::{KernelLifecycleKind, SourceMechanism, DEFAULT_MATCH_WINDOW_NS};
    use std::collections::BTreeMap;

    // Index by the same PID/TGID predicate as the collector, then sort times.
    // Avoid an all-pairs scan when a burst fills the bounded sensor drains.
    let mut witnesses: BTreeMap<(u32, u32), [Vec<u64>; 2]> = BTreeMap::new();
    for event in events {
        let (side, pid, tgid) = match (&event.mechanism, &event.kind) {
            (SourceMechanism::SchedTracepoint, KernelLifecycleKind::ProcessExec { pid, .. }) => {
                (0, *pid, *pid)
            }
            (SourceMechanism::SchedTracepoint, KernelLifecycleKind::Exec { pid, tgid }) => {
                (0, *pid, *tgid)
            }
            (SourceMechanism::ProcConnector, KernelLifecycleKind::Exec { pid, tgid }) => {
                (1, *pid, *tgid)
            }
            _ => continue,
        };
        witnesses.entry((pid, tgid)).or_default()[side].push(event.kernel_timestamp_ns);
    }
    witnesses.values_mut().all(|sides| {
        sides[0].sort_unstable();
        sides[1].sort_unstable();
        let has_counterparts = |source: &[u64], other: &[u64]| {
            source.iter().all(|stamp| {
                let lower = stamp.saturating_sub(DEFAULT_MATCH_WINDOW_NS);
                let upper = stamp.saturating_add(DEFAULT_MATCH_WINDOW_NS);
                let first = other.partition_point(|candidate| *candidate < lower);
                other
                    .get(first)
                    .is_some_and(|candidate| *candidate <= upper)
            })
        };
        has_counterparts(&sides[0], &sides[1]) && has_counterparts(&sides[1], &sides[0])
    })
}

/// Owns the open tracers and the batch-building probe.
pub struct SensorSet {
    probe: ProcfsProbe,
    batch_counter: u64,
    #[cfg(target_os = "linux")]
    process: Option<aip_observe::ProcessTracer>,
    /// Cgroup placement events (ADR-019): decision-cgroup creation, removal
    /// and migration, each with the acting task.
    #[cfg(target_os = "linux")]
    cgroup: Option<aip_observe::CgroupTracer>,
    #[cfg(target_os = "linux")]
    sockstate: Option<aip_observe::SockStateTracer>,
    #[cfg(target_os = "linux")]
    socksend: Option<aip_observe::SockSendTracer>,
    /// The netlink process-event connector: kernel-pushed fork/exec/exit,
    /// not exposed to the per-tracepoint eBPF submission gate. The only
    /// source whose coverage licenses a process-lifecycle non-occurrence
    /// claim. `CAP_NET_ADMIN`.
    #[cfg(target_os = "linux")]
    connector: Option<aip_observe::ProcConnector>,
    /// The fanotify mount watch: kernel-queued file events carrying a pidfd
    /// the kernel made from the event's own process reference. Like the
    /// connector, it is not exposed to the per-tracepoint eBPF submission
    /// gate. `CAP_SYS_ADMIN`.
    #[cfg(target_os = "linux")]
    file: Option<aip_observe::FanotifyWatch>,
    /// The `AF_PACKET` device tap: frame **headers only**, never a payload
    /// byte (I23). Gate-independent for the same reason. The device layer
    /// knows no process, so a wire segment is never bound to an instance —
    /// it is evidence that bytes crossed a device, not that a given process
    /// sent them. `CAP_NET_RAW`.
    #[cfg(target_os = "linux")]
    wire: Option<aip_observe::WireTap>,
}

/// Encode a monotonic counter into a 16-byte batch id (big-endian in the low 8
/// bytes). Distinct per batch within a probe run; the probe's `probe_run_id`
/// separates runs.
fn batch_id_bytes(counter: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[8..].copy_from_slice(&counter.to_be_bytes());
    id
}

/// Names which sensors are open, and nothing else. Useful in a startup log
/// line and in a test failure; it holds descriptors, not secrets, so there
/// is nothing here to redact — but there is also no reason to print a
/// descriptor number.
impl std::fmt::Debug for SensorSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut open: Vec<&str> = Vec::new();
        #[cfg(target_os = "linux")]
        {
            if self.process.is_some() {
                open.push("sched");
            }
            if self.cgroup.is_some() {
                open.push("cgroup");
            }
            if self.sockstate.is_some() {
                open.push("sockstate");
            }
            if self.socksend.is_some() {
                open.push("socksend");
            }
            if self.connector.is_some() {
                open.push("connector");
            }
            if self.file.is_some() {
                open.push("fanotify");
            }
            if self.wire.is_some() {
                open.push("afpacket");
            }
        }
        f.debug_struct("SensorSet")
            .field("open", &open)
            .field("batches", &self.batch_counter)
            .finish()
    }
}

impl SensorSet {
    /// Open every configured sensor. Fails closed: a requested sensor that
    /// cannot be opened (no `CAP_PERFMON`, no tracefs, tracepoint absent) is a
    /// startup error, not a silent downgrade — the operator learns immediately
    /// rather than the probe running blind.
    #[cfg(target_os = "linux")]
    pub fn open(probe_id: &str, cfg: SensorConfig) -> Result<Self, String> {
        use aip_observe::{
            boot_clock_anchor, CgroupTracer, FanotifyWatch, ProcConnector, ProcessTracer,
            SockSendTracer, SockStateTracer, SourceMechanism, WireTap, FAN_CLOSE_WRITE,
        };

        let mut probe = ProcfsProbe::new(probe_id);

        let process = if cfg.sched {
            let t = ProcessTracer::open().map_err(|e| format!("open sched tracer: {e:?}"))?;
            probe.declare_source(SourceMechanism::SchedTracepoint);
            probe.enable_loss_counter();
            Some(t)
        } else {
            None
        };
        let cgroup = if cfg.cgroup {
            let t = CgroupTracer::open().map_err(|e| format!("open cgroup tracer: {e:?}"))?;
            probe.declare_source(SourceMechanism::CgroupTracepoint);
            probe.enable_loss_counter();
            Some(t)
        } else {
            None
        };
        let sockstate = if cfg.sockstate {
            let t = SockStateTracer::open().map_err(|e| format!("open sockstate tracer: {e:?}"))?;
            probe.declare_source(SourceMechanism::SockStateTracepoint);
            probe.enable_loss_counter();
            Some(t)
        } else {
            None
        };
        let socksend = if cfg.socksend {
            let t = SockSendTracer::open().map_err(|e| format!("open socksend tracer: {e:?}"))?;
            probe.declare_source(SourceMechanism::SockSendTracepoint);
            probe.enable_loss_counter();
            Some(t)
        } else {
            None
        };

        let connector = if cfg.connector {
            let c = ProcConnector::open()
                .map_err(|e| format!("open netlink process connector (needs CAP_NET_ADMIN in the initial network namespace): {e}"))?;
            probe.declare_source(SourceMechanism::ProcConnector);
            probe.enable_loss_counter();
            Some(c)
        } else {
            None
        };

        // Filesystem evidence. FAN_CLOSE_WRITE only: one event per completed
        // write-and-close, not one per write (FAN_MODIFY), because the
        // per-write firehose buys nothing the close does not already say and
        // overflows the queue on a busy mount — and an overflow is counted
        // loss, which degrades the epoch.
        let file = if cfg.fanotify {
            let path = cfg.fanotify_path.as_deref().ok_or_else(|| {
                "sensor \"fanotify\" requires AIP_PROBE_FANOTIFY_PATH".to_string()
            })?;
            let w = FanotifyWatch::open(path, FAN_CLOSE_WRITE).map_err(|e| {
                format!("open fanotify mount watch on {path:?} (needs CAP_SYS_ADMIN): {e:?}")
            })?;
            probe.declare_source(SourceMechanism::Fanotify);
            probe.enable_loss_counter();
            Some(w)
        } else {
            None
        };

        // Wire evidence. Headers only; no payload byte is copied, hashed or
        // kept (I23).
        let wire = if cfg.afpacket {
            let iface = cfg.afpacket_interface.as_deref();
            let t = WireTap::open(iface).map_err(|e| {
                format!(
                    "open AF_PACKET tap on {} (needs CAP_NET_RAW): {e:?}",
                    iface.unwrap_or("every device")
                )
            })?;
            probe.declare_source(SourceMechanism::WireTapAfPacket);
            probe.enable_loss_counter();
            Some(t)
        } else {
            None
        };

        if let Ok(anchor) = boot_clock_anchor() {
            probe.declare_clock_anchor(anchor);
        }

        Ok(Self {
            probe,
            batch_counter: 0,
            process,
            cgroup,
            sockstate,
            socksend,
            connector,
            file,
            wire,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_probe_id: &str, _cfg: SensorConfig) -> Result<Self, String> {
        Err("aip-probe requires Linux (perf tracepoints); this build cannot open sensors".into())
    }

    /// Drain the open sensors and build one batch covering `[from_ms, to_ms]`.
    /// Reported ring loss becomes counted loss on the batch; nothing is
    /// inferred to fill a gap.
    pub fn collect_batch(&mut self, from_ms: u64, to_ms: u64) -> ObservationBatch {
        #[cfg(target_os = "linux")]
        {
            use aip_observe::boot_clock_anchor;
            // Re-anchor each cycle so a suspend cannot silently shift the
            // boot↔monotonic relation the collector uses to place events.
            if let Ok(anchor) = boot_clock_anchor() {
                self.probe.declare_clock_anchor(anchor);
            }
            // Drain one tracer into the probe: pull events until the ring is
            // quiet (`Ok(None)`), a source error, or the per-cycle cap; then
            // fold any reported ring loss into counted loss. A `while let Ok`
            // ends the loop on both `Ok(None)` and `Err` — the same terminal
            // behavior as the explicit match, without a busy spin.
            macro_rules! drain_into_probe {
                ($slot:expr, $ingest:ident) => {
                    if let Some(t) = $slot.as_mut() {
                        let mut n: u32 = 0;
                        while let Ok(Some(ev)) = t.next_event(POLL_MS) {
                            self.probe.$ingest(ev);
                            n += 1;
                            if n >= MAX_EVENTS_PER_DRAIN {
                                break;
                            }
                        }
                        let lost = t.take_lost();
                        if lost > 0 {
                            self.probe.record_lost_events(lost);
                        }
                    }
                };
            }
            drain_into_probe!(self.process, ingest_sched_event);
            drain_into_probe!(self.cgroup, ingest_cgroup_event);
            drain_into_probe!(self.sockstate, ingest_socket_event);
            drain_into_probe!(self.socksend, ingest_send_event);
            // The AF_PACKET tap yields the same `ProcEvent` shape as the
            // tracers, so it drains identically; its loss counter is the
            // kernel's own `PACKET_STATISTICS.tp_drops`.
            drain_into_probe!(self.wire, ingest_wire_event);

            // fanotify yields a `FileObservation` (event plus the kernel's
            // pidfd), not a bare `ProcEvent`, so it does not fit the macro.
            // The pidfd is consumed by `ingest_file_event`, which measures
            // through it and applies the start-tick rule; an event whose
            // process had already gone is recorded unbound — existence
            // without identity — rather than guessed at from the pid.
            if let Some(w) = self.file.as_mut() {
                let mut n: u32 = 0;
                while let Ok(Some(obs)) = w.next_event(POLL_MS) {
                    self.probe.ingest_file_event(obs);
                    n += 1;
                    if n >= MAX_EVENTS_PER_DRAIN {
                        break;
                    }
                }
                let lost = w.take_lost();
                if lost > 0 {
                    self.probe.record_lost_events(lost);
                }
            }

            // The connector has no ring and no LOST record: the kernel signals
            // an overflowed receive queue with `ENOBUFS`, surfaced as
            // `SourceError::EventsLost`. How many events were lost is unknown,
            // so the count recorded is a floor of one, and it does what any
            // counted loss does: the collector marks the epoch degraded and
            // the probe forgets its exec-time bindings (a pid may have been
            // recycled across the gap). Nothing is inferred to fill the hole.
            if let Some(c) = self.connector.as_ref() {
                let mut n: u32 = 0;
                loop {
                    match c.next_event(POLL_MS) {
                        Ok(Some(ev)) => {
                            self.probe.ingest_kernel_event(ev);
                            n += 1;
                            if n >= MAX_EVENTS_PER_DRAIN {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(aip_observe::SourceError::EventsLost) => {
                            self.probe.record_lost_events(1);
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }

            // Either source can deliver its counterpart after the other's
            // initial drain. Keep acquiring into this SAME unsent batch for a
            // bounded grace period; never borrow an earlier signed batch or
            // fabricate a match. Exhaustion emits every original event as-is.
            // A connector exec still missing perf is refused by the collector;
            // a perf-only event does not invent a new collector finding.
            if self.process.is_some() && self.connector.is_some() {
                let started = std::time::Instant::now();
                let mut rounds = 0;
                let mut acquired = 0;
                while exec_rendezvous_has_budget(rounds, acquired, started.elapsed())
                    && !pending_exec_witnesses_paired(self.probe.pending_kernel_events())
                {
                    if let Some(t) = self.process.as_mut() {
                        let mut source_events = 0;
                        while source_events < EXEC_RENDEZVOUS_SOURCE_CHUNK
                            && exec_rendezvous_has_budget(rounds, acquired, started.elapsed())
                        {
                            match t.next_event(0) {
                                Ok(Some(event)) => {
                                    self.probe.ingest_sched_event(event);
                                    acquired += 1;
                                    source_events += 1;
                                }
                                Ok(None) | Err(_) => break,
                            }
                        }
                        let lost = t.take_lost();
                        if lost > 0 {
                            self.probe.record_lost_events(lost);
                        }
                    }
                    if let Some(c) = self.connector.as_ref() {
                        let mut source_events = 0;
                        while source_events < EXEC_RENDEZVOUS_SOURCE_CHUNK
                            && exec_rendezvous_has_budget(rounds, acquired, started.elapsed())
                        {
                            match c.next_event(0) {
                                Ok(Some(event)) => {
                                    self.probe.ingest_kernel_event(event);
                                    acquired += 1;
                                    source_events += 1;
                                }
                                Ok(None) => break,
                                Err(aip_observe::SourceError::EventsLost) => {
                                    self.probe.record_lost_events(1);
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    rounds += 1;
                    if exec_rendezvous_has_budget(rounds, acquired, started.elapsed())
                        && !pending_exec_witnesses_paired(self.probe.pending_kernel_events())
                    {
                        std::thread::sleep(
                            std::time::Duration::from_millis(1)
                                .min(EXEC_RENDEZVOUS_TIME.saturating_sub(started.elapsed())),
                        );
                    }
                }
            }

            // Integrity check for every open perf-tracepoint sensor, every
            // cycle, carried in the batch. A foreign eBPF program on a sampled
            // tracepoint suppresses events host-wide with no loss accounting;
            // the collector — on another host, holding the key — can only
            // sign `IntegrityUnknown` if this probe tells it. A refused query
            // is reported as `Unverifiable`, which the collector treats like
            // a found gate. Nothing here is signed: it is a probe claim the
            // collector can lower the state on, never raise it.
            use aip_observe::SourceMechanism;
            if let Some(t) = self.process.as_ref() {
                self.probe.declare_mechanism_integrity(
                    SourceMechanism::SchedTracepoint,
                    t.mechanism_integrity(),
                );
            }
            if let Some(t) = self.cgroup.as_ref() {
                self.probe.declare_mechanism_integrity(
                    SourceMechanism::CgroupTracepoint,
                    t.mechanism_integrity(),
                );
            }
            if let Some(t) = self.sockstate.as_ref() {
                self.probe.declare_mechanism_integrity(
                    SourceMechanism::SockStateTracepoint,
                    t.mechanism_integrity(),
                );
            }
            if let Some(t) = self.socksend.as_ref() {
                self.probe.declare_mechanism_integrity(
                    SourceMechanism::SockSendTracepoint,
                    t.mechanism_integrity(),
                );
            }
            // fanotify and the AF_PACKET tap get no integrity report, and
            // owe none: neither reaches the probe through a perf tracepoint,
            // so neither is exposed to the per-tracepoint eBPF submission
            // gate that the reports above exist to detect
            // (`SourceMechanism::shares_perf_tracepoint_gate` is false for
            // both, and the collector's sink asks for a report only for the
            // mechanisms where it is true). Declaring a finding for them
            // would be inventing a check that was never run.
        }
        let _ = (from_ms, to_ms);
        self.batch_counter += 1;
        self.probe
            .batch(batch_id_bytes(self.batch_counter), from_ms, to_ms, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{
        AgentAttribution, CgroupSample, KernelLifecycleEvent, KernelLifecycleKind, SourceMechanism,
        DEFAULT_MATCH_WINDOW_NS, OBSERVE_PROTOCOL_VERSION,
    };

    fn event(
        mechanism: SourceMechanism,
        kind: KernelLifecycleKind,
        stamp: u64,
    ) -> KernelLifecycleEvent {
        KernelLifecycleEvent {
            version: OBSERVE_PROTOCOL_VERSION,
            probe_id: "acquisition-readiness-test".into(),
            mechanism,
            kind,
            cpu: 0,
            kernel_timestamp_ns: stamp,
            probe_seq: stamp,
            bound: None,
            attribution: AgentAttribution::NotEstablished,
            claimed_decision_id: None,
            cgroup: CgroupSample::NotSampled,
        }
    }

    fn sched(pid: u32, stamp: u64) -> KernelLifecycleEvent {
        event(
            SourceMechanism::SchedTracepoint,
            KernelLifecycleKind::ProcessExec {
                pid,
                old_pid: pid + 100,
                filename: "/test/real-event-shape".into(),
            },
            stamp,
        )
    }

    fn connector(pid: u32, tgid: u32, stamp: u64) -> KernelLifecycleEvent {
        event(
            SourceMechanism::ProcConnector,
            KernelLifecycleKind::Exec { pid, tgid },
            stamp,
        )
    }

    #[test]
    fn sched_first_waits_for_actual_connector_without_rewriting_events() {
        let first = sched(42, 95_977_404_365);
        let mut pending = vec![first.clone()];
        assert!(!pending_exec_witnesses_paired(&pending));
        pending.push(connector(42, 42, 95_977_410_203));
        let originals = pending.clone();
        assert!(pending_exec_witnesses_paired(&pending));
        assert_eq!(pending, originals);
        assert_eq!(pending[0], first);
    }

    #[test]
    fn connector_first_waits_for_actual_sched_and_each_extra_exec() {
        let mut pending = vec![connector(42, 42, 100)];
        assert!(!pending_exec_witnesses_paired(&pending));
        pending.push(sched(42, 99));
        assert!(pending_exec_witnesses_paired(&pending));
        pending.push(sched(43, 110));
        assert!(!pending_exec_witnesses_paired(&pending));
        pending.push(connector(43, 43, 111));
        assert!(pending_exec_witnesses_paired(&pending));
    }

    #[test]
    fn wrong_pid_or_tgid_never_satisfies_readiness() {
        for other in [connector(43, 43, 100), connector(42, 43, 100)] {
            assert!(!pending_exec_witnesses_paired(&[sched(42, 100), other]));
        }
    }

    #[test]
    fn uses_existing_timestamp_window_without_expanding_it() {
        let stamp = DEFAULT_MATCH_WINDOW_NS + 10;
        assert!(pending_exec_witnesses_paired(&[
            sched(42, stamp),
            connector(42, 42, stamp + DEFAULT_MATCH_WINDOW_NS),
        ]));
        assert!(!pending_exec_witnesses_paired(&[
            sched(42, stamp),
            connector(42, 42, stamp + DEFAULT_MATCH_WINDOW_NS + 1),
        ]));
    }

    #[test]
    fn missing_witness_remains_unready_and_no_exec_requires_no_wait() {
        let pending = vec![connector(42, 42, 100)];
        for _ in 0..EXEC_RENDEZVOUS_ROUNDS {
            assert!(!pending_exec_witnesses_paired(&pending));
        }
        assert_eq!(pending.len(), 1);
        assert!(pending_exec_witnesses_paired(&[]));
        assert!(pending_exec_witnesses_paired(&[event(
            SourceMechanism::ProcConnector,
            KernelLifecycleKind::Exit {
                pid: 42,
                tgid: 42,
                exit_code: 0,
                exit_signal: 0
            },
            100,
        )]));
    }

    #[test]
    fn exhaustion_preserves_original_batch_and_collector_still_requires_witness() {
        use aip_observe::{detect_cross_sensor_divergence_default, MechanismIntegrity, ProcEvent};

        let mut probe = ProcfsProbe::new("acquisition-unit-fixture");
        probe.declare_source(SourceMechanism::SchedTracepoint);
        probe.declare_source(SourceMechanism::ProcConnector);
        probe.enable_loss_counter();
        probe.ingest_kernel_event(ProcEvent {
            kind: KernelLifecycleKind::Exec { pid: 42, tgid: 42 },
            cpu: 0,
            timestamp_ns: 95_977_410_203,
            cgroup: CgroupSample::NotSampled,
        });
        let originals = probe.pending_kernel_events().to_vec();
        assert!(!pending_exec_witnesses_paired(&originals));
        assert!(!exec_rendezvous_has_budget(
            EXEC_RENDEZVOUS_ROUNDS,
            EXEC_RENDEZVOUS_EVENTS,
            EXEC_RENDEZVOUS_TIME,
        ));
        // Two unit scenarios from the same unsent fixture. Neither batch is
        // signed; no previous attested batch contributes a matching witness.
        let exhausted = probe.clone().batch([1; 16], 1, 2, vec![]);
        assert_eq!(exhausted.kernel_events, originals);
        let reports = detect_cross_sensor_divergence_default(&exhausted).integrity_reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].mechanism, SourceMechanism::SchedTracepoint);
        assert_eq!(reports[0].integrity, MechanismIntegrity::Unverifiable);

        probe.ingest_sched_event(ProcEvent {
            kind: KernelLifecycleKind::ProcessExec {
                pid: 42,
                old_pid: 142,
                filename: "/test/real-event-shape".into(),
            },
            cpu: 0,
            timestamp_ns: 95_977_404_365,
            cgroup: CgroupSample::NotSampled,
        });
        assert!(pending_exec_witnesses_paired(probe.pending_kernel_events()));
        let paired = probe.batch([2; 16], 1, 2, vec![]);
        assert_eq!(paired.kernel_events.len(), 2);
        assert_eq!(paired.kernel_events[0], originals[0]);
        assert_eq!(paired.kernel_events[1].kernel_timestamp_ns, 95_977_404_365);
        assert!(detect_cross_sensor_divergence_default(&paired).is_empty());
    }

    #[test]
    fn acquisition_stops_at_each_aggregate_budget_boundary() {
        assert_eq!(
            EXEC_RENDEZVOUS_SOURCE_CHUNK * 2 * EXEC_RENDEZVOUS_ROUNDS,
            EXEC_RENDEZVOUS_EVENTS
        );
        let before = EXEC_RENDEZVOUS_TIME - std::time::Duration::from_nanos(1);
        assert!(exec_rendezvous_has_budget(
            EXEC_RENDEZVOUS_ROUNDS - 1,
            EXEC_RENDEZVOUS_EVENTS - 1,
            before,
        ));
        assert!(!exec_rendezvous_has_budget(
            EXEC_RENDEZVOUS_ROUNDS,
            0,
            before
        ));
        assert!(!exec_rendezvous_has_budget(
            0,
            EXEC_RENDEZVOUS_EVENTS,
            before
        ));
        assert!(!exec_rendezvous_has_budget(0, 0, EXEC_RENDEZVOUS_TIME));
        assert!(!pending_exec_witnesses_paired(&[connector(42, 42, 100)]));
    }
}
