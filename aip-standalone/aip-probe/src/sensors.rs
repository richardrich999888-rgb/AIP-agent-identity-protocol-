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
        #[cfg(target_os = "linux")]
        let mut open: Vec<&str> = Vec::new();
        #[cfg(not(target_os = "linux"))]
        let open: Vec<&str> = Vec::new();
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

        if probe_id.is_empty() || probe_id.len() > 256 {
            return Err("probe id must contain 1..256 bytes".into());
        }
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
        // Capture the common cutoff BEFORE any source is drained. Keep one
        // existing match window of delivery holdback; this delays publication,
        // not the workload's start/end or the collector's matching rule.
        #[cfg(target_os = "linux")]
        let cutoff = aip_observe::boot_clock_anchor().ok().map(|anchor| {
            self.probe.declare_clock_anchor(anchor);
            anchor
                .monotonic_ns
                .saturating_sub(aip_observe::divergence::DEFAULT_MATCH_WINDOW_NS)
        });
        #[cfg(not(target_os = "linux"))]
        let cutoff = None;
        #[cfg(target_os = "linux")]
        {
            use aip_observe::SourceMechanism;
            // Drain one tracer into the probe: pull events until the ring is
            // quiet (`Ok(None)`), a source error, or the per-cycle cap; then
            // fold any reported ring loss into counted loss. An error or cap
            // is not an empty queue: it explicitly withdraws capability.
            macro_rules! drain_into_probe {
                ($slot:expr, $ingest:ident, $mechanism:expr) => {
                    if let Some(t) = $slot.as_mut() {
                        let mut n: u32 = 0;
                        let mut drained = false;
                        loop {
                            if !self.probe.live_event_capacity_available() {
                                self.probe.record_source_fault($mechanism);
                                break;
                            }
                            match t.next_event(POLL_MS) {
                                Ok(Some(ev)) => {
                                    self.probe.$ingest(ev);
                                    n += 1;
                                    if n >= MAX_EVENTS_PER_DRAIN {
                                        self.probe.record_source_fault($mechanism);
                                        break;
                                    }
                                }
                                Ok(None) => {
                                    drained = true;
                                    break;
                                }
                                Err(_) => {
                                    self.probe.record_source_fault($mechanism);
                                    break;
                                }
                            }
                        }
                        let lost = t.take_lost();
                        if lost > 0 {
                            self.probe.record_lost_events(lost);
                        }
                        if !$mechanism.shares_perf_tracepoint_gate() && drained && lost == 0 {
                            self.probe.declare_mechanism_integrity(
                                $mechanism,
                                aip_observe::MechanismIntegrity::Verified,
                            );
                        }
                    }
                };
            }
            drain_into_probe!(
                self.process,
                ingest_sched_event,
                SourceMechanism::SchedTracepoint
            );
            drain_into_probe!(
                self.cgroup,
                ingest_cgroup_event,
                SourceMechanism::CgroupTracepoint
            );
            drain_into_probe!(
                self.sockstate,
                ingest_socket_event,
                SourceMechanism::SockStateTracepoint
            );
            drain_into_probe!(
                self.socksend,
                ingest_send_event,
                SourceMechanism::SockSendTracepoint
            );
            // The AF_PACKET tap yields the same `ProcEvent` shape as the
            // tracers, so it drains identically; its loss counter is the
            // kernel's own `PACKET_STATISTICS.tp_drops`.
            drain_into_probe!(
                self.wire,
                ingest_wire_event,
                SourceMechanism::WireTapAfPacket
            );

            // fanotify yields a `FileObservation` (event plus the kernel's
            // pidfd), not a bare `ProcEvent`, so it does not fit the macro.
            // The pidfd is consumed by `ingest_file_event`, which measures
            // through it and applies the start-tick rule; an event whose
            // process had already gone is recorded unbound — existence
            // without identity — rather than guessed at from the pid.
            if let Some(w) = self.file.as_mut() {
                let mut n: u32 = 0;
                let mut drained = false;
                loop {
                    if !self.probe.live_event_capacity_available() {
                        self.probe.record_source_fault(SourceMechanism::Fanotify);
                        break;
                    }
                    match w.next_event(POLL_MS) {
                        Ok(Some(obs)) => {
                            self.probe.ingest_file_event(obs);
                            n += 1;
                            if n >= MAX_EVENTS_PER_DRAIN {
                                self.probe.record_source_fault(SourceMechanism::Fanotify);
                                break;
                            }
                        }
                        Ok(None) => {
                            drained = true;
                            break;
                        }
                        Err(_) => {
                            self.probe.record_source_fault(SourceMechanism::Fanotify);
                            break;
                        }
                    }
                }
                let lost = w.take_lost();
                if lost > 0 {
                    self.probe.record_lost_events(lost);
                }
                if drained && lost == 0 {
                    self.probe.declare_mechanism_integrity(
                        SourceMechanism::Fanotify,
                        aip_observe::MechanismIntegrity::Verified,
                    );
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
                let mut drained = false;
                loop {
                    if !self.probe.live_event_capacity_available() {
                        self.probe
                            .record_source_fault(SourceMechanism::ProcConnector);
                        break;
                    }
                    match c.next_event(POLL_MS) {
                        Ok(Some(ev)) => {
                            self.probe.ingest_kernel_event(ev);
                            n += 1;
                            if n >= MAX_EVENTS_PER_DRAIN {
                                self.probe
                                    .record_source_fault(SourceMechanism::ProcConnector);
                                break;
                            }
                        }
                        Ok(None) => {
                            drained = true;
                            break;
                        }
                        Err(aip_observe::SourceError::EventsLost) => {
                            self.probe.record_lost_events(1);
                            self.probe
                                .record_source_fault(SourceMechanism::ProcConnector);
                            break;
                        }
                        Err(_) => {
                            self.probe
                                .record_source_fault(SourceMechanism::ProcConnector);
                            break;
                        }
                    }
                }
                if drained {
                    self.probe.declare_mechanism_integrity(
                        SourceMechanism::ProcConnector,
                        aip_observe::MechanismIntegrity::Verified,
                    );
                }
            }

            // An exec can arrive after the first sched drain but before the
            // connector drain. Its connector notification is then already in
            // this batch while its earlier perf sample is still in the ring.
            // Drain sched once more before the collector's strict same-batch
            // comparison. This is bounded by the same per-sensor cap; a
            // missing sample still produces Unverifiable, never a match.
            drain_into_probe!(
                self.process,
                ingest_sched_event,
                SourceMechanism::SchedTracepoint
            );

            // Integrity check for every open perf-tracepoint sensor, every
            // cycle, carried in the batch. A foreign eBPF program on a sampled
            // tracepoint suppresses events host-wide with no loss accounting;
            // the collector — on another host, holding the key — can only
            // sign `IntegrityUnknown` if this probe tells it. A refused query
            // is reported as `Unverifiable`, which the collector treats like
            // a found gate. Nothing here is signed: it is a probe claim the
            // collector can lower the state on, never raise it.
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
            // Non-perf sources report only completed loss-free queue reads
            // above, never an invented foreign-tracepoint query. A read/cap
            // fault overrides these readings in batch_through; a later fully
            // drained cycle can explicitly recover without backfilling it.
        }
        self.batch_counter += 1;
        self.probe
            .batch_through(batch_id_bytes(self.batch_counter), from_ms, to_ms, cutoff)
    }
}
