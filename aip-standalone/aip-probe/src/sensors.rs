//! The probe's sensor set: opens the configured perf-tracepoint sources and
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
/// Cap on events drained from one sensor per cycle, so a burst cannot make a
/// single batch unbounded; the remainder is carried by the next cycle.
#[cfg(target_os = "linux")]
const MAX_EVENTS_PER_SENSOR: u32 = 4096;

/// Owns the open tracers and the batch-building probe.
pub struct SensorSet {
    probe: ProcfsProbe,
    batch_counter: u64,
    #[cfg(target_os = "linux")]
    process: Option<aip_observe::ProcessTracer>,
    #[cfg(target_os = "linux")]
    sockstate: Option<aip_observe::SockStateTracer>,
    #[cfg(target_os = "linux")]
    socksend: Option<aip_observe::SockSendTracer>,
}

/// Encode a monotonic counter into a 16-byte batch id (big-endian in the low 8
/// bytes). Distinct per batch within a probe run; the probe's `probe_run_id`
/// separates runs.
fn batch_id_bytes(counter: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[8..].copy_from_slice(&counter.to_be_bytes());
    id
}

impl SensorSet {
    /// Open every configured sensor. Fails closed: a requested sensor that
    /// cannot be opened (no `CAP_PERFMON`, no tracefs, tracepoint absent) is a
    /// startup error, not a silent downgrade — the operator learns immediately
    /// rather than the probe running blind.
    #[cfg(target_os = "linux")]
    pub fn open(probe_id: &str, cfg: SensorConfig) -> Result<Self, String> {
        use aip_observe::{
            boot_clock_anchor, ProcessTracer, SockSendTracer, SockStateTracer, SourceMechanism,
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

        if let Ok(anchor) = boot_clock_anchor() {
            probe.declare_clock_anchor(anchor);
        }

        Ok(Self {
            probe,
            batch_counter: 0,
            process,
            sockstate,
            socksend,
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
                            if n >= MAX_EVENTS_PER_SENSOR {
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
            drain_into_probe!(self.sockstate, ingest_socket_event);
            drain_into_probe!(self.socksend, ingest_send_event);
        }
        let _ = (from_ms, to_ms);
        self.batch_counter += 1;
        self.probe
            .batch(batch_id_bytes(self.batch_counter), from_ms, to_ms, vec![])
    }
}
