//! aip-observe — Ghost Stage 3 (independent observation and attestation) and
//! Stage 6.5 (Sniffer Dog: kernel-mediated evidence sources).
//!
//! This crate answers exactly one question:
//!
//! ```text
//! What execution-related fact did an independently keyed observer actually
//! record, how did it obtain it, and over what interval can it vouch for its
//! own coverage?
//! ```
//!
//! # What it is not
//!
//! - It does **not** decide whether anything was permitted. There is no
//!   `permitted`, `authorized`, `allowed`, `safe` or `malicious` field
//!   anywhere in the crate, and no type from `aip-authorize` is imported
//!   (I19, I22).
//! - It does **not** reconcile. It emits no `VERIFIED_EXECUTION`,
//!   `PHANTOM_CLAIM`, `CANNOT_PROVE` or any other result class; those belong
//!   to Stage 4.
//! - It does **not** classify anything as malicious, and it never converts
//!   missing telemetry into a statement that an execution did not occur
//!   (I8). Missing coverage is [`ObservationAvailability::Unavailable`].
//! - It does **not** contain, kill, quarantine a workload, filter, or drop
//!   traffic. The only "quarantine" here is [`ObserverState::Quarantined`],
//!   a statement about the *observer's own* integrity.
//!
//! # The split that carries the security property
//!
//! ```text
//!   observed host (attacker reach)              off-host collector
//!   ──────────────────────────────────          ──────────────────────────────
//!   ProcfsProbe          no key                 CollectorSigner   holds the key
//!     · procfs poll                               · probe registry: which probe
//!     · pidfd-anchored read                         may claim which mechanism
//!     · kernel proc-connector events              · assigns sequence + prev_head
//!     · kernel socket tables                      · enforces continuity ledger
//!     │                                           · tracks probe run / seq / loss
//!     ▼                                           ▼
//!   ObservationBatch  (unsigned) ─────────────▶ AttestedBatch  (signed)
//! ```
//!
//! [`ObservationBatch`] has no signature field; [`ProcfsProbe`] has no key
//! field and no signing method; chain position, head and the probe registry
//! are collector state. A wiped or rolled-back host cannot re-assert a place
//! in attested history, and cannot label its own report as kernel-sourced.
//!
//! # What an attestation does and does not mean
//!
//! A verified [`AttestedBatch`] means: *the trusted observer signed exactly
//! these bytes at this position in its chain, from a probe it recognises,
//! claiming only mechanisms that probe was provisioned for*. It does **not**
//! mean the observations are true — a root-compromised host can still lie to
//! its own probe about procfs content — nor that the interval was
//! continuously covered. Coverage is a separate, explicit question answered
//! by [`SignedSensorHealth::availability_for`]. Kernel-pushed events
//! ([`KernelLifecycleEvent`]) narrow the lie: their existence, order, CPU and
//! kernel timestamp come from the kernel, not from a procfs read.

pub mod attest;
pub mod continuity;
pub mod health;
pub mod linux;
pub mod observed;
pub mod perf;
pub mod probe;
pub mod sched;
pub mod sockstate;
pub mod wiretap;

pub use attest::{
    verify_attested_batch, verify_attested_batch_independent_of_agent, verify_continuity,
    verify_signed_health, AttestError, AttestedBatch, CollectorSigner, CollectorSnapshot,
    ObserverAttestor, ObserverTrustAnchors, ProbeStreamFault, VerifyError, OBSERVER_HEAD_DOMAIN,
};
pub use continuity::{Admission, ContinuityBreak, ContinuityFault, ObserverLedger};
pub use health::{
    no_observer, ContinuityStatus, CoverageWindow, ObservationAvailability, ObserverState,
    ProbePolicy, SensorHealth, SignedSensorHealth, UnavailableReason, OBSERVER_HEALTH_DOMAIN,
};
pub use linux::{
    parse_proc_event, parse_proc_net_table, parse_socket_link, ProcEvent, SocketRecord, SourceError,
};
#[cfg(target_os = "linux")]
pub use linux::{snapshot_socket_tables, socket_inodes_of, PidFd, ProcConnector};
pub use observed::{
    tcp_flags, tcp_state, AgentAttribution, BootClockAnchor, KernelLifecycleEvent,
    KernelLifecycleKind, ObservationBatch, ObservedEffect, ObservedExecution, ObservedProcess,
    SocketEndpoint, SocketProtocol, SourceMechanism, WireDirection, KERNEL_EVENT_DOMAIN,
    OBSERVATION_BATCH_DOMAIN, OBSERVED_EXECUTION_DOMAIN, OBSERVED_PROCESS_DOMAIN,
    OBSERVE_PROTOCOL_VERSION,
};
#[cfg(target_os = "linux")]
pub use perf::PerfTracepoints;
pub use perf::{data_loc, decode_sample, RawFormat, RawSample, TraceField};
#[cfg(target_os = "linux")]
pub use probe::AnchoredMeasurement;
pub use probe::{clk_tck, instance_started_no_later_than, AgentClaim, ProbeError, ProcfsProbe};
#[cfg(target_os = "linux")]
pub use sched::ProcessTracer;
pub use sched::{parse_exec_record, parse_fork_record, EXEC_TRACEPOINT, FORK_TRACEPOINT};
#[cfg(target_os = "linux")]
pub use sockstate::{boot_clock_anchor, SockStateTracer};
pub use sockstate::{parse_sock_state_record, TracepointFormat, SOCK_STATE_TRACEPOINT};
pub use wiretap::parse_wire_frame;
#[cfg(target_os = "linux")]
pub use wiretap::WireTap;
