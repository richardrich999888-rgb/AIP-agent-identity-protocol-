//! aip-observe — Ghost Stage 3: independent observation and attestation.
//!
//! This crate answers exactly one question:
//!
//! ```text
//! What execution-related fact did an independently keyed observer actually
//! record, and over what interval can it vouch for its own coverage?
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
//! - It does **not** contain, kill, quarantine a workload, or touch the
//!   network. The only "quarantine" here is [`ObserverState::Quarantined`],
//!   a statement about the *observer's own* integrity.
//!
//! # The split that carries the security property
//!
//! ```text
//!   observed host (attacker reach)          off-host collector
//!   ────────────────────────────────        ──────────────────────────────
//!   ProcfsProbe        no key               CollectorSigner   holds the key
//!     │ measures procfs                       │ assigns sequence + prev_head
//!     ▼                                       │ enforces continuity ledger
//!   ObservationBatch  (unsigned) ──────────▶  ▼
//!                                           AttestedBatch  (signed)
//! ```
//!
//! [`ObservationBatch`] has no signature field; [`ProcfsProbe`] has no key
//! field and no signing method; the chain position and head are collector
//! state, so a wiped or rolled-back host cannot re-assert a place in attested
//! history — it can only produce a discontinuity the collector will see.
//!
//! # What an attestation does and does not mean
//!
//! A verified [`AttestedBatch`] means: *the trusted observer signed exactly
//! these bytes at this position in its chain*. It does **not** mean the
//! observations are true — a root-compromised host can lie to its own probe —
//! nor that the interval was continuously covered. Coverage is a separate,
//! explicit question answered by [`SignedSensorHealth::availability_for`].

pub mod attest;
pub mod continuity;
pub mod health;
pub mod observed;
pub mod probe;

pub use attest::{
    verify_attested_batch, verify_attested_batch_independent_of_agent, verify_signed_health,
    AttestError, AttestedBatch, CollectorSigner, ObserverAttestor, ObserverTrustAnchors,
    VerifyError, OBSERVER_HEAD_DOMAIN,
};
pub use continuity::{Admission, ContinuityFault, ObserverLedger};
pub use health::{
    no_observer, ContinuityStatus, CoverageWindow, ObservationAvailability, ObserverState,
    SensorHealth, SignedSensorHealth, UnavailableReason, OBSERVER_HEALTH_DOMAIN,
};
pub use observed::{
    AgentAttribution, ObservationBatch, ObservedEffect, ObservedExecution, ObservedProcess,
    OBSERVATION_BATCH_DOMAIN, OBSERVED_EXECUTION_DOMAIN, OBSERVED_PROCESS_DOMAIN,
    OBSERVE_PROTOCOL_VERSION,
};
pub use probe::{AgentClaim, ProbeError, ProcfsProbe};
