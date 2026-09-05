//! Observer health, continuity state, and observation availability.
//!
//! Health is security state, not logging metadata (I9). It is signed by the
//! collector, and its **absence reduces coverage — it never extends it**.

use aip_crypto::sha256;
use aip_types::canonical::*;
use aip_types::Signature;
use serde::{Deserialize, Serialize};

/// Domain tag leading the canonical encoding of [`SensorHealth`].
pub const OBSERVER_HEALTH_DOMAIN: &str = "SYNTRIASS/GHOST/OBSERVER_HEALTH/v1";

/// The five mandatory observer states (OBSERVER_ATTESTATION.md §5, I9).
///
/// Only `Active` permits an observation to be used at `Attested` strength.
/// Every other state yields `OBSERVATION_UNAVAILABLE` for the affected
/// window — which is an epistemic limitation, never a verdict about whether
/// an execution occurred (I8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObserverState {
    /// Live, and continuity verified across the window.
    Active,
    /// Live, but with a known gap, drop, or coverage defect.
    Degraded,
    /// Restarted; continuity not yet re-established.
    Recovering,
    /// Resumed with no verifiable link to prior attested state.
    ContinuityUnverified,
    /// Integrity failure proven arithmetically (e.g. two distinct attested
    /// batches at the same sequence under the same key).
    Quarantined,
}

impl ObserverState {
    fn code(&self) -> u8 {
        match self {
            ObserverState::Active => 0x01,
            ObserverState::Degraded => 0x02,
            ObserverState::Recovering => 0x03,
            ObserverState::ContinuityUnverified => 0x04,
            ObserverState::Quarantined => 0x05,
        }
    }

    /// May observations inside the covered window be used at `Attested`
    /// strength? True only for `Active`. This crate does not define evidence
    /// strength (that is Stage 5); the predicate exists so no caller has to
    /// re-derive the rule and get it wrong.
    pub fn permits_attested_use(&self) -> bool {
        matches!(self, ObserverState::Active)
    }
}

/// The interval an observation covers. Half-open is avoided deliberately:
/// both ends are inclusive, matching the R10 convention used since Stage 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageWindow {
    pub from_ms: u64,
    pub to_ms: u64,
}

impl CoverageWindow {
    pub fn contains(&self, t_ms: u64) -> bool {
        t_ms >= self.from_ms && t_ms <= self.to_ms
    }

    pub fn covers(&self, other: &CoverageWindow) -> bool {
        other.from_ms >= self.from_ms && other.to_ms <= self.to_ms
    }
}

/// Why coverage could not be established. Each variant is an epistemic
/// statement about the observer, never about the workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnavailableReason {
    /// No observer has ever attested for this subject.
    NoObserver,
    /// The observer is alive but degraded over the window.
    ObserverDegraded,
    /// The observer restarted and has not re-established continuity.
    ObserverRecovering,
    /// The observer resumed without a verifiable link to prior state.
    ContinuityUnverified,
    /// The observer's integrity failed arithmetically.
    ObserverQuarantined,
    /// The observer is healthy but the requested window falls outside what
    /// it attested to.
    WindowNotCovered,
    /// The most recent signed health is older than the caller's freshness
    /// bound; silence must shrink coverage, not extend it.
    HealthStale { newest_ms: u64, required_ms: u64 },
}

/// The answer to "was this window observed?".
///
/// `Unavailable` means the observer cannot vouch for the window. It does
/// **not** mean nothing happened. Nothing in this crate can produce a
/// `PHANTOM_CLAIM`; that classification requires attested coverage and is
/// the reconciler's to make (I8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationAvailability {
    Covered { window: CoverageWindow },
    Unavailable { reason: UnavailableReason },
}

impl ObservationAvailability {
    pub fn is_covered(&self) -> bool {
        matches!(self, ObservationAvailability::Covered { .. })
    }
}

/// Continuity status as of the last admitted batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuityStatus {
    /// Every batch since the epoch start chained to its predecessor.
    Verified,
    /// A sequence gap was admitted; the missing interval is not covered.
    GapObserved,
    /// The chain link could not be verified.
    Unverified,
    /// A fork was proven under one key at one sequence.
    Broken,
}

/// Whether the collector accepts batches from any probe id or only from
/// probes an operator registered (with the mechanisms each may claim).
///
/// `Open` is the Stage 3 behaviour and is only acceptable where the
/// probe→collector transport is itself authenticated; it is recorded in every
/// signed health record so a verifier can see which regime produced the
/// evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbePolicy {
    Open,
    RegisteredOnly,
}

impl ProbePolicy {
    fn code(&self) -> u8 {
        match self {
            ProbePolicy::Open => 0x01,
            ProbePolicy::RegisteredOnly => 0x02,
        }
    }
}

/// Signed statement of the observer's own condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorHealth {
    pub version: u16,
    pub observer_id: String,
    pub key_version: u32,
    pub state: ObserverState,
    pub continuity: ContinuityStatus,
    pub probe_policy: ProbePolicy,
    /// Sequence of the last admitted batch (0 when none).
    pub sequence: u64,
    /// Head of the last admitted batch (`[0u8;32]` when none).
    pub head: [u8; 32],
    pub last_batch_id: Option<[u8; 16]>,
    /// The interval the collector is prepared to vouch for.
    pub attested_coverage: Option<CoverageWindow>,
    /// Collector wall clock when this health was emitted.
    pub emitted_at_ms: u64,
}

impl SensorHealth {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, OBSERVER_HEALTH_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.observer_id);
        put_u32(&mut buf, self.key_version);
        put_u8(&mut buf, self.state.code());
        put_u8(
            &mut buf,
            match self.continuity {
                ContinuityStatus::Verified => 0x01,
                ContinuityStatus::GapObserved => 0x02,
                ContinuityStatus::Unverified => 0x03,
                ContinuityStatus::Broken => 0x04,
            },
        );
        put_u8(&mut buf, self.probe_policy.code());
        put_u64(&mut buf, self.sequence);
        buf.extend_from_slice(&self.head);
        match &self.last_batch_id {
            Some(b) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(b);
            }
            None => put_u8(&mut buf, 0),
        }
        match &self.attested_coverage {
            Some(w) => {
                put_u8(&mut buf, 1);
                put_u64(&mut buf, w.from_ms);
                put_u64(&mut buf, w.to_ms);
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.emitted_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// [`SensorHealth`] plus the collector's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSensorHealth {
    pub health: SensorHealth,
    pub attestation: Signature,
}

impl SignedSensorHealth {
    /// Availability for `window`, given a freshness bound on health itself.
    ///
    /// `now_ms` and `max_health_age_ms` are supplied by the caller; this
    /// function never reads a clock.
    pub fn availability_for(
        &self,
        window: &CoverageWindow,
        now_ms: u64,
        max_health_age_ms: u64,
    ) -> ObservationAvailability {
        let stale = now_ms.saturating_sub(self.health.emitted_at_ms) > max_health_age_ms;
        if stale {
            return ObservationAvailability::Unavailable {
                reason: UnavailableReason::HealthStale {
                    newest_ms: self.health.emitted_at_ms,
                    required_ms: now_ms.saturating_sub(max_health_age_ms),
                },
            };
        }
        let reason = match self.health.state {
            ObserverState::Degraded => Some(UnavailableReason::ObserverDegraded),
            ObserverState::Recovering => Some(UnavailableReason::ObserverRecovering),
            ObserverState::ContinuityUnverified => Some(UnavailableReason::ContinuityUnverified),
            ObserverState::Quarantined => Some(UnavailableReason::ObserverQuarantined),
            ObserverState::Active => None,
        };
        if let Some(reason) = reason {
            return ObservationAvailability::Unavailable { reason };
        }
        match self.health.attested_coverage {
            Some(attested) if attested.covers(window) => {
                ObservationAvailability::Covered { window: *window }
            }
            _ => ObservationAvailability::Unavailable {
                reason: UnavailableReason::WindowNotCovered,
            },
        }
    }
}

/// Availability when no observer exists at all.
pub fn no_observer() -> ObservationAvailability {
    ObservationAvailability::Unavailable {
        reason: UnavailableReason::NoObserver,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_active_permits_attested_use() {
        assert!(ObserverState::Active.permits_attested_use());
        for s in [
            ObserverState::Degraded,
            ObserverState::Recovering,
            ObserverState::ContinuityUnverified,
            ObserverState::Quarantined,
        ] {
            assert!(!s.permits_attested_use(), "{s:?} must not be Attested");
        }
    }

    #[test]
    fn state_codes_are_distinct() {
        let codes: Vec<u8> = [
            ObserverState::Active,
            ObserverState::Degraded,
            ObserverState::Recovering,
            ObserverState::ContinuityUnverified,
            ObserverState::Quarantined,
        ]
        .iter()
        .map(|s| s.code())
        .collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(codes.len(), sorted.len());
    }

    #[test]
    fn coverage_window_is_inclusive() {
        let w = CoverageWindow {
            from_ms: 10,
            to_ms: 20,
        };
        assert!(w.contains(10));
        assert!(w.contains(20));
        assert!(!w.contains(9));
        assert!(!w.contains(21));
    }
}
