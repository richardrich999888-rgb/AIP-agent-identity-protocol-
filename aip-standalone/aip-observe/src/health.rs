//! Observer health, continuity state, and observation availability.
//!
//! Health is security state, not logging metadata (I9). It is signed by the
//! collector, and its **absence reduces coverage — it never extends it**.

use aip_crypto::sha256;
use aip_types::canonical::*;
use aip_types::Signature;
use serde::{Deserialize, Serialize};

use crate::observed::SourceMechanism;

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
    /// Live and continuous, but the observer cannot establish that its
    /// observation mechanism remained *capable* of delivering the event class
    /// over the window — a foreign eBPF program was found gating a tracepoint
    /// it samples, so the perf submission for that tracepoint may have been
    /// suppressed host-wide with no dropped-record accounting. This is neither
    /// ordinary loss (nothing was dropped from the ring) nor a continuity
    /// break (the chain is intact); it is the observation-integrity finding
    /// (`docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`). Absence during such a
    /// window carries no information: the observer may have been blind.
    IntegrityUnknown,
}

impl ObserverState {
    fn code(&self) -> u8 {
        match self {
            ObserverState::Active => 0x01,
            ObserverState::Degraded => 0x02,
            ObserverState::Recovering => 0x03,
            ObserverState::ContinuityUnverified => 0x04,
            ObserverState::Quarantined => 0x05,
            ObserverState::IntegrityUnknown => 0x06,
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

/// The collector's finding about whether its observation mechanisms remained
/// *capable* of delivering their event class — distinct from whether they
/// dropped anything (loss) or whether the chain is intact (continuity).
///
/// This is runtime state the collector derives from a live integrity check
/// (on Linux, enumerating the eBPF programs attached to the tracepoints it
/// samples). It is never signed on its own; its effect is carried into signed
/// evidence through [`ObserverState::IntegrityUnknown`], so a verifier trusts
/// the resulting state, not this input. Default is `Verified`: an observer
/// that samples no gate-able mechanism, or that has positively checked, is
/// capable — and the reconciler's non-occurrence gate does not rest on this
/// signal in any case (it requires a gate-independent mechanism in the signed
/// coverage), so a collector that never checks cannot thereby manufacture a
/// coverage claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MechanismIntegrity {
    /// No foreign eBPF program was found gating a sampled tracepoint (or the
    /// observer samples nothing a tracepoint gate could suppress).
    Verified,
    /// A foreign eBPF program was found attached to a tracepoint the observer
    /// samples: its perf submission may be suppressed host-wide with no loss
    /// accounting. The count is diagnostic, not load-bearing.
    ForeignTracepointGate { foreign_programs: u32 },
    /// The kernel refused the integrity query (for example, no `CAP_PERFMON`
    /// to run `PERF_EVENT_IOC_QUERY_BPF`). The observer could establish
    /// neither that a gate is present nor that none is: capability is unknown.
    /// Distinct from `ForeignTracepointGate` so a refused query is never
    /// reported as a *found* gate, and fail-closed like it — both drive
    /// [`ObserverState::IntegrityUnknown`] (see [`Self::is_capable`]).
    Unverifiable,
}

impl MechanismIntegrity {
    /// Map the result of a foreign-program enumeration
    /// ([`crate::PerfTracepoints::foreign_bpf_program_count`]) to a finding.
    /// One place decides the fail-closed policy for every perf-tracepoint
    /// sensor, so `sched`, `sock:inet_sock_set_state` and
    /// `sock:sock_send_length` cannot drift apart:
    ///
    /// - `Ok(0)` → `Verified` (no foreign program on the shared gate);
    /// - `Ok(n)` → `ForeignTracepointGate { n }` (a program that can suppress
    ///   this sensor's samples host-wide);
    /// - `Err(_)` → `Unverifiable` (capability could not be established, so
    ///   integrity is *not* assumed clean).
    pub fn from_foreign_program_query(result: std::io::Result<u32>) -> Self {
        match result {
            Ok(0) => Self::Verified,
            Ok(foreign_programs) => Self::ForeignTracepointGate { foreign_programs },
            Err(_) => Self::Unverifiable,
        }
    }

    /// True only when the mechanism is positively established as capable of
    /// delivering the event class. `ForeignTracepointGate` and `Unverifiable`
    /// are both false: a gated sensor may be silently blind, and an
    /// unverifiable one cannot rule that out. This is the single predicate the
    /// collector's state derivation rests on, so "found a gate" and "could not
    /// check" fail closed identically without conflating the two diagnostics.
    pub fn is_capable(&self) -> bool {
        matches!(self, MechanismIntegrity::Verified)
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
    /// The observer could not establish that its mechanism remained capable of
    /// observing the event class (a foreign eBPF program was gating a sampled
    /// tracepoint). Absence over this window is not evidence of non-occurrence.
    ObserverIntegrityUnknown,
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
    /// The mechanisms that were declared live in **every** batch of the
    /// current coverage epoch — the intersection, canonically ordered. Empty
    /// whenever `attested_coverage` is `None`. A reconciler may treat a
    /// window as covered *by kernel-pushed observation* only if a
    /// kernel-pushed mechanism appears here; polling in this list never
    /// supports a claim about what did not happen.
    pub covered_by: Vec<SourceMechanism>,
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
        put_u32(&mut buf, self.covered_by.len() as u32);
        for m in &self.covered_by {
            put_u8(&mut buf, m.code());
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
    /// Was the attested coverage epoch covered by a kernel-pushed mechanism
    /// that an on-host adversary cannot silently suppress?
    ///
    /// This is the precondition for any statement about an event *not* having
    /// happened; polled coverage can never support one. It now requires more
    /// than "kernel-pushed": the coverage must include at least one mechanism
    /// that does not pass through the per-tracepoint eBPF submission gate
    /// (`is_gate_independent_kernel_pushed`). A window covered *only* by
    /// perf-tracepoint mechanisms (sched/sock-state/sock-send) is not
    /// sufficient, because a single eBPF program on that tracepoint blinds
    /// them all with no loss accounting — the observation-integrity finding.
    /// Requiring an independent facility (the netlink process connector, the
    /// `fanotify` queue, or the `AF_PACKET` tap) is the cross-mechanism
    /// corroboration that closes it: two tracepoint consumers are not
    /// independent observers, so one of them alone cannot license a
    /// non-occurrence claim. See `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`
    /// and `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`.
    pub fn covered_by_kernel_pushed_source(&self) -> bool {
        self.health.state.permits_attested_use()
            && self.health.attested_coverage.is_some()
            && self
                .health
                .covered_by
                .iter()
                .any(|m| m.is_gate_independent_kernel_pushed())
    }

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
            ObserverState::IntegrityUnknown => Some(UnavailableReason::ObserverIntegrityUnknown),
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
            ObserverState::IntegrityUnknown,
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
            ObserverState::IntegrityUnknown,
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

    // ── observation-integrity finding ────────────────────────────────────
    // A blinded observer is one whose sampled tracepoint has a foreign eBPF
    // program gating it. The signed health must not let such an observer's
    // silence be read as coverage. These pin the two mechanisms that stop it:
    // the `IntegrityUnknown` state, and the requirement for a gate-independent
    // mechanism before coverage counts as kernel-pushed.

    fn signed(
        state: ObserverState,
        covered_by: Vec<SourceMechanism>,
        coverage: Option<CoverageWindow>,
    ) -> SignedSensorHealth {
        SignedSensorHealth {
            health: SensorHealth {
                version: 9,
                observer_id: "obs".into(),
                key_version: 1,
                state,
                continuity: ContinuityStatus::Verified,
                probe_policy: ProbePolicy::RegisteredOnly,
                sequence: 1,
                head: [0u8; 32],
                last_batch_id: None,
                attested_coverage: coverage,
                covered_by,
                emitted_at_ms: 1_000,
            },
            // The predicates under test never inspect the signature; a
            // placeholder keeps the test to the logic it is pinning.
            attestation: Signature {
                algorithm: aip_types::AlgorithmId::Ed25519,
                signer_id: "obs".into(),
                timestamp: 1_000,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: vec![0u8; 64],
            },
        }
    }

    #[test]
    fn integrity_unknown_does_not_permit_attested_use() {
        assert!(!ObserverState::IntegrityUnknown.permits_attested_use());
    }

    #[test]
    fn integrity_unknown_reports_unavailable_not_covered() {
        let w = CoverageWindow {
            from_ms: 10,
            to_ms: 20,
        };
        let h = signed(
            ObserverState::IntegrityUnknown,
            vec![SourceMechanism::ProcConnector],
            Some(w),
        );
        // Even with the connector in coverage and the window inside it, an
        // integrity-unknown observer vouches for nothing.
        assert_eq!(
            h.availability_for(&w, 1_000, 60_000),
            ObservationAvailability::Unavailable {
                reason: UnavailableReason::ObserverIntegrityUnknown
            }
        );
        assert!(!h.covered_by_kernel_pushed_source());
    }

    #[test]
    fn lone_gate_able_tracepoint_is_not_kernel_pushed_coverage() {
        let w = CoverageWindow {
            from_ms: 10,
            to_ms: 20,
        };
        // Active observer, real coverage — but the only mechanism is the
        // sched tracepoint, which a single eBPF program can blind. This is the
        // finding: it must NOT license a non-occurrence statement.
        let h = signed(
            ObserverState::Active,
            vec![SourceMechanism::SchedTracepoint],
            Some(w),
        );
        assert!(
            !h.covered_by_kernel_pushed_source(),
            "a gate-able tracepoint alone must not count as kernel-pushed coverage"
        );
        // Same for the other two perf-tracepoint mechanisms, alone or together.
        let h2 = signed(
            ObserverState::Active,
            vec![
                SourceMechanism::SockStateTracepoint,
                SourceMechanism::SockSendTracepoint,
            ],
            Some(w),
        );
        assert!(!h2.covered_by_kernel_pushed_source());
    }

    #[test]
    fn gate_independent_mechanism_is_kernel_pushed_coverage() {
        let w = CoverageWindow {
            from_ms: 10,
            to_ms: 20,
        };
        // The netlink connector is kernel-pushed and not exposed to the
        // tracepoint gate, so it stands on its own.
        for m in [
            SourceMechanism::ProcConnector,
            SourceMechanism::WireTapAfPacket,
            SourceMechanism::Fanotify,
        ] {
            let h = signed(ObserverState::Active, vec![m], Some(w));
            assert!(
                h.covered_by_kernel_pushed_source(),
                "{m:?} is gate-independent and should count"
            );
        }
    }

    #[test]
    fn independent_mechanism_alongside_a_gate_able_one_still_counts() {
        let w = CoverageWindow {
            from_ms: 10,
            to_ms: 20,
        };
        // A gate on the sched tracepoint cannot suppress the connector, so the
        // pair is corroborated by the independent mechanism.
        let h = signed(
            ObserverState::Active,
            vec![
                SourceMechanism::SchedTracepoint,
                SourceMechanism::ProcConnector,
            ],
            Some(w),
        );
        assert!(h.covered_by_kernel_pushed_source());
    }
}
