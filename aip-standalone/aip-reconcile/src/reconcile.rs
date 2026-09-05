//! The engine. Pure, deterministic, clock-free; consumes verified evidence
//! and emits a [`Reconciliation`]. It grants nothing, revokes nothing,
//! contains nothing.
//!
//! Verification order (Skill 7 §9): structure → expected signature →
//! expected window → observer signatures → observer trust → chain/continuity
//! → identity → decision id → binding → action → parameters → time →
//! strength → result. A failed prerequisite is never skipped and never
//! upgraded.

use aip_authorize::{verify_expected_execution, ExpectedExecution, ExpectedVerifyError};
use aip_observe::{
    verify_attested_batch, verify_signed_health, AttestedBatch, CoverageWindow,
    KernelLifecycleEvent, ObservationAvailability, ObservedExecution, ObserverState, ProbePolicy,
    UnavailableReason, VerifyError,
};
use aip_types::ExecutionBinding;

use crate::ids::DecisionId;
use crate::inputs::{
    ExpectedSideCoverage, ObservationTarget, ObserverEvidence, ReconciliationContext,
};
use crate::result::{
    ActionComparison, EvidenceRef, EvidenceStrength, IdentityComparison, ReasonCode,
    Reconciliation, ReconciliationResult, TemporalComparison, RECONCILIATION_VERSION,
};

// ─── Result assembly ───

struct Draft {
    decision_id: Option<DecisionId>,
    availability: ObservationAvailability,
    identity: IdentityComparison,
    action: ActionComparison,
    temporal: TemporalComparison,
    replay_detected: bool,
    evidence: Vec<EvidenceRef>,
    verification_time_ms: u64,
}

impl Draft {
    fn new(ctx: &ReconciliationContext) -> Self {
        Self {
            decision_id: None,
            availability: aip_observe::no_observer(),
            identity: IdentityComparison::NoReference,
            action: ActionComparison::Unobservable,
            temporal: TemporalComparison::Indeterminate,
            replay_detected: false,
            evidence: Vec::new(),
            verification_time_ms: ctx.verification_time_ms,
        }
    }

    fn finish(
        self,
        result: ReconciliationResult,
        strength: EvidenceStrength,
        reason: ReasonCode,
    ) -> Reconciliation {
        Reconciliation {
            version: RECONCILIATION_VERSION,
            result,
            strength,
            reason,
            decision_id: self.decision_id,
            availability: self.availability,
            identity: self.identity,
            action: self.action,
            temporal: self.temporal,
            replay_detected: self.replay_detected,
            evidence: self.evidence,
            verification_time_ms: self.verification_time_ms,
        }
    }

    fn cannot_prove(self, reason: ReasonCode) -> Reconciliation {
        self.finish(
            ReconciliationResult::CannotProve,
            EvidenceStrength::Heuristic,
            reason,
        )
    }
}

// ─── Observer evidence verification ───

/// Verified, deduplicated, chain-checked observer evidence.
struct VerifiedObserver<'a> {
    batches: Vec<&'a AttestedBatch>,
    health: &'a aip_observe::SensorHealth,
    replay_detected: bool,
}

enum ObserverCheck<'a> {
    Ok(VerifiedObserver<'a>),
    /// Signature or chain arithmetic failed — third party can recompute.
    IntegrityFailure(ReasonCode),
    /// Not enough to proceed, without an integrity claim.
    CannotProve(ReasonCode),
}

fn verify_observer<'a>(
    ev: &'a ObserverEvidence,
    ctx: &ReconciliationContext,
    draft: &mut Draft,
) -> ObserverCheck<'a> {
    // Health first: it anchors everything else.
    match verify_signed_health(&ev.health, &ctx.observer_anchors) {
        Ok(()) => {}
        Err(VerifyError::UntrustedObserverKey { .. }) => {
            return ObserverCheck::CannotProve(ReasonCode::ObserverUntrusted)
        }
        Err(VerifyError::UnsupportedVersion(_)) => {
            return ObserverCheck::CannotProve(ReasonCode::ObserverUntrusted)
        }
        Err(_) => return ObserverCheck::IntegrityFailure(ReasonCode::ObserverSignatureInvalid),
    }
    let health = &ev.health.health;
    draft.evidence.push(EvidenceRef::Health {
        observer_id: health.observer_id.clone(),
        sequence: health.sequence,
        emitted_at_ms: health.emitted_at_ms,
    });

    // Batches: verify each, dedup exact replays, refuse mixed observers.
    let mut seen: Vec<(u64, [u8; 32])> = Vec::new();
    let mut batches: Vec<&AttestedBatch> = Vec::new();
    for b in &ev.batches {
        match verify_attested_batch(b, &ctx.observer_anchors) {
            Ok(()) => {}
            Err(VerifyError::UntrustedObserverKey { .. })
            | Err(VerifyError::UnsupportedVersion(_)) => {
                return ObserverCheck::CannotProve(ReasonCode::ObserverUntrusted)
            }
            Err(_) => return ObserverCheck::IntegrityFailure(ReasonCode::ObserverSignatureInvalid),
        }
        if b.observer_id != health.observer_id {
            return ObserverCheck::CannotProve(ReasonCode::MixedObservers);
        }
        let key = (b.sequence, b.head());
        if seen.contains(&key) {
            draft.replay_detected = true;
            continue;
        }
        seen.push(key);
        batches.push(b);
    }
    batches.sort_by_key(|b| b.sequence);

    // Same sequence, different bytes, both validly signed: the collector
    // signed a fork. Arithmetic, recomputable by anyone holding both.
    for w in batches.windows(2) {
        if w[0].sequence == w[1].sequence {
            return ObserverCheck::IntegrityFailure(ReasonCode::ObserverChainBroken);
        }
    }
    // Contiguity and linkage.
    for w in batches.windows(2) {
        if w[1].sequence != w[0].sequence + 1 {
            return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);
        }
        if w[1].prev_head != w[0].head() {
            return ObserverCheck::IntegrityFailure(ReasonCode::ObserverChainBroken);
        }
    }
    // The supplied chain must end exactly where the health record says the
    // chain is; otherwise batches may have been withheld.
    if let Some(last) = batches.last() {
        if last.sequence != health.sequence || last.head() != health.head {
            return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);
        }
    } else if health.sequence != 0 {
        return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);
    }
    for b in &batches {
        draft.evidence.push(EvidenceRef::Batch {
            observer_id: b.observer_id.clone(),
            key_version: b.key_version,
            sequence: b.sequence,
            head: b.head(),
        });
    }
    ObserverCheck::Ok(VerifiedObserver {
        batches,
        health,
        replay_detected: draft.replay_detected,
    })
}

/// Map the observer's own state to the reason a window is unavailable, when
/// the state alone settles the question.
fn state_reason(state: ObserverState) -> Option<ReasonCode> {
    match state {
        ObserverState::Active => None,
        ObserverState::Degraded => Some(ReasonCode::ObserverDegraded),
        ObserverState::Recovering => Some(ReasonCode::ObserverRecovering),
        ObserverState::ContinuityUnverified => Some(ReasonCode::ObserverContinuityUnverified),
        ObserverState::Quarantined => Some(ReasonCode::ObserverQuarantined),
    }
}

// ─── Reference collection ───

#[derive(Default)]
struct References {
    matching: Vec<EvidenceRef>,
    divergent: Vec<EvidenceRef>,
    unbound: Vec<EvidenceRef>,
    outside_window: u32,
}

fn window_overlaps(batch: &AttestedBatch, w: &CoverageWindow, tol: u64) -> bool {
    let from = w.from_ms.saturating_sub(tol);
    let to = w.to_ms.saturating_add(tol);
    batch.batch.claimed_from_ms <= to && batch.batch.claimed_to_ms >= from
}

fn observation_refers(
    o: &ObservedExecution,
    expected: &ExecutionBinding,
    decision_id: &DecisionId,
) -> Refers {
    if o.observed.matches_process_of(expected) {
        Refers::Match
    } else if o.claimed_decision_id.as_ref() == Some(decision_id.as_bytes()) {
        Refers::Divergent
    } else if o.observed.process.pid == expected.process.pid {
        Refers::UnboundPid
    } else {
        Refers::None
    }
}

fn kernel_event_refers(
    e: &KernelLifecycleEvent,
    expected: &ExecutionBinding,
    decision_id: &DecisionId,
) -> Refers {
    match &e.bound {
        Some(p) if p.matches_process_of(expected) => Refers::Match,
        Some(_) if e.claimed_decision_id.as_ref() == Some(decision_id.as_bytes()) => {
            Refers::Divergent
        }
        Some(_) => Refers::None,
        None => {
            if e.kind.subject_pid() == Some(expected.process.pid)
                || e.claimed_decision_id.as_ref() == Some(decision_id.as_bytes())
            {
                Refers::UnboundPid
            } else {
                Refers::None
            }
        }
    }
}

enum Refers {
    Match,
    Divergent,
    UnboundPid,
    None,
}

fn collect_references(
    obs: &VerifiedObserver<'_>,
    ee: &ExpectedExecution,
    window: &CoverageWindow,
    tol: u64,
) -> References {
    let decision_id = DecisionId::from_bytes(ee.decision_id);
    let mut refs = References::default();
    for b in &obs.batches {
        let in_window = window_overlaps(b, window, tol);
        for (i, o) in b.batch.observations.iter().enumerate() {
            let r = observation_refers(o, &ee.execution_binding, &decision_id);
            let er = EvidenceRef::Observation {
                batch_sequence: b.sequence,
                index: i as u32,
            };
            match r {
                Refers::None => {}
                _ if !in_window => refs.outside_window += 1,
                Refers::Match => refs.matching.push(er),
                Refers::Divergent => refs.divergent.push(er),
                Refers::UnboundPid => refs.unbound.push(er),
            }
        }
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            let r = kernel_event_refers(e, &ee.execution_binding, &decision_id);
            let er = EvidenceRef::KernelEvent {
                batch_sequence: b.sequence,
                index: i as u32,
            };
            match r {
                Refers::None => {}
                _ if !in_window => refs.outside_window += 1,
                Refers::Match => refs.matching.push(er),
                Refers::Divergent => refs.divergent.push(er),
                Refers::UnboundPid => refs.unbound.push(er),
            }
        }
    }
    refs
}

/// Do the supplied batches' claimed windows, taken together, cover `w`?
/// Batches are contiguous by construction here, so a union check suffices.
fn batches_cover(batches: &[&AttestedBatch], w: &CoverageWindow) -> bool {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for b in batches {
        lo = lo.min(b.batch.claimed_from_ms);
        hi = hi.max(b.batch.claimed_to_ms);
    }
    !batches.is_empty() && lo <= w.from_ms && hi >= w.to_ms
}

// ─── Entry point 1: an expectation against observation ───

/// Reconcile one signed expectation against the observer evidence the caller
/// holds. `None` observer evidence is a legitimate input and yields
/// `CANNOT_PROVE` with `NoObserver` availability — never a verdict.
pub fn reconcile_expectation(
    ee: &ExpectedExecution,
    observer: Option<&ObserverEvidence>,
    ctx: &ReconciliationContext,
) -> Reconciliation {
    let mut draft = Draft::new(ctx);
    draft.decision_id = Some(DecisionId::from_bytes(ee.decision_id));
    draft.evidence.push(EvidenceRef::Expected {
        decision_point_id: ee.decision_point_id.clone(),
        decision_id: DecisionId::from_bytes(ee.decision_id),
    });

    // 1–3. Expected signature, trust, structure (window included).
    match verify_expected_execution(ee, &ctx.decision_point_anchors) {
        Ok(()) => {}
        Err(ExpectedVerifyError::UntrustedDecisionPoint(_)) => {
            return draft.cannot_prove(ReasonCode::ExpectedUntrustedDecisionPoint)
        }
        Err(ExpectedVerifyError::PayloadHashMismatch)
        | Err(ExpectedVerifyError::SignatureInvalid)
        | Err(ExpectedVerifyError::SignerMismatch)
        | Err(ExpectedVerifyError::Crypto(_)) => {
            return draft.cannot_prove(ReasonCode::ExpectedSignatureInvalid)
        }
        Err(_) => return draft.cannot_prove(ReasonCode::ExpectedStructurallyInvalid),
    }
    let window = CoverageWindow {
        from_ms: ee.issued_at,
        to_ms: ee.valid_until,
    };

    // 4–6. Observer signatures, trust, chain, continuity.
    let Some(ev) = observer else {
        return draft.cannot_prove(ReasonCode::NoObserverEvidence);
    };
    let obs = match verify_observer(ev, ctx, &mut draft) {
        ObserverCheck::Ok(o) => o,
        ObserverCheck::IntegrityFailure(reason) => {
            return draft.finish(
                ReconciliationResult::SensorIntegrityFailure,
                EvidenceStrength::Proven,
                reason,
            )
        }
        ObserverCheck::CannotProve(reason) => return draft.cannot_prove(reason),
    };
    draft.replay_detected = obs.replay_detected;
    draft.availability =
        ev.health
            .availability_for(&window, ctx.verification_time_ms, ctx.health_max_age_ms);

    // Health stale: nothing about the window can be said.
    if let ObservationAvailability::Unavailable {
        reason: UnavailableReason::HealthStale { .. },
    } = &draft.availability
    {
        return draft.cannot_prove(ReasonCode::HealthStale);
    }

    // 7–12. Identity, decision id, binding, action, parameters, time.
    let refs = collect_references(&obs, ee, &window, ctx.window_tolerance_ms);
    draft.temporal =
        if refs.matching.is_empty() && refs.divergent.is_empty() && refs.unbound.is_empty() {
            if refs.outside_window > 0 {
                TemporalComparison::OutsideWindow
            } else {
                TemporalComparison::Indeterminate
            }
        } else {
            TemporalComparison::WithinWindow
        };
    draft.identity = match (
        refs.matching.len(),
        refs.divergent.len(),
        refs.unbound.len(),
    ) {
        (0, 0, 0) => IdentityComparison::NoReference,
        (0, 0, u) => IdentityComparison::UnboundReferencesOnly {
            references: u as u32,
        },
        (m, 0, _) => IdentityComparison::Match {
            observations: m as u32,
        },
        (0, d, _) => IdentityComparison::Divergent {
            observations: d as u32,
        },
        (m, d, _) => IdentityComparison::Ambiguous {
            matching: m as u32,
            divergent: d as u32,
        },
    };
    // Action and parameters: no current observation carries them.
    draft.action = ActionComparison::Unobservable;
    draft.evidence.extend(
        refs.matching
            .iter()
            .chain(&refs.divergent)
            .chain(&refs.unbound)
            .cloned(),
    );

    // Observer state gates every positive statement.
    let state = obs.health.state;
    match state {
        ObserverState::Quarantined => {
            return draft.finish(
                ReconciliationResult::SensorIntegrityFailure,
                EvidenceStrength::Attested,
                ReasonCode::ObserverQuarantined,
            )
        }
        ObserverState::Recovering | ObserverState::ContinuityUnverified => {
            return draft.finish(
                ReconciliationResult::ContinuityFailure,
                EvidenceStrength::Attested,
                state_reason(state).unwrap_or(ReasonCode::ObserverContinuityUnverified),
            )
        }
        ObserverState::Degraded => return draft.cannot_prove(ReasonCode::ObserverDegraded),
        ObserverState::Active => {}
    }

    // 13–14. Result and strength, Active observer.
    match draft.identity {
        IdentityComparison::Ambiguous { .. } => {
            draft.cannot_prove(ReasonCode::AmbiguousObservations)
        }
        IdentityComparison::Match { .. } => {
            // Identity corroborated; the action itself is unobservable, so
            // VERIFIED_EXECUTION's precondition cannot be met. This is the
            // ceiling of the current sensors and is reported as such.
            draft.cannot_prove(ReasonCode::ActionEvidenceUnavailable)
        }
        IdentityComparison::Divergent { .. } => {
            if obs.health.probe_policy == ProbePolicy::Open {
                return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);
            }
            draft.finish(
                ReconciliationResult::IdentityDivergence,
                EvidenceStrength::Attested,
                ReasonCode::IdentityDiverged,
            )
        }
        IdentityComparison::UnboundReferencesOnly { .. } => {
            draft.cannot_prove(ReasonCode::UnboundReferencesOnly)
        }
        IdentityComparison::NoReference => {
            if refs.outside_window > 0 {
                return draft.cannot_prove(ReasonCode::ObservationOutsideWindow);
            }
            // PHANTOM_CLAIM needs: Covered window, kernel-pushed coverage in
            // the signed health, a registered-only probe regime, and the
            // supplied contiguous chain actually spanning the window.
            if !draft.availability.is_covered() {
                return draft.cannot_prove(ReasonCode::WindowNotCovered);
            }
            if obs.health.probe_policy == ProbePolicy::Open {
                return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);
            }
            if !ev.health.covered_by_kernel_pushed_source() {
                return draft.cannot_prove(ReasonCode::CoverageNotKernelPushed);
            }
            if !batches_cover(&obs.batches, &window) {
                return draft.cannot_prove(ReasonCode::ObservationSetIncomplete);
            }
            draft.finish(
                ReconciliationResult::PhantomClaim,
                EvidenceStrength::Attested,
                ReasonCode::KernelCoverageWithNoReference,
            )
        }
    }
}

// ─── Entry point 2: an observation without an expectation ───

/// Reconcile one attested observation against the expected side. Yields
/// `UNATTRIBUTED_EFFECT` only when a decision point has attested the
/// complete set of expectations for the claimed agent over the window and
/// the observation's claim is not among them.
pub fn reconcile_observation(
    observer: &ObserverEvidence,
    target: ObservationTarget,
    ctx: &ReconciliationContext,
) -> Reconciliation {
    let mut draft = Draft::new(ctx);
    let obs = match verify_observer(observer, ctx, &mut draft) {
        ObserverCheck::Ok(o) => o,
        ObserverCheck::IntegrityFailure(reason) => {
            return draft.finish(
                ReconciliationResult::SensorIntegrityFailure,
                EvidenceStrength::Proven,
                reason,
            )
        }
        ObserverCheck::CannotProve(reason) => return draft.cannot_prove(reason),
    };
    draft.replay_detected = obs.replay_detected;

    // Locate the target.
    let (batch, claimed_agent, claimed_decision, has_instance, target_ref) = match target {
        ObservationTarget::Observation {
            batch_sequence,
            index,
        } => {
            let Some(b) = obs.batches.iter().find(|b| b.sequence == batch_sequence) else {
                return draft.cannot_prove(ReasonCode::TargetNotFound);
            };
            let Some(o) = b.batch.observations.get(index as usize) else {
                return draft.cannot_prove(ReasonCode::TargetNotFound);
            };
            (
                *b,
                o.attribution.claimed_agent_id().map(str::to_string),
                o.claimed_decision_id,
                true,
                EvidenceRef::Observation {
                    batch_sequence,
                    index,
                },
            )
        }
        ObservationTarget::KernelEvent {
            batch_sequence,
            index,
        } => {
            let Some(b) = obs.batches.iter().find(|b| b.sequence == batch_sequence) else {
                return draft.cannot_prove(ReasonCode::TargetNotFound);
            };
            let Some(e) = b.batch.kernel_events.get(index as usize) else {
                return draft.cannot_prove(ReasonCode::TargetNotFound);
            };
            (
                *b,
                e.attribution.claimed_agent_id().map(str::to_string),
                e.claimed_decision_id,
                e.bound.is_some(),
                EvidenceRef::KernelEvent {
                    batch_sequence,
                    index,
                },
            )
        }
    };
    draft.evidence.push(target_ref);
    draft.decision_id = claimed_decision.map(DecisionId::from_bytes);
    let window = CoverageWindow {
        from_ms: batch.batch.claimed_from_ms,
        to_ms: batch.batch.claimed_to_ms,
    };
    draft.availability =
        observer
            .health
            .availability_for(&window, ctx.verification_time_ms, ctx.health_max_age_ms);
    draft.temporal = TemporalComparison::WithinWindow;

    if let Some(reason) = state_reason(obs.health.state) {
        return match obs.health.state {
            ObserverState::Quarantined => draft.finish(
                ReconciliationResult::SensorIntegrityFailure,
                EvidenceStrength::Attested,
                reason,
            ),
            ObserverState::Recovering | ObserverState::ContinuityUnverified => draft.finish(
                ReconciliationResult::ContinuityFailure,
                EvidenceStrength::Attested,
                reason,
            ),
            _ => draft.cannot_prove(reason),
        };
    }
    if !has_instance {
        draft.identity = IdentityComparison::UnboundReferencesOnly { references: 1 };
        return draft.cannot_prove(ReasonCode::UnboundReferencesOnly);
    }
    draft.identity = IdentityComparison::Match { observations: 1 };
    let Some(agent) = claimed_agent else {
        return draft.cannot_prove(ReasonCode::AttributionNotEstablished);
    };
    if obs.health.probe_policy == ProbePolicy::Open {
        return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);
    }

    // Expected-side completeness must be attested, not assumed.
    let stmt = match &ctx.expected_side {
        ExpectedSideCoverage::Unknown => {
            return draft.cannot_prove(ReasonCode::ExpectedSideCompletenessUnknown)
        }
        ExpectedSideCoverage::Attested(s) => s,
    };
    if stmt.verify(&ctx.decision_point_anchors).is_err() {
        return draft.cannot_prove(ReasonCode::ExpectedSideStatementInvalid);
    }
    draft.evidence.push(EvidenceRef::CoverageStatement {
        decision_point_id: stmt.decision_point_id.clone(),
        issued_at_ms: stmt.issued_at_ms,
    });
    if stmt.agent_id != agent || !stmt.window.covers(&window) {
        return draft.cannot_prove(ReasonCode::ExpectedSideStatementDoesNotCover);
    }
    match claimed_decision {
        Some(d) if stmt.decision_ids.contains(&d) => {
            // An expectation exists for this claim; reconcile it from the
            // expected side instead of declaring anything here.
            draft.cannot_prove(ReasonCode::ExpectationExistsForObservation)
        }
        _ => draft.finish(
            ReconciliationResult::UnattributedEffect,
            EvidenceStrength::Attested,
            ReasonCode::NoExpectationAttested,
        ),
    }
}
