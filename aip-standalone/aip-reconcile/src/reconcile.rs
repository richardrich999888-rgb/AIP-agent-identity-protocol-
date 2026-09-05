//! The engine. Pure, deterministic, clock-free; consumes verified evidence
//! and emits a [`Reconciliation`]. It grants nothing, revokes nothing,
//! contains nothing.
//!
//! Verification order (Skill 7 §9): structure → expected signature →
//! expected window → observer signatures → observer trust → chain/continuity
//! → identity → decision id → binding → action → parameters → time →
//! strength → result. A failed prerequisite is never skipped and never
//! upgraded.

use aip_authorize::{
    verify_expected_execution, verify_expected_execution_for_agent, ExpectedExecution,
    ExpectedVerifyError,
};
use aip_observe::{
    verify_attested_batch, verify_attested_batch_independent_of_agent, verify_signed_health,
    AttestedBatch, CoverageWindow, KernelLifecycleEvent, ObservationAvailability,
    ObservedExecution, ObserverState, ProbePolicy, SourceMechanism, UnavailableReason, VerifyError,
};

use crate::ids::{BatchId, DecisionId, DecisionPointId, ObserverId, ObserverSequence, ProbeRunId};
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
    /// Set only by [`recompute_coverage`], and only when the supplied
    /// batches themselves establish gap-free, single-run, kernel-pushed
    /// coverage of the window. `PhantomClaim` cannot leave `finish` without
    /// it, so a future edit that forgets the recomputation downgrades to
    /// `CannotProve` instead of asserting non-execution.
    coverage_recomputed: bool,
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
            coverage_recomputed: false,
        }
    }

    /// Is the precondition of `result` actually visible in the record being
    /// emitted? This is the single choke point every result passes through:
    /// the per-branch logic decides *which* class to propose, and this
    /// decides whether the evidence in hand permits it. A proposal that
    /// fails becomes `CannotProve`.
    fn precondition_holds(&self, result: ReconciliationResult, strength: EvidenceStrength) -> bool {
        use ReconciliationResult as R;
        match result {
            R::CannotProve => true,
            // Requires action-level evidence, which no observation carries;
            // `ActionComparison::Match` is unconstructible (see `result`).
            R::VerifiedExecution => {
                self.action.is_observable()
                    && matches!(self.identity, IdentityComparison::Match { .. })
                    && self.availability.is_covered()
                    && strength >= EvidenceStrength::Attested
            }
            // Requires a verified decision-point completeness statement,
            // which must be in the evidence list.
            R::UnattributedEffect => {
                strength == EvidenceStrength::Attested
                    && self
                        .evidence
                        .iter()
                        .any(|e| matches!(e, EvidenceRef::CoverageStatement { .. }))
            }
            // Requires recomputed coverage and no reference at all.
            R::PhantomClaim => {
                self.coverage_recomputed
                    && matches!(self.identity, IdentityComparison::NoReference)
                    && self.availability.is_covered()
                    && strength == EvidenceStrength::Attested
            }
            R::IdentityDivergence => {
                matches!(self.identity, IdentityComparison::Divergent { .. })
                    && strength == EvidenceStrength::Attested
            }
            // No lineage evidence type exists; nothing may emit this.
            R::LineageViolation => false,
            R::SensorIntegrityFailure | R::ContinuityFailure => {
                strength >= EvidenceStrength::Attested
            }
        }
    }

    fn finish(
        self,
        result: ReconciliationResult,
        strength: EvidenceStrength,
        reason: ReasonCode,
    ) -> Reconciliation {
        let (result, strength, reason) = if self.precondition_holds(result, strength) {
            (result, strength, reason)
        } else {
            (
                ReconciliationResult::CannotProve,
                EvidenceStrength::Heuristic,
                ReasonCode::InvariantNotSatisfied,
            )
        };
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

/// Map an observer verification failure to its epistemic class.
///
/// The distinction matters: a signature that does not cover the bytes is
/// arithmetic anyone can recompute (`Proven` sensor integrity failure), while
/// an unanchored key, an unsupported protocol version, a malformed anchor or
/// an observer key that is the agent's own are all statements about *trust
/// and configuration*. Accusing the observer of tampering because the
/// verifier holds a bad anchor would be a false positive at `Proven`
/// strength. Matched exhaustively so a new variant breaks the build rather
/// than falling into a default.
fn classify_observer_error(e: &VerifyError) -> ObserverCheck<'static> {
    match e {
        VerifyError::UntrustedObserverKey { .. } => {
            ObserverCheck::CannotProve(ReasonCode::ObserverUntrusted)
        }
        VerifyError::UnsupportedVersion(_) => {
            ObserverCheck::CannotProve(ReasonCode::ObserverProtocolUnsupported)
        }
        VerifyError::ObserverKeyIsAgentKey => {
            ObserverCheck::CannotProve(ReasonCode::ObserverKeyIsAgentKey)
        }
        VerifyError::Crypto(_) => ObserverCheck::CannotProve(ReasonCode::ObserverUntrusted),
        VerifyError::SignerMismatch
        | VerifyError::PayloadHashMismatch
        | VerifyError::SignatureInvalid => {
            ObserverCheck::IntegrityFailure(ReasonCode::ObserverSignatureInvalid)
        }
    }
}

fn verify_observer<'a>(
    ev: &'a ObserverEvidence,
    ctx: &ReconciliationContext,
    draft: &mut Draft,
) -> ObserverCheck<'a> {
    // Health first: it anchors everything else.
    if let Err(e) = verify_signed_health(&ev.health, &ctx.observer_anchors) {
        return classify_observer_error(&e);
    }
    let health = &ev.health.health;
    // I10: the observer's key must not be the observed agent's key. Only
    // checkable when the verifier supplied that key.
    if let Some(agent_key) = &ctx.agent_public_key {
        if ctx
            .observer_anchors
            .get(&health.observer_id, health.key_version)
            == Some(agent_key.as_slice())
        {
            return ObserverCheck::CannotProve(ReasonCode::ObserverKeyIsAgentKey);
        }
    }
    draft.evidence.push(EvidenceRef::Health {
        observer_id: ObserverId(health.observer_id.clone()),
        sequence: ObserverSequence(health.sequence),
        emitted_at_ms: health.emitted_at_ms,
    });

    // Batches: verify each, dedup exact replays, refuse mixed observers.
    let mut seen: Vec<(u64, [u8; 32])> = Vec::new();
    let mut batches: Vec<&AttestedBatch> = Vec::new();
    for b in &ev.batches {
        let verified = match &ctx.agent_public_key {
            Some(k) => verify_attested_batch_independent_of_agent(b, &ctx.observer_anchors, k),
            None => verify_attested_batch(b, &ctx.observer_anchors),
        };
        if let Err(e) = verified {
            return classify_observer_error(&e);
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
            observer_id: ObserverId(b.observer_id.clone()),
            key_version: b.key_version,
            sequence: ObserverSequence(b.sequence),
            batch_id: BatchId::from_bytes(b.batch.batch_id),
            probe_run_id: ProbeRunId::from_bytes(b.batch.probe_run_id),
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
    inconsistent: Vec<EvidenceRef>,
    outside_window: u32,
}

fn window_overlaps(batch: &AttestedBatch, w: &CoverageWindow, tol: u64) -> bool {
    let from = w.from_ms.saturating_sub(tol);
    let to = w.to_ms.saturating_add(tol);
    batch.batch.claimed_from_ms <= to && batch.batch.claimed_to_ms >= from
}

/// Does a claim pair — `claimed_decision_id` plus the `agent_id` inside the
/// same `AgentAttribution` — hang together?
///
/// Both halves come from one unauthenticated claim made to the probe. A
/// claim that names this decision while naming a different agent is
/// internally inconsistent: taking the decision id and ignoring the agent id
/// would let anything that can register a claim attach itself to another
/// party's decision and produce a divergence verdict against them.
fn claim_pair(
    claimed_decision_id: &Option<[u8; 16]>,
    attribution: &aip_observe::AgentAttribution,
    decision_id: &DecisionId,
    agent_id: &str,
) -> ClaimPair {
    if claimed_decision_id.as_ref() != Some(decision_id.as_bytes()) {
        ClaimPair::NotThisDecision
    } else if attribution.claimed_agent_id() == Some(agent_id) {
        ClaimPair::Consistent
    } else {
        ClaimPair::Inconsistent
    }
}

enum ClaimPair {
    NotThisDecision,
    Consistent,
    Inconsistent,
}

fn observation_refers(
    o: &ObservedExecution,
    ee: &ExpectedExecution,
    decision_id: &DecisionId,
) -> Refers {
    let expected = &ee.execution_binding;
    // An instance match is a measurement, independent of any claim.
    if o.observed.matches_process_of(expected) {
        return Refers::Match;
    }
    match claim_pair(
        &o.claimed_decision_id,
        &o.attribution,
        decision_id,
        &ee.agent_id,
    ) {
        ClaimPair::Consistent => Refers::Divergent,
        ClaimPair::Inconsistent => Refers::ClaimInconsistent,
        ClaimPair::NotThisDecision if o.observed.process.pid == expected.process.pid => {
            Refers::UnboundPid
        }
        ClaimPair::NotThisDecision => Refers::None,
    }
}

fn kernel_event_refers(
    e: &KernelLifecycleEvent,
    ee: &ExpectedExecution,
    decision_id: &DecisionId,
) -> Refers {
    let expected = &ee.execution_binding;
    let claim = claim_pair(
        &e.claimed_decision_id,
        &e.attribution,
        decision_id,
        &ee.agent_id,
    );
    match &e.bound {
        Some(p) if p.matches_process_of(expected) => Refers::Match,
        Some(_) => match claim {
            ClaimPair::Consistent => Refers::Divergent,
            ClaimPair::Inconsistent => Refers::ClaimInconsistent,
            ClaimPair::NotThisDecision => Refers::None,
        },
        // Unbound: kernel-attested existence of a pid, no identity (I4).
        None => match claim {
            ClaimPair::Inconsistent => Refers::ClaimInconsistent,
            _ if e.kind.subject_pid() == Some(expected.process.pid) => Refers::UnboundPid,
            ClaimPair::Consistent => Refers::UnboundPid,
            ClaimPair::NotThisDecision => Refers::None,
        },
    }
}

enum Refers {
    Match,
    Divergent,
    UnboundPid,
    /// Claims this decision, names another agent.
    ClaimInconsistent,
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
            let r = observation_refers(o, ee, &decision_id);
            let er = EvidenceRef::Observation {
                batch_sequence: ObserverSequence(b.sequence),
                index: i as u32,
            };
            match r {
                Refers::None => {}
                _ if !in_window => refs.outside_window += 1,
                Refers::Match => refs.matching.push(er),
                Refers::Divergent => refs.divergent.push(er),
                Refers::UnboundPid => refs.unbound.push(er),
                Refers::ClaimInconsistent => refs.inconsistent.push(er),
            }
        }
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            let r = kernel_event_refers(e, ee, &decision_id);
            let er = EvidenceRef::KernelEvent {
                batch_sequence: ObserverSequence(b.sequence),
                index: i as u32,
            };
            match r {
                Refers::None => {}
                _ if !in_window => refs.outside_window += 1,
                Refers::Match => refs.matching.push(er),
                Refers::Divergent => refs.divergent.push(er),
                Refers::UnboundPid => refs.unbound.push(er),
                Refers::ClaimInconsistent => refs.inconsistent.push(er),
            }
        }
    }
    refs
}

/// Does the outer hull of the supplied batches' claimed windows reach across
/// `w`? A necessary condition only — it says nothing about holes inside.
fn batches_span(batches: &[&AttestedBatch], w: &CoverageWindow) -> bool {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for b in batches {
        lo = lo.min(b.batch.claimed_from_ms);
        hi = hi.max(b.batch.claimed_to_ms);
    }
    !batches.is_empty() && lo <= w.from_ms && hi >= w.to_ms
}

/// Recompute, from the attested batches alone, whether `w` was continuously
/// sampled by one probe run using a kernel-pushed mechanism.
///
/// This exists because every input to the collector's derived coverage
/// fields is authored by the **host-side probe**: `claimed_from_ms`,
/// `claimed_to_ms`, `active_mechanisms` and `probe_run_id` are claims, and
/// the collector unions the claimed intervals without checking that they
/// abut, that they end before its own clock, or that one probe run produced
/// them. Trusting `attested_coverage` / `covered_by` alone would therefore
/// let a compromised host manufacture coverage over an interval nothing
/// sampled — and a `PHANTOM_CLAIM` is precisely a statement about such an
/// interval. The reconciler holds the batches, so it re-derives the claim,
/// exactly as the observer re-derives chain heads instead of reading them.
///
/// `health_emitted_at_ms` anchors the end of the window to a time the
/// collector itself signed: a probe can claim to have sampled the future,
/// but the collector cannot have signed for it yet.
fn recompute_coverage(
    batches: &[&AttestedBatch],
    w: &CoverageWindow,
    health_emitted_at_ms: u64,
    tolerance_ms: u64,
) -> Result<(), ReasonCode> {
    // The window may not extend past the moment the observer last spoke.
    if w.to_ms > health_emitted_at_ms.saturating_add(tolerance_ms) {
        return Err(ReasonCode::CoverageEndsAfterHealth);
    }
    // Order by claimed interval; sequence order is the collector's, and the
    // claimed intervals are the probe's, so the two need not agree.
    let mut claimed: Vec<&&AttestedBatch> = batches.iter().collect();
    claimed.sort_by_key(|b| (b.batch.claimed_from_ms, b.batch.claimed_to_ms));

    let mut cursor = w.from_ms;
    let mut used: Vec<&AttestedBatch> = Vec::new();
    for b in claimed {
        if b.batch.claimed_to_ms < cursor {
            continue; // entirely before the uncovered remainder
        }
        if b.batch.claimed_from_ms > cursor.saturating_add(tolerance_ms) {
            // Nothing claims [cursor, claimed_from): a hole inside the
            // window. Silence in a hole is not attested silence (I8).
            return Err(ReasonCode::CoverageGapInWindow);
        }
        used.push(b);
        cursor = cursor.max(b.batch.claimed_to_ms);
        if cursor >= w.to_ms {
            break;
        }
    }
    if cursor < w.to_ms {
        return Err(ReasonCode::CoverageGapInWindow);
    }
    // One probe run, or the window was not continuously sampled whatever the
    // health record's epoch bookkeeping says.
    let run = used[0].batch.probe_run_id;
    if used.iter().any(|b| b.batch.probe_run_id != run) {
        return Err(ReasonCode::CoverageProbeRunChanged);
    }
    // Provenance, recomputed: intersect the declared live mechanisms over
    // exactly the batches that carried the window.
    let kernel_pushed = used
        .iter()
        .map(|b| b.batch.active_mechanisms.clone())
        .reduce(|acc, m| acc.into_iter().filter(|x| m.contains(x)).collect())
        .unwrap_or_default()
        .iter()
        .any(SourceMechanism::is_kernel_pushed);
    if !kernel_pushed {
        return Err(ReasonCode::CoverageNotKernelPushed);
    }
    Ok(())
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
        decision_point_id: DecisionPointId(ee.decision_point_id.clone()),
        decision_id: DecisionId::from_bytes(ee.decision_id),
    });

    // 1–3. Expected signature, trust, structure (window included). When the
    // verifier supplied the agent's key, also I1: the agent must not hold
    // the decision key. Matched exhaustively: a new variant must be
    // classified deliberately, not swept into a default.
    let expected_verified = match &ctx.agent_public_key {
        Some(k) => verify_expected_execution_for_agent(ee, &ctx.decision_point_anchors, k),
        None => verify_expected_execution(ee, &ctx.decision_point_anchors),
    };
    if let Err(e) = expected_verified {
        let reason = match e {
            ExpectedVerifyError::UntrustedDecisionPoint(_) => {
                ReasonCode::ExpectedUntrustedDecisionPoint
            }
            ExpectedVerifyError::PayloadHashMismatch
            | ExpectedVerifyError::SignatureInvalid
            | ExpectedVerifyError::SignerMismatch
            | ExpectedVerifyError::Crypto(_) => ReasonCode::ExpectedSignatureInvalid,
            ExpectedVerifyError::SelfAuthorization | ExpectedVerifyError::DecisionKeyIsAgentKey => {
                ReasonCode::ExpectedSelfAuthorization
            }
            ExpectedVerifyError::UnsupportedVersion(_)
            | ExpectedVerifyError::InvalidWindow { .. }
            | ExpectedVerifyError::BindingAgentMismatch
            | ExpectedVerifyError::BindingMalformed(_) => ReasonCode::ExpectedStructurallyInvalid,
        };
        return draft.cannot_prove(reason);
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
    // …and health the verifier's own clock says has not been emitted yet.
    // Staleness only bounds records that are too old; a forward-set collector
    // clock would otherwise saturate to "age zero" and read as fresh.
    if ev.health.health.emitted_at_ms
        > ctx
            .verification_time_ms
            .saturating_add(ctx.window_tolerance_ms)
    {
        return draft.cannot_prove(ReasonCode::HealthNotYetEmitted);
    }

    // 7–12. Identity, decision id, binding, action, parameters, time.
    let refs = collect_references(&obs, ee, &window, ctx.window_tolerance_ms);
    let any_reference = !refs.matching.is_empty()
        || !refs.divergent.is_empty()
        || !refs.unbound.is_empty()
        || !refs.inconsistent.is_empty();
    draft.temporal = if any_reference {
        TemporalComparison::WithinWindow
    } else if refs.outside_window > 0 {
        TemporalComparison::OutsideWindow
    } else {
        TemporalComparison::Indeterminate
    };
    draft.identity = match (
        refs.matching.len(),
        refs.divergent.len(),
        refs.unbound.len(),
        refs.inconsistent.len(),
    ) {
        (0, 0, 0, 0) => IdentityComparison::NoReference,
        // An internally inconsistent claim outranks a bare pid: it is the
        // more specific statement about why nothing can be concluded.
        (0, 0, _, i) if i > 0 => IdentityComparison::ClaimInconsistent {
            references: i as u32,
        },
        (0, 0, u, _) => IdentityComparison::UnboundReferencesOnly {
            references: u as u32,
        },
        (m, 0, _, _) => IdentityComparison::Match {
            observations: m as u32,
        },
        (0, d, _, _) => IdentityComparison::Divergent {
            observations: d as u32,
        },
        (m, d, _, _) => IdentityComparison::Ambiguous {
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
            .chain(&refs.inconsistent)
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
        IdentityComparison::ClaimInconsistent { .. } => {
            draft.cannot_prove(ReasonCode::AttributionInconsistent)
        }
        IdentityComparison::NoReference => {
            if refs.outside_window > 0 {
                return draft.cannot_prove(ReasonCode::ObservationOutsideWindow);
            }
            // PHANTOM_CLAIM — the one class that asserts something *did not*
            // happen — needs all of:
            //   a. the collector's own availability says Covered;
            //   b. a registered-only probe regime, so the bytes have known
            //      provenance;
            //   c. kernel-pushed coverage in the signed health;
            //   d. the supplied contiguous chain spanning the window;
            //   e. that same chain, re-derived, showing gap-free coverage by
            //      one probe run with a kernel-pushed source, ending no later
            //      than the collector's own signed clock.
            // (a)–(c) are the collector's derived claims; (d)–(e) are the
            // reconciler recomputing them from the batches it holds.
            if !draft.availability.is_covered() {
                return draft.cannot_prove(ReasonCode::WindowNotCovered);
            }
            if obs.health.probe_policy == ProbePolicy::Open {
                return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);
            }
            if !ev.health.covered_by_kernel_pushed_source() {
                return draft.cannot_prove(ReasonCode::CoverageNotKernelPushed);
            }
            if !batches_span(&obs.batches, &window) {
                return draft.cannot_prove(ReasonCode::ObservationSetIncomplete);
            }
            if let Err(reason) = recompute_coverage(
                &obs.batches,
                &window,
                obs.health.emitted_at_ms,
                ctx.window_tolerance_ms,
            ) {
                return draft.cannot_prove(reason);
            }
            draft.coverage_recomputed = true;
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
            let Some(b) = obs.batches.iter().find(|b| b.sequence == batch_sequence.0) else {
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
            let Some(b) = obs.batches.iter().find(|b| b.sequence == batch_sequence.0) else {
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
    if observer.health.health.emitted_at_ms
        > ctx
            .verification_time_ms
            .saturating_add(ctx.window_tolerance_ms)
    {
        return draft.cannot_prove(ReasonCode::HealthNotYetEmitted);
    }

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
        decision_point_id: DecisionPointId(stmt.decision_point_id.clone()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use aip_authorize::DecisionPointTrustAnchors;
    use aip_observe::ObserverTrustAnchors;

    fn ctx() -> ReconciliationContext {
        ReconciliationContext {
            decision_point_anchors: DecisionPointTrustAnchors::new(),
            observer_anchors: ObserverTrustAnchors::new(),
            verification_time_ms: 1_000,
            health_max_age_ms: 60_000,
            window_tolerance_ms: 0,
            expected_side: ExpectedSideCoverage::Unknown,
            agent_public_key: None,
        }
    }

    /// The guard is the last line: whatever a branch proposes, a positive
    /// class may only leave `finish` when its precondition is visible in the
    /// record. These call it directly with the preconditions absent — the
    /// shape a future edit would take if it forgot a check.
    #[test]
    fn positive_classes_without_their_precondition_are_downgraded() {
        let c = ctx();
        for (result, strength) in [
            (
                ReconciliationResult::VerifiedExecution,
                EvidenceStrength::Attested,
            ),
            (
                ReconciliationResult::PhantomClaim,
                EvidenceStrength::Attested,
            ),
            (
                ReconciliationResult::UnattributedEffect,
                EvidenceStrength::Attested,
            ),
            (
                ReconciliationResult::IdentityDivergence,
                EvidenceStrength::Attested,
            ),
            (
                ReconciliationResult::LineageViolation,
                EvidenceStrength::Proven,
            ),
            (
                ReconciliationResult::SensorIntegrityFailure,
                EvidenceStrength::Heuristic,
            ),
        ] {
            let r =
                Draft::new(&c).finish(result, strength, ReasonCode::KernelCoverageWithNoReference);
            assert_eq!(
                r.result,
                ReconciliationResult::CannotProve,
                "{result:?} escaped without its precondition"
            );
            assert_eq!(r.reason, ReasonCode::InvariantNotSatisfied);
            assert_eq!(r.strength, EvidenceStrength::Heuristic);
        }
    }

    /// A `PhantomClaim` needs the coverage recomputation flag, which only
    /// `recompute_coverage` success sets, plus `NoReference` and `Covered`.
    #[test]
    fn phantom_claim_requires_the_recomputed_coverage_flag() {
        let c = ctx();
        let covered = ObservationAvailability::Covered {
            window: CoverageWindow {
                from_ms: 0,
                to_ms: 10,
            },
        };
        let mut d = Draft::new(&c);
        d.availability = covered.clone();
        assert_eq!(
            d.finish(
                ReconciliationResult::PhantomClaim,
                EvidenceStrength::Attested,
                ReasonCode::KernelCoverageWithNoReference
            )
            .result,
            ReconciliationResult::CannotProve
        );

        let mut d = Draft::new(&c);
        d.availability = covered;
        d.coverage_recomputed = true;
        assert_eq!(
            d.finish(
                ReconciliationResult::PhantomClaim,
                EvidenceStrength::Attested,
                ReasonCode::KernelCoverageWithNoReference
            )
            .result,
            ReconciliationResult::PhantomClaim
        );
    }

    /// `LineageViolation` has no evidence type behind it at all, so the guard
    /// refuses it unconditionally rather than relying on no branch proposing
    /// it.
    #[test]
    fn lineage_violation_is_refused_unconditionally() {
        let c = ctx();
        let mut d = Draft::new(&c);
        d.identity = IdentityComparison::Divergent { observations: 1 };
        d.availability = ObservationAvailability::Covered {
            window: CoverageWindow {
                from_ms: 0,
                to_ms: 10,
            },
        };
        d.coverage_recomputed = true;
        let r = d.finish(
            ReconciliationResult::LineageViolation,
            EvidenceStrength::Proven,
            ReasonCode::IdentityDiverged,
        );
        assert_eq!(r.result, ReconciliationResult::CannotProve);
        assert_eq!(r.reason, ReasonCode::InvariantNotSatisfied);
    }
}
