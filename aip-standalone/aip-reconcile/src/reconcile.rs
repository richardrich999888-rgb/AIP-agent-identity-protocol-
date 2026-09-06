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
    ObservedExecution, ObserverState, ProbePolicy, SocketEndpoint, SocketProtocol, SourceMechanism,
    UnavailableReason, VerifyError,
};

use crate::action::{
    derive_action, derive_lineage_edges, derive_transition_evidence, LineageEdge,
    TransitionEvidence,
};
use crate::ids::{BatchId, DecisionId, DecisionPointId, ObserverId, ObserverSequence, ProbeRunId};
use crate::inputs::{
    ExpectedSideCoverage, LineageInputs, ObservationTarget, ObserverEvidence, ReconciliationContext,
};
use crate::result::{
    ActionComparison, ActionEvidenceKind, EvidenceRef, EvidenceStrength, IdentityComparison,
    LineageComparison, LineageLink, Provenance, ReasonCode, Reconciliation, ReconciliationResult,
    TemporalComparison, WireCorroboration, RECONCILIATION_VERSION,
};

// ─── Result assembly ───

struct Draft {
    decision_id: Option<DecisionId>,
    availability: ObservationAvailability,
    identity: IdentityComparison,
    action: ActionComparison,
    temporal: TemporalComparison,
    /// Set only by [`reconcile_lineage`]; `Contradicted` is the sole value
    /// that lets `LineageViolation` leave `finish`.
    lineage: LineageComparison,
    /// Set only when a socket transition carried a `VerifiedExecution`
    /// (Gate 2). Informational: it can neither raise nor lower the verdict.
    wire: WireCorroboration,
    replay_detected: bool,
    evidence: Vec<EvidenceRef>,
    verification_time_ms: u64,
    /// Set only by [`recompute_coverage`], and only when the supplied
    /// batches themselves establish gap-free, single-run, kernel-pushed
    /// coverage of the window. `PhantomClaim` cannot leave `finish` without
    /// it, so a future edit that forgets the recomputation downgrades to
    /// `CannotProve` instead of asserting non-execution.
    coverage_recomputed: bool,
    /// Set only by [`compare_action`], and only when the batch carrying the
    /// matching action evidence lies wholly inside the authorized window and
    /// inside the collector's attested coverage epoch. `VerifiedExecution`
    /// cannot leave `finish` without it.
    action_continuity_verified: bool,
}

impl Draft {
    fn new(ctx: &ReconciliationContext) -> Self {
        Self {
            decision_id: None,
            availability: aip_observe::no_observer(),
            identity: IdentityComparison::NoReference,
            action: ActionComparison::Unobservable,
            temporal: TemporalComparison::Indeterminate,
            lineage: LineageComparison::NotEvaluated,
            wire: WireCorroboration::NotEvaluated,
            replay_detected: false,
            evidence: Vec::new(),
            verification_time_ms: ctx.verification_time_ms,
            coverage_recomputed: false,
            action_continuity_verified: false,
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
            // Requires a sealed action match (only `compare_action` can build
            // one), a matching instance, the carrying batch inside the window
            // and inside attested coverage, and exactly `Attested`: the
            // content is procfs-read and can never be `Proven`. Full coverage
            // of the *whole* window is not required for a positive claim —
            // the observation itself is the evidence; coverage of the rest of
            // the window would add nothing to it.
            R::VerifiedExecution => {
                matches!(self.action, ActionComparison::Match(_))
                    && matches!(self.identity, IdentityComparison::Match { .. })
                    && self.action_continuity_verified
                    && strength == EvidenceStrength::Attested
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
            // Phase C2: only `reconcile_lineage`, and only with both sides
            // complete and contradicting. The content is procfs-bound on the
            // observed side and token/document-bound on the claimed side:
            // `Attested`, never `Proven`.
            R::LineageViolation => {
                matches!(self.lineage, LineageComparison::Contradicted)
                    && strength == EvidenceStrength::Attested
            }
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
            lineage: self.lineage,
            wire: self.wire,
            replay_detected: self.replay_detected,
            evidence: self.evidence,
            verification_time_ms: self.verification_time_ms,
            provenance: Provenance::Engine,
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
            attested_at_ms: b.attested_at_ms,
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

/// An in-window observation whose measured instance matches the expected
/// binding — the only kind of observation that can carry action evidence
/// for the expectation.
struct ActionCandidate<'a> {
    evidence: EvidenceRef,
    observation: &'a ObservedExecution,
    batch: &'a AttestedBatch,
    /// The observation's claim pair names this decision *and* this agent.
    claimed_here: bool,
}

/// A kernel-reported connection transition whose anchored instance matches
/// the expected binding, with the batches that carry its two events.
struct TransitionCandidate<'a> {
    t: TransitionEvidence,
    /// The initiating event's claim pair names this decision and this agent.
    claimed_here: bool,
    syn_batch: &'a AttestedBatch,
    est_batch: Option<&'a AttestedBatch>,
}

#[derive(Default)]
struct References<'a> {
    matching: Vec<EvidenceRef>,
    divergent: Vec<EvidenceRef>,
    unbound: Vec<EvidenceRef>,
    inconsistent: Vec<EvidenceRef>,
    outside_window: u32,
    candidates: Vec<ActionCandidate<'a>>,
    transitions: Vec<TransitionCandidate<'a>>,
}

/// Where a kernel-timestamped transition sits relative to the authorized
/// window, decided by the most trustworthy clock available first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Before the decision was issued: by the collector's signed attestation
    /// clock (the transition was already attested when the decision was
    /// made — two off-host clocks, no host input), or by the probe's
    /// boot-clock anchor.
    Before,
    Within,
    After,
    /// No anchor: kernel time and wall time are different clock domains and
    /// are not compared.
    Unanchored,
}

fn place_transition(
    t: &TransitionEvidence,
    syn_batch: &AttestedBatch,
    est_batch: Option<&AttestedBatch>,
    window: &CoverageWindow,
    tol: u64,
) -> Placement {
    // Trusted clocks first. The initiation cannot have happened after the
    // collector signed the batch that carries it.
    if syn_batch.attested_at_ms.saturating_add(tol) < window.from_ms {
        return Placement::Before;
    }
    let Some(anchor) = syn_batch.batch.clock_anchor else {
        return Placement::Unanchored;
    };
    let init_wall = anchor.wall_ms(t.initiation().kernel_timestamp_ns);
    if init_wall.saturating_add(tol) < window.from_ms {
        return Placement::Before;
    }
    if init_wall > window.to_ms.saturating_add(tol) {
        return Placement::After;
    }
    if let Some(c) = t.completion() {
        let est_anchor = est_batch
            .and_then(|b| b.batch.clock_anchor)
            .unwrap_or(anchor);
        if est_anchor.wall_ms(c.kernel_timestamp_ns) > window.to_ms.saturating_add(tol) {
            return Placement::After;
        }
    }
    Placement::Within
}

/// How the observations of the authorized instance compare with the
/// expected action, by priority: a claimed transition wins; then a claimed
/// presence unless a transition proves that connection predates the
/// decision; otherwise the most specific reason nothing verified.
enum ActionOutcome {
    Verified {
        mechanism: SourceMechanism,
        kind: ActionEvidenceKind,
        evidence: Vec<EvidenceRef>,
        /// Index into `References::transitions` of the transition that
        /// carried the verdict, when one did.
        transition: Option<usize>,
    },
    /// A matching connection transition is placed before the decision.
    Precedes,
    /// Presence: carrying batch straddles or lies outside the window.
    OutsideWindow,
    /// Transition: placed after the window.
    AfterWindow,
    /// Carrying batch(es) outside the collector's attested coverage epoch.
    NotCovered,
    /// Exact match exists but is not claimed under this decision.
    Unclaimed,
    /// The initiation was seen for this instance and endpoint, but no
    /// completion of that socket was recorded.
    Incomplete,
    /// Gate 3 / Gate 4: an action by the instance was seen, but what it
    /// acted on cannot be placed on any authorized parameter (a send whose
    /// socket no attested transition names; a write whose name the kernel
    /// reported as deleted). The reason names the class.
    Unresolved { reason: ReasonCode },
    /// A matching transition exists but its batch has no clock anchor.
    Unanchored,
    /// Evidence of the expected kind exists with a different digest.
    Mismatch {
        mechanism: SourceMechanism,
        kind: ActionEvidenceKind,
    },
    /// No observation of the instance is an instance of the expected kind.
    None,
}

/// Compare the expected action with what the candidates evidence.
///
/// Transition evidence (kernel-pushed, `SockStateTracepoint`) is evaluated
/// first: the `connect()` initiation anchored to the instance, paired with
/// its completion by kernel socket identity, placed in time by the
/// collector's signed clock and then by the probe's boot-clock anchor. A
/// transition placed **before** the decision is not the authorized action,
/// whoever claims it — and it also disqualifies presence evidence of the
/// same connection, which is exactly the "existed, but was not made" case.
///
/// Presence evidence (polled table) is evaluated second and unchanged: for
/// a positive claim the carrying batch's claimed interval must lie wholly
/// inside the authorized window (± verifier tolerance), the probe's own
/// wall-clock stamp too, and the batch must sit inside the coverage epoch
/// the collector signed. Host claims only ever *restrict* a verdict.
fn compare_action(
    ee: &ExpectedExecution,
    refs: &References<'_>,
    window: &CoverageWindow,
    attested_coverage: Option<CoverageWindow>,
    tol: u64,
) -> ActionOutcome {
    let lo = window.from_ms.saturating_sub(tol);
    let hi = window.to_ms.saturating_add(tol);
    let covered = |b: &AttestedBatch| {
        attested_coverage.is_some_and(|cov| {
            cov.covers(&CoverageWindow {
                from_ms: b.batch.claimed_from_ms,
                to_ms: b.batch.claimed_to_ms,
            })
        })
    };

    // ── Transitions ──
    let mut t_verified: Vec<EvidenceRef> = Vec::new();
    let mut preceding: Vec<(SocketProtocol, SocketEndpoint, Option<SocketEndpoint>)> = Vec::new();
    let (mut t_after, mut t_uncovered, mut t_unclaimed, mut t_incomplete, mut t_unanchored) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut t_mismatch = false;
    let mut t_precedes = false;
    let mut t_mechanism: Option<SourceMechanism> = None;
    let mut t_first: Option<usize> = None;
    let mut t_unresolved: Option<ReasonCode> = None;
    for (ti, c) in refs.transitions.iter().enumerate() {
        let t = &c.t;
        if t.kind() != &ee.action_kind {
            continue;
        }
        // An initiation whose parameters are not yet knowable (a spawn with
        // no paired exec) is an attempt of the expected kind; a send whose
        // socket no attested transition names cannot be placed on an
        // endpoint at all.
        let Some(digest) = t.parameter_digest() else {
            match t {
                TransitionEvidence::Send(_) => {
                    t_unresolved.get_or_insert(ReasonCode::SendSocketUnresolved);
                }
                TransitionEvidence::File(_) => {
                    t_unresolved.get_or_insert(ReasonCode::FilePathUnresolved);
                }
                _ => t_incomplete += 1,
            }
            continue;
        };
        if digest != ee.parameter_digest {
            t_mismatch = true;
            t_mechanism.get_or_insert(t.mechanism());
            continue;
        }
        let placement = place_transition(t, c.syn_batch, c.est_batch, window, tol);
        if placement == Placement::Before {
            if let Some(tuple) = t.socket_tuple() {
                preceding.push(tuple);
            }
            t_precedes = true;
            continue;
        }
        if !c.claimed_here {
            t_unclaimed += 1;
            continue;
        }
        let Some(completion) = t.completion() else {
            t_incomplete += 1;
            continue;
        };
        // An exec pairing whose child start could not be checked against
        // the fork (no anchor on the exec batch) is unanchored evidence.
        if let TransitionEvidence::Exec(x) = t {
            if !x.execution.as_ref().is_some_and(|e| e.child_start_verified) {
                t_unanchored += 1;
                continue;
            }
        }
        match placement {
            Placement::Unanchored => {
                t_unanchored += 1;
                continue;
            }
            Placement::After => {
                t_after += 1;
                continue;
            }
            Placement::Within => {}
            Placement::Before => unreachable!("handled above"),
        }
        if !covered(c.syn_batch) || !c.est_batch.is_some_and(covered) {
            t_uncovered += 1;
            continue;
        }
        t_mechanism.get_or_insert(t.mechanism());
        t_first.get_or_insert(ti);
        let initiation = t.initiation();
        t_verified.push(EvidenceRef::KernelEvent {
            batch_sequence: ObserverSequence(initiation.batch_sequence),
            index: initiation.index,
        });
        if completion != initiation {
            t_verified.push(EvidenceRef::KernelEvent {
                batch_sequence: ObserverSequence(completion.batch_sequence),
                index: completion.index,
            });
        }
    }
    if !t_verified.is_empty() {
        return ActionOutcome::Verified {
            mechanism: t_mechanism.unwrap_or(SourceMechanism::SockStateTracepoint),
            kind: ActionEvidenceKind::Transition,
            evidence: t_verified,
            transition: t_first,
        };
    }

    // ── Presence ──
    let mut verified: Vec<EvidenceRef> = Vec::new();
    let mut mechanism: Option<SourceMechanism> = None;
    let (mut outside, mut uncovered, mut unclaimed, mut p_precedes) = (0u32, 0u32, 0u32, 0u32);
    let mut mismatch: Option<SourceMechanism> = None;
    for c in &refs.candidates {
        let Some(d) = derive_action(c.observation) else {
            continue;
        };
        if d.kind != ee.action_kind {
            continue;
        }
        if d.parameter_digest != ee.parameter_digest {
            mismatch.get_or_insert(d.mechanism);
            continue;
        }
        // The same connection, shown by the kernel to predate the decision.
        if let aip_observe::ObservedEffect::SocketObserved {
            protocol,
            local,
            remote,
            ..
        } = &c.observation.effect
        {
            if preceding.iter().any(|(p, r, l)| {
                p == protocol && r == remote && l.is_none_or(|l| l.port == local.port)
            }) {
                p_precedes += 1;
                continue;
            }
        }
        if !c.claimed_here {
            unclaimed += 1;
            continue;
        }
        let b = &c.batch.batch;
        let inside_window = b.claimed_from_ms >= lo
            && b.claimed_to_ms <= hi
            && c.observation.host_wall_clock_ms >= lo
            && c.observation.host_wall_clock_ms <= hi;
        if !inside_window {
            outside += 1;
            continue;
        }
        if !covered(c.batch) {
            uncovered += 1;
            continue;
        }
        mechanism.get_or_insert(d.mechanism);
        verified.push(c.evidence.clone());
    }
    if let Some(mechanism) = mechanism {
        return ActionOutcome::Verified {
            mechanism,
            kind: ActionEvidenceKind::Presence,
            evidence: verified,
            transition: None,
        };
    }
    if t_precedes || p_precedes > 0 {
        return ActionOutcome::Precedes;
    }
    if outside > 0 {
        return ActionOutcome::OutsideWindow;
    }
    if t_after > 0 {
        return ActionOutcome::AfterWindow;
    }
    if uncovered > 0 || t_uncovered > 0 {
        return ActionOutcome::NotCovered;
    }
    if unclaimed > 0 || t_unclaimed > 0 {
        return ActionOutcome::Unclaimed;
    }
    if t_incomplete > 0 {
        return ActionOutcome::Incomplete;
    }
    if let Some(reason) = t_unresolved {
        return ActionOutcome::Unresolved { reason };
    }
    if t_unanchored > 0 {
        return ActionOutcome::Unanchored;
    }
    if t_mismatch {
        return ActionOutcome::Mismatch {
            mechanism: t_mechanism.unwrap_or(SourceMechanism::SockStateTracepoint),
            kind: ActionEvidenceKind::Transition,
        };
    }
    if let Some(mechanism) = mismatch {
        return ActionOutcome::Mismatch {
            mechanism,
            kind: ActionEvidenceKind::Presence,
        };
    }
    ActionOutcome::None
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

fn collect_references<'a>(
    obs: &VerifiedObserver<'a>,
    ee: &ExpectedExecution,
    window: &CoverageWindow,
    tol: u64,
) -> References<'a> {
    let decision_id = DecisionId::from_bytes(ee.decision_id);
    let mut refs = References::default();
    for b in &obs.batches {
        let b: &'a AttestedBatch = b;
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
                Refers::Match => {
                    refs.candidates.push(ActionCandidate {
                        evidence: er.clone(),
                        observation: o,
                        batch: b,
                        claimed_here: matches!(
                            claim_pair(
                                &o.claimed_decision_id,
                                &o.attribution,
                                &decision_id,
                                &ee.agent_id
                            ),
                            ClaimPair::Consistent
                        ),
                    });
                    refs.matching.push(er)
                }
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
    // Kernel-reported connection transitions anchored to the expected
    // instance. Their temporal placement is decided later from kernel time
    // and signed clocks, not from batch windows.
    for t in derive_transition_evidence(obs.batches.iter().copied()) {
        if !t.actor().matches_process_of(&ee.execution_binding) {
            continue;
        }
        let find = |seq: u64| obs.batches.iter().copied().find(|b| b.sequence == seq);
        let Some(syn_batch) = find(t.initiation().batch_sequence) else {
            continue;
        };
        let est_batch = t.completion().and_then(|c| find(c.batch_sequence));
        let claimed_here = matches!(
            claim_pair(
                &t.claimed_decision_id(),
                t.attribution(),
                &decision_id,
                &ee.agent_id
            ),
            ClaimPair::Consistent
        );
        refs.transitions.push(TransitionCandidate {
            t,
            claimed_here,
            syn_batch,
            est_batch,
        });
    }
    refs
}

/// Slack, in kernel nanoseconds, around a socket transition inside which a
/// wire handshake is taken to belong to it. Anchors are exact to the
/// millisecond; one second absorbs anchor skew between batches without
/// reaching into a neighbouring connection on the same tuple.
const WIRE_WINDOW_NS: u64 = 1_000_000_000;

/// Gate 2 — does the device layer corroborate a socket-layer transition?
///
/// Looks for exactly one TCP handshake on the transition's tuple inside
/// `[initiation − slack, completion + slack]` on the kernel monotonic axis:
/// a SYN from the local endpoint to the remote and a SYN-ACK back that
/// acknowledges it. Wire stamps are on the realtime clock and are placed on
/// the monotonic axis through the carrying batch's `clock_anchor`; a segment
/// in an unanchored batch cannot be placed and is not evidence.
///
/// `Unavailable` when no batch overlapping the transition's wall window
/// declared a live tap inside attested coverage, or when such a batch
/// reported loss — the tap cannot vouch for its own silence then.
/// Ambiguity (two distinct SYNs) cites nothing. Nothing here changes the
/// verdict or the strength of the record it is written on.
fn corroborate_wire(
    t: &crate::action::SocketTransition,
    batches: &[&AttestedBatch],
    attested_coverage: Option<CoverageWindow>,
) -> (WireCorroboration, Vec<EvidenceRef>) {
    let (Some(local), Some(completion)) = (t.local, t.completion) else {
        return (WireCorroboration::NotEvaluated, Vec::new());
    };
    let syn_batch = batches
        .iter()
        .copied()
        .find(|b| b.sequence == t.initiation.batch_sequence);
    let Some(anchor) = syn_batch.and_then(|b| b.batch.clock_anchor) else {
        return (WireCorroboration::Unavailable, Vec::new());
    };
    let lo_ns = t
        .initiation
        .kernel_timestamp_ns
        .saturating_sub(WIRE_WINDOW_NS);
    let hi_ns = completion
        .kernel_timestamp_ns
        .saturating_add(WIRE_WINDOW_NS);
    let (lo_ms, hi_ms) = (anchor.wall_ms(lo_ns), anchor.wall_ms(hi_ns));

    // Which batches can vouch for the wire over that window?
    let mut tap_live = false;
    for b in batches {
        let declared = b
            .batch
            .active_mechanisms
            .contains(&SourceMechanism::WireTapAfPacket);
        let overlaps = b.batch.claimed_from_ms <= hi_ms && b.batch.claimed_to_ms >= lo_ms;
        if !declared || !overlaps {
            continue;
        }
        let covered = attested_coverage.is_some_and(|cov| {
            cov.covers(&CoverageWindow {
                from_ms: b.batch.claimed_from_ms,
                to_ms: b.batch.claimed_to_ms,
            })
        });
        if !covered || b.batch.dropped_events != Some(0) {
            return (WireCorroboration::Unavailable, Vec::new());
        }
        tap_live = true;
    }
    if !tap_live {
        return (WireCorroboration::Unavailable, Vec::new());
    }

    // Place every segment of the tuple inside the window.
    struct Seg {
        seq: u32,
        ack: u32,
        at_ns: u64,
        is_syn: bool,
        r: EvidenceRef,
    }
    let mut segs: Vec<Seg> = Vec::new();
    for b in batches {
        let Some(a) = b.batch.clock_anchor else {
            continue;
        };
        for (i, e) in b.batch.kernel_events.iter().enumerate() {
            if e.mechanism != SourceMechanism::WireTapAfPacket {
                continue;
            }
            let aip_observe::KernelLifecycleKind::WireSegment {
                protocol,
                src,
                dst,
                seq,
                ack,
                kernel_realtime_ns,
                ..
            } = &e.kind
            else {
                continue;
            };
            if *protocol != t.protocol {
                continue;
            }
            let is_syn = e.kind.is_wire_syn() && *src == local && *dst == t.remote;
            let is_syn_ack = e.kind.is_wire_syn_ack() && *src == t.remote && *dst == local;
            if !is_syn && !is_syn_ack {
                continue;
            }
            let at_ns = a.realtime_ns_to_monotonic(*kernel_realtime_ns);
            if at_ns < lo_ns || at_ns > hi_ns {
                continue;
            }
            segs.push(Seg {
                seq: *seq,
                ack: *ack,
                at_ns,
                is_syn,
                r: EvidenceRef::KernelEvent {
                    batch_sequence: ObserverSequence(b.sequence),
                    index: i as u32,
                },
            });
        }
    }
    let mut isns: Vec<u32> = segs.iter().filter(|s| s.is_syn).map(|s| s.seq).collect();
    isns.sort_unstable();
    isns.dedup();
    if isns.len() > 1 {
        return (
            WireCorroboration::Ambiguous {
                handshakes: isns.len() as u32,
            },
            Vec::new(),
        );
    }
    let Some(isn) = isns.first().copied() else {
        return (WireCorroboration::NotObserved, Vec::new());
    };
    let syn = segs
        .iter()
        .filter(|s| s.is_syn && s.seq == isn)
        .min_by_key(|s| s.at_ns)
        .expect("an isn came from a syn");
    let syn_ack = segs
        .iter()
        .filter(|s| !s.is_syn && s.ack == isn.wrapping_add(1) && s.at_ns >= syn.at_ns)
        .min_by_key(|s| s.at_ns);
    match syn_ack {
        Some(sa) => (
            WireCorroboration::Corroborated,
            vec![syn.r.clone(), sa.r.clone()],
        ),
        None => (WireCorroboration::NotObserved, Vec::new()),
    }
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
    // exactly the batches that carried the window. A statement that a
    // *process* never appeared needs kernel-pushed **lifecycle** coverage
    // (the process-event connector); a socket-state stream is kernel-pushed
    // too but says nothing about processes, so it does not qualify.
    let lifecycle_covered = used
        .iter()
        .map(|b| b.batch.active_mechanisms.clone())
        .reduce(|acc, m| acc.into_iter().filter(|x| m.contains(x)).collect())
        .unwrap_or_default()
        .iter()
        .any(SourceMechanism::covers_process_lifecycle);
    if !lifecycle_covered {
        return Err(ReasonCode::CoverageNotKernelPushed);
    }
    Ok(())
}

// ─── Entry point 1: an expectation against observation ───

/// Everything the two entry points share before they diverge: expectation
/// verification, window, observer verification, availability, health
/// freshness. Returned as a whole; an early exit is the finished record.
struct Prepared<'a> {
    draft: Draft,
    obs: VerifiedObserver<'a>,
    window: CoverageWindow,
    ev: &'a ObserverEvidence,
}

fn prologue<'a>(
    ee: &ExpectedExecution,
    observer: Option<&'a ObserverEvidence>,
    ctx: &ReconciliationContext,
    mut draft: Draft,
) -> Result<Prepared<'a>, Reconciliation> {
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
        return Err(draft.cannot_prove(reason));
    }
    let window = CoverageWindow {
        from_ms: ee.issued_at,
        to_ms: ee.valid_until,
    };

    // 4–6. Observer signatures, trust, chain, continuity.
    let Some(ev) = observer else {
        return Err(draft.cannot_prove(ReasonCode::NoObserverEvidence));
    };
    let obs = match verify_observer(ev, ctx, &mut draft) {
        ObserverCheck::Ok(o) => o,
        ObserverCheck::IntegrityFailure(reason) => {
            return Err(draft.finish(
                ReconciliationResult::SensorIntegrityFailure,
                EvidenceStrength::Proven,
                reason,
            ))
        }
        ObserverCheck::CannotProve(reason) => return Err(draft.cannot_prove(reason)),
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
        return Err(draft.cannot_prove(ReasonCode::HealthStale));
    }
    // …and health the verifier's own clock says has not been emitted yet.
    // Staleness only bounds records that are too old; a forward-set collector
    // clock would otherwise saturate to "age zero" and read as fresh.
    if ev.health.health.emitted_at_ms
        > ctx
            .verification_time_ms
            .saturating_add(ctx.window_tolerance_ms)
    {
        return Err(draft.cannot_prove(ReasonCode::HealthNotYetEmitted));
    }
    Ok(Prepared {
        draft,
        obs,
        window,
        ev,
    })
}

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

    let Prepared {
        mut draft,
        obs,
        window,
        ev,
    } = match prologue(ee, observer, ctx, draft) {
        Ok(p) => p,
        Err(r) => return r,
    };

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
            // Identity corroborated. Whether the *action* is corroborated
            // depends on whether some in-window observation of the instance
            // is an instance of an observable action class of the expected
            // kind (`action::derive_action`), with the expected digest,
            // claimed under this decision, carried by a batch inside the
            // window and inside attested coverage. Anything less is the
            // ceiling of the current sensors and is reported as such.
            let outcome = compare_action(
                ee,
                &refs,
                &window,
                obs.health.attested_coverage,
                ctx.window_tolerance_ms,
            );
            if !matches!(outcome, ActionOutcome::None)
                && obs.health.probe_policy == ProbePolicy::Open
            {
                // Action-shaped evidence exists but its mechanism label is
                // unverified provenance.
                return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);
            }
            match outcome {
                ActionOutcome::Verified {
                    mechanism,
                    kind,
                    mut evidence,
                    transition,
                } => {
                    draft.action = ActionComparison::matched(mechanism, kind);
                    draft.action_continuity_verified = true;
                    // Gate 2: ask the device layer whether it saw the
                    // handshake the socket layer reported. Informational.
                    if let Some(TransitionEvidence::Socket(t)) =
                        transition.map(|i| &refs.transitions[i].t)
                    {
                        let (wire, wire_refs) =
                            corroborate_wire(t, &obs.batches, obs.health.attested_coverage);
                        draft.wire = wire;
                        evidence.extend(wire_refs);
                    }
                    for e in evidence {
                        if !draft.evidence.contains(&e) {
                            draft.evidence.push(e);
                        }
                    }
                    draft.finish(
                        ReconciliationResult::VerifiedExecution,
                        EvidenceStrength::Attested,
                        ReasonCode::ActionEvidenceMatches,
                    )
                }
                ActionOutcome::Precedes => {
                    draft.temporal = TemporalComparison::BeforeWindow;
                    draft.cannot_prove(ReasonCode::ActionPrecedesAuthorization)
                }
                ActionOutcome::AfterWindow => {
                    draft.temporal = TemporalComparison::AfterWindow;
                    draft.cannot_prove(ReasonCode::ActionEvidenceOutsideWindow)
                }
                ActionOutcome::Unanchored => {
                    draft.temporal = TemporalComparison::Unanchored;
                    draft.cannot_prove(ReasonCode::KernelTimeUnanchored)
                }
                ActionOutcome::Incomplete => {
                    draft.cannot_prove(ReasonCode::ActionTransitionIncomplete)
                }
                ActionOutcome::Unresolved { reason } => draft.cannot_prove(reason),
                ActionOutcome::Mismatch { mechanism, kind } => {
                    draft.action = ActionComparison::mismatched(mechanism, kind);
                    draft.cannot_prove(ReasonCode::ActionEvidenceDoesNotMatch)
                }
                ActionOutcome::Unclaimed => draft.cannot_prove(ReasonCode::ActionEvidenceUnclaimed),
                ActionOutcome::OutsideWindow => {
                    draft.cannot_prove(ReasonCode::ActionEvidenceOutsideWindow)
                }
                ActionOutcome::NotCovered => {
                    draft.cannot_prove(ReasonCode::ActionEvidenceNotCovered)
                }
                ActionOutcome::None => draft.cannot_prove(ReasonCode::ActionEvidenceUnavailable),
            }
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

// ─── Lineage (Phase C2) ───

/// Ask the lineage question about one decision: does the kernel-observed
/// ancestry of the authorized instance contradict the lineage its own
/// signed claims assert? See `tests/lineage_violation.rs` for the full
/// precondition. Every missing piece is `CANNOT_PROVE` naming the gap;
/// every ambiguity is ambiguity; only complete, contradicting evidence on
/// both sides yields `LINEAGE_VIOLATION`, at `Attested`.
pub fn reconcile_lineage(
    ee: &ExpectedExecution,
    observer: Option<&ObserverEvidence>,
    ctx: &ReconciliationContext,
    li: &LineageInputs<'_>,
) -> Reconciliation {
    let mut draft = Draft::new(ctx);
    draft.decision_id = Some(DecisionId::from_bytes(ee.decision_id));
    draft.evidence.push(EvidenceRef::Expected {
        decision_point_id: DecisionPointId(ee.decision_point_id.clone()),
        decision_id: DecisionId::from_bytes(ee.decision_id),
    });
    let Prepared {
        mut draft,
        obs,
        window: _,
        ev: _,
    } = match prologue(ee, observer, ctx, draft) {
        Ok(p) => p,
        Err(r) => return r,
    };

    // Observer state gates lineage exactly as it gates actions.
    match obs.health.state {
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
                state_reason(obs.health.state).unwrap_or(ReasonCode::ObserverContinuityUnverified),
            )
        }
        ObserverState::Degraded => return draft.cannot_prove(ReasonCode::ObserverDegraded),
        ObserverState::Active => {}
    }

    // ── Observed side ──
    // 1. Edges whose child is the authorized instance.
    let edges: Vec<LineageEdge> = derive_lineage_edges(obs.batches.iter().copied())
        .into_iter()
        .filter(|e| e.child.matches_process_of(&ee.execution_binding))
        .collect();
    if edges.is_empty() {
        draft.lineage = LineageComparison::Incomplete;
        return draft.cannot_prove(ReasonCode::LineageEvidenceUnavailable);
    }
    if obs.health.probe_policy == ProbePolicy::Open {
        draft.lineage = LineageComparison::Incomplete;
        return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);
    }
    // 2. The carrying batch inside the collector's attested coverage.
    let covered = |seq: u64| {
        obs.batches
            .iter()
            .find(|b| b.sequence == seq)
            .is_some_and(|b| {
                obs.health.attested_coverage.is_some_and(|cov| {
                    cov.covers(&CoverageWindow {
                        from_ms: b.batch.claimed_from_ms,
                        to_ms: b.batch.claimed_to_ms,
                    })
                })
            })
    };
    let edges: Vec<LineageEdge> = edges
        .into_iter()
        .filter(|e| covered(e.batch_sequence))
        .collect();
    if edges.is_empty() {
        draft.lineage = LineageComparison::Incomplete;
        return draft.cannot_prove(ReasonCode::LineageEdgeNotCovered);
    }
    for e in &edges {
        draft.evidence.push(EvidenceRef::KernelEvent {
            batch_sequence: ObserverSequence(e.fork.batch_sequence),
            index: e.fork.index,
        });
        draft.evidence.push(EvidenceRef::KernelEvent {
            batch_sequence: ObserverSequence(e.exec.batch_sequence),
            index: e.exec.index,
        });
    }
    // Two different parent instances for one child instance cannot both be
    // true; report ambiguity rather than pick one.
    let mut parents: Vec<&aip_observe::ObservedProcess> = Vec::new();
    for e in &edges {
        if !parents.iter().any(|p| **p == e.parent) {
            parents.push(&e.parent);
        }
    }
    if parents.len() > 1 {
        draft.lineage = LineageComparison::Ambiguous {
            parent_candidates: parents.len() as u32,
        };
        return draft.cannot_prove(ReasonCode::LineageParentAmbiguous);
    }
    let parent = parents[0];

    // 3. Attribute the parent through verified peer expectations; and
    //    refuse a child that another agent's expectation also names.
    let peers: Vec<&ExpectedExecution> = li
        .peer_expectations
        .iter()
        .filter(|p| verify_expected_execution(p, &ctx.decision_point_anchors).is_ok())
        .collect();
    if peers.iter().any(|p| {
        p.agent_id != ee.agent_id
            && aip_observe::ObservedProcess {
                process: ee.execution_binding.process,
                exe_content_sha256: ee.execution_binding.exe_content_sha256,
                exe_path: String::new(),
            }
            .matches_process_of(&p.execution_binding)
    }) {
        draft.lineage = LineageComparison::Ambiguous {
            parent_candidates: 0,
        };
        return draft.cannot_prove(ReasonCode::LineageChildAmbiguous);
    }
    let mut parent_agents: Vec<(&str, &ExpectedExecution)> = Vec::new();
    for p in peers
        .iter()
        .filter(|p| parent.matches_process_of(&p.execution_binding))
    {
        if !parent_agents.iter().any(|(a, _)| *a == p.agent_id) {
            parent_agents.push((&p.agent_id, p));
        }
    }
    let (parent_agent, parent_ee) = match parent_agents.as_slice() {
        [] => {
            draft.lineage = LineageComparison::Incomplete;
            return draft.cannot_prove(ReasonCode::LineageParentUnattributed);
        }
        [one] => *one,
        many => {
            draft.lineage = LineageComparison::Ambiguous {
                parent_candidates: many.len() as u32,
            };
            return draft.cannot_prove(ReasonCode::LineageParentAmbiguous);
        }
    };
    draft.evidence.push(EvidenceRef::Expected {
        decision_point_id: DecisionPointId(parent_ee.decision_point_id.clone()),
        decision_id: DecisionId::from_bytes(parent_ee.decision_id),
    });

    // ── Claimed side ──
    // 4. The decision's authority chain: the tokens named by `AuthorityRef`,
    //    verified by aip_core, ending at this agent, in standing at the
    //    decision time, none revoked.
    let delegators = match li.authority.and_then(|a| verified_delegators(ee, a, li)) {
        Some(d) => d,
        None => {
            draft.lineage = LineageComparison::Incomplete;
            return draft.cannot_prove(ReasonCode::LineageAuthorityUnavailable);
        }
    };
    // 5. The identity parent: the agent's document, its proof verified
    //    against the offered parent document.
    let identity_parent = match li.identity.and_then(|i| verified_identity_parent(ee, i)) {
        Some(a) => a,
        None => {
            draft.lineage = LineageComparison::Incomplete;
            return draft.cannot_prove(ReasonCode::LineageIdentityUnavailable);
        }
    };

    // ── Decide ──
    let via = if parent_agent == ee.agent_id {
        Some(LineageLink::SelfSpawn)
    } else if delegators.iter().any(|d| d == parent_agent) {
        Some(LineageLink::Delegator)
    } else if identity_parent == parent_agent {
        Some(LineageLink::IdentityParent)
    } else {
        None
    };
    match via {
        Some(via) => {
            draft.lineage = LineageComparison::Consistent { via };
            draft.cannot_prove(ReasonCode::LineageConsistent)
        }
        None => {
            draft.lineage = LineageComparison::Contradicted;
            draft.finish(
                ReconciliationResult::LineageViolation,
                EvidenceStrength::Attested,
                ReasonCode::LineageContradicted,
            )
        }
    }
}

/// The delegators of a decision's authority, or `None` if the supplied
/// tokens are not that decision's, do not verify, end elsewhere, are out of
/// standing at the decision time, or include a revoked id.
fn verified_delegators(
    ee: &ExpectedExecution,
    a: &crate::inputs::DecisionAuthority,
    li: &LineageInputs<'_>,
) -> Option<Vec<String>> {
    use aip_core::capability::verify_scoped_token;
    use aip_core::delegation::verify_delegation_chain;

    let root = &a.root;
    if root.jti != ee.authority.root_jti {
        return None;
    }
    let chain_jtis: Vec<[u8; 16]> = a.chain.iter().map(|h| h.jti).collect();
    if chain_jtis != ee.authority.chain_jtis {
        return None;
    }
    if root.issuer_id == ee.agent_id || root.issuer_id == root.agent_id {
        return None;
    }
    let key = li.issuer_keys.get(&root.issuer_id)?;
    if !matches!(verify_scoped_token(root, key), Ok(true)) {
        return None;
    }
    verify_delegation_chain(root, &a.chain, li.issuer_keys).ok()?;
    let leaf = a
        .chain
        .last()
        .map(|h| h.grantee_id.as_str())
        .unwrap_or(root.agent_id.as_str());
    if leaf != ee.agent_id {
        return None;
    }
    if li.revoked_jtis.contains(&root.jti)
        || a.chain.iter().any(|h| li.revoked_jtis.contains(&h.jti))
    {
        return None;
    }
    let issued = a
        .chain
        .iter()
        .map(|h| h.issued_at)
        .fold(root.issued_at, u64::max);
    let expiry = a
        .chain
        .iter()
        .filter_map(|h| h.expires_at)
        .fold(root.expires_at, |acc, e| Some(acc.map_or(e, |x| x.min(e))));
    if ee.issued_at < issued || expiry.is_some_and(|x| ee.issued_at > x) {
        return None;
    }
    let mut d = vec![root.issuer_id.clone()];
    d.extend(a.chain.iter().map(|h| h.issuer_id.clone()));
    Some(d)
}

/// The identity parent named by a verified lineage proof, or `None`.
fn verified_identity_parent(
    ee: &ExpectedExecution,
    i: crate::inputs::IdentityLineageInput<'_>,
) -> Option<String> {
    use aip_core::{validate_aid, validate_aid_with_parent};
    if i.child.id != ee.agent_id {
        return None;
    }
    validate_aid(i.parent).ok()?;
    validate_aid_with_parent(i.child, &i.parent.id, &i.parent.primary_key.key_bytes).ok()?;
    Some(i.parent.id.clone())
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
    fn lineage_violation_is_refused_without_a_contradicted_lineage() {
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
