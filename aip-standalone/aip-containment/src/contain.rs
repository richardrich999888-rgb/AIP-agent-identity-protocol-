//! The boundary itself: every gate, in order, then the actuator.
//!
//! ```text
//!  1. warrant authenticated under the warrant trust root, distinct from
//!     this authority's key                          → WarrantInvalid
//!  2. now inside [issued_at, valid_until]           → NotYetValid / Expired
//!  3. response == Contain                           → ResponseNotContain
//!  4. target == Workload                            → TargetNotWorkload
//!  5. strength == Proven (explicit match)           → StrengthBelowProven
//!  6. result is a workload violation                → ResultNotWorkloadViolation
//!  7. observation was not Unavailable               → ObservationUnavailable
//!  8. evidence references present                   → NoEvidenceReference
//!  9. engine issued it autonomous, not protected    → WarrantNotAutonomous /
//!                                                      WarrantMarkedProtected
//! 10. warrant subject == target agent               → SubjectUnbound / Mismatch
//! 11. no protected identity involved                → Protected
//! 12. mode permits: Advisory records; OperatorEnabled
//!     needs an acknowledgement naming this warrant  → OperatorAcknowledgement*
//! 13. current signed health from a cited observer,
//!     Active, fresh                                 → ObserverHealth* / NotActive /
//!                                                      NotCited
//! 14. warrant id not consumed                       → Replayed
//! 15. target attributed live through a pidfd        → Attribution(..)
//! 16. consume the warrant id, durably
//! 17. actuate; Applied only on confirmed effect, Failed otherwise
//! ```
//!
//! Every exit is a signed record. Steps 1–15 touch nothing.

use aip_crypto::sha256;
use aip_observe::{verify_signed_health, ObserverState, SignedSensorHealth};
use aip_reconcile::{EvidenceRef, EvidenceStrength, ReconciliationResult};
use aip_types::canonical::*;
use aip_types::{AipError, ExecutionBinding};
use aip_warrant::{
    verify_warrant_distinct, ResponseClass, ResponseTarget, Warrant, WarrantTrustAnchors,
};

use crate::actuator::{Actuator, Applied};
use crate::attribution::attribute;
use crate::record::{
    ContainmentAction, ContainmentAuthority, ContainmentDecision, ContainmentMode,
    ContainmentPolicy, ContainmentRecord, OperatorAcknowledgement, Outcome, Refusal,
    SignedContainmentRecord, TargetIdentity, CONTAINMENT_DOMAIN, CONTAINMENT_VERSION,
};
use crate::replay::ReplayLedger;

/// The trust roots the boundary verifies against: the warrant authority's
/// keys and the observers' keys.
#[derive(Debug, Clone, Default)]
pub struct ContainmentAnchors {
    pub warrant: WarrantTrustAnchors,
    pub observer: aip_observe::ObserverTrustAnchors,
}

/// One request. A warrant, the binding the request claims it concerns,
/// the newest signed health of the cited observer, and — under
/// `OperatorEnabled` — an operator's acknowledgement.
#[derive(Debug, Clone)]
pub struct ContainmentRequest<'a> {
    pub warrant: &'a Warrant,
    pub target: &'a ExecutionBinding,
    pub observer_health: Option<&'a SignedSensorHealth>,
    pub operator_ack: Option<&'a OperatorAcknowledgement>,
}

/// A confirmed effect, held so it can be released through the same
/// actuator and recorded under the same decision.
#[derive(Debug)]
pub struct Hold {
    pub decision: ContainmentDecision,
    pub applied: Applied,
}

/// The result of one attempt: the signed record, and the hold when an
/// effect was confirmed.
#[derive(Debug)]
pub struct Containment {
    pub record: SignedContainmentRecord,
    pub hold: Option<Hold>,
}

impl Containment {
    /// Was an effect confirmed? True only for `Outcome::Applied`.
    pub fn actuated(&self) -> bool {
        matches!(self.record.record.outcome, Outcome::Applied { .. })
    }
}

fn decision_id(
    warrant_id: &[u8; 16],
    target: &TargetIdentity,
    policy_version: u32,
    now: u64,
) -> [u8; 16] {
    let mut b = Vec::new();
    put_domain(&mut b, CONTAINMENT_DOMAIN);
    b.extend_from_slice(warrant_id);
    put_str(&mut b, &target.agent_id);
    put_u32(&mut b, target.process.pid);
    put_u64(&mut b, target.process.pid_start_time_ticks);
    b.extend_from_slice(&target.process.boot_id);
    b.extend_from_slice(&target.exe_content_sha256);
    put_u32(&mut b, policy_version);
    put_u64(&mut b, now);
    let h = sha256(&b);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

fn cited_observers(refs: &[EvidenceRef]) -> Vec<&str> {
    refs.iter()
        .filter_map(|r| match r {
            EvidenceRef::Batch { observer_id, .. } | EvidenceRef::Health { observer_id, .. } => {
                Some(observer_id.0.as_str())
            }
            _ => None,
        })
        .collect()
}

/// Which protected identity, if any, this warrant involves.
fn protected_identity(w: &Warrant, target_agent: &str, p: &ContainmentPolicy) -> Option<String> {
    if p.protected.contains_agent(target_agent) {
        return Some(target_agent.to_string());
    }
    for r in &w.evidence_refs {
        match r {
            EvidenceRef::Expected {
                decision_point_id, ..
            }
            | EvidenceRef::CoverageStatement {
                decision_point_id, ..
            } => {
                if p.protected.contains_decision_point(&decision_point_id.0) {
                    return Some(decision_point_id.0.clone());
                }
            }
            EvidenceRef::Batch { observer_id, .. } | EvidenceRef::Health { observer_id, .. } => {
                if p.protected.contains_observer(&observer_id.0) {
                    return Some(observer_id.0.clone());
                }
            }
            EvidenceRef::Observation { .. } | EvidenceRef::KernelEvent { .. } => {}
        }
    }
    None
}

/// The gates, returning the first refusal.
fn gates(
    req: &ContainmentRequest<'_>,
    policy: &ContainmentPolicy,
    anchors: &ContainmentAnchors,
    ledger: &dyn ReplayLedger,
    authority: &ContainmentAuthority,
    now_ms: u64,
) -> Result<(), Refusal> {
    let w = req.warrant;
    // 1
    verify_warrant_distinct(w, &anchors.warrant, &[authority.public_key()])
        .map_err(|e| Refusal::WarrantInvalid(format!("{e:?}")))?;
    // 2
    let valid_until = w.valid_until.ok_or(Refusal::NoValidityBound)?;
    if now_ms < w.issued_at {
        return Err(Refusal::WarrantNotYetValid {
            issued_at: w.issued_at,
            now: now_ms,
        });
    }
    if now_ms > valid_until {
        return Err(Refusal::WarrantExpired {
            valid_until,
            now: now_ms,
        });
    }
    // 3
    if w.response != ResponseClass::Contain {
        return Err(Refusal::ResponseNotContain(format!("{:?}", w.response)));
    }
    // 4
    if w.target != ResponseTarget::Workload {
        return Err(Refusal::TargetNotWorkload);
    }
    // 5 — explicit match, no ordering, no arithmetic.
    match w.evidence_strength {
        EvidenceStrength::Proven => {}
        other @ (EvidenceStrength::Heuristic
        | EvidenceStrength::Correlated
        | EvidenceStrength::Attested) => return Err(Refusal::StrengthBelowProven(other)),
    }
    // 6
    match w.reconciliation_result {
        ReconciliationResult::UnattributedEffect
        | ReconciliationResult::PhantomClaim
        | ReconciliationResult::IdentityDivergence
        | ReconciliationResult::LineageViolation => {}
        other @ (ReconciliationResult::VerifiedExecution
        | ReconciliationResult::SensorIntegrityFailure
        | ReconciliationResult::ContinuityFailure
        | ReconciliationResult::CannotProve) => {
            return Err(Refusal::ResultNotWorkloadViolation(other))
        }
    }
    // 7
    if w.observation_unavailable {
        return Err(Refusal::ObservationUnavailable);
    }
    // 8
    if w.evidence_refs.is_empty() {
        return Err(Refusal::NoEvidenceReference);
    }
    // 9
    if !w.autonomous {
        return Err(Refusal::WarrantNotAutonomous);
    }
    if w.protected {
        return Err(Refusal::WarrantMarkedProtected);
    }
    // 10
    let subject = w.subject_agent.as_deref().ok_or(Refusal::SubjectUnbound)?;
    if subject != req.target.agent_id {
        return Err(Refusal::SubjectMismatch {
            warrant_subject: subject.to_string(),
            target_agent: req.target.agent_id.clone(),
        });
    }
    // 11
    if let Some(identity) = protected_identity(w, subject, policy) {
        return Err(Refusal::Protected { identity });
    }
    // 12
    match policy.mode {
        ContainmentMode::Advisory => {}
        ContainmentMode::AutonomousEnabled => {}
        ContainmentMode::OperatorEnabled => {
            let ack = req
                .operator_ack
                .ok_or(Refusal::OperatorAcknowledgementMissing)?;
            if ack.warrant_id != w.warrant_id {
                return Err(Refusal::OperatorAcknowledgementMismatch);
            }
        }
    }
    // 13
    let health = req.observer_health.ok_or(Refusal::ObserverHealthMissing)?;
    verify_signed_health(health, &anchors.observer)
        .map_err(|e| Refusal::ObserverHealthUntrusted(format!("{e:?}")))?;
    let cited = cited_observers(&w.evidence_refs);
    if !cited.contains(&health.health.observer_id.as_str()) {
        return Err(Refusal::ObserverNotCited {
            observer_id: health.health.observer_id.clone(),
        });
    }
    if now_ms.saturating_sub(health.health.emitted_at_ms) > policy.max_health_age_ms {
        return Err(Refusal::ObserverHealthStale {
            emitted_at_ms: health.health.emitted_at_ms,
            now: now_ms,
        });
    }
    match health.health.state {
        ObserverState::Active => {}
        other => return Err(Refusal::ObserverNotActive(other)),
    }
    // 14
    if ledger.is_consumed(&w.warrant_id) {
        return Err(Refusal::Replayed {
            warrant_id: w.warrant_id,
        });
    }
    Ok(())
}

/// Decide and, when every gate passes and the policy permits, act.
///
/// Returns `Err` only when the record itself could not be signed; every
/// other condition is a signed record with the outcome inside.
pub fn contain<A: Actuator, L: ReplayLedger>(
    req: &ContainmentRequest<'_>,
    policy: &ContainmentPolicy,
    anchors: &ContainmentAnchors,
    ledger: &mut L,
    actuator: &mut A,
    authority: &ContainmentAuthority,
    now_ms: u64,
) -> Result<Containment, AipError> {
    let w = req.warrant;
    let target = TargetIdentity {
        agent_id: req.target.agent_id.clone(),
        process: req.target.process,
        exe_content_sha256: req.target.exe_content_sha256,
    };
    let decision = ContainmentDecision {
        version: CONTAINMENT_VERSION,
        decision_id: decision_id(&w.warrant_id, &target, policy.version, now_ms),
        warrant_id: w.warrant_id,
        warrant_digest: sha256(&w.signing_preimage()),
        reconciliation_digest: w.reconciliation_digest,
        reconciliation_result: w.reconciliation_result,
        evidence_strength: w.evidence_strength,
        evidence_refs: w.evidence_refs.clone(),
        target,
        action: policy.action,
        mode: policy.mode,
        policy_version: policy.version,
        warrant_autonomous: w.autonomous,
        decided_at_ms: now_ms,
        valid_until: w.valid_until,
    };
    let finish = |decision: ContainmentDecision, outcome: Outcome, hold: Option<Hold>| {
        let record = authority.sign(ContainmentRecord {
            version: CONTAINMENT_VERSION,
            decision,
            outcome,
            recorded_at_ms: now_ms,
        })?;
        Ok(Containment { record, hold })
    };

    if let Err(r) = gates(req, policy, anchors, ledger, authority, now_ms) {
        return finish(decision, Outcome::Refused(r), None);
    }
    // 15
    let attributed = match attribute(req.target) {
        Ok(a) => a,
        Err(e) => return finish(decision, Outcome::Refused(Refusal::Attribution(e)), None),
    };
    // Advisory: decided, recorded, nothing done, nothing consumed.
    if policy.mode == ContainmentMode::Advisory || policy.action == ContainmentAction::AdvisoryOnly
    {
        return finish(decision, Outcome::Advisory, None);
    }
    // 16 — consumed before actuation, so a failure is not retried
    // destructively by default and a replay meets the ledger.
    if let Err(reason) = ledger.consume(&w.warrant_id) {
        return finish(
            decision,
            Outcome::Failed(crate::actuator::ActuationFailure::Stage {
                stage: "ledger".into(),
                reason,
            }),
            None,
        );
    }
    // 17
    match actuator.apply(&attributed, policy.action) {
        Ok(applied) => {
            let outcome = Outcome::Applied {
                mechanism: applied.mechanism,
                handle: applied.handle.clone(),
            };
            let hold = Hold {
                decision: decision.clone(),
                applied,
            };
            finish(decision, outcome, Some(hold))
        }
        Err(f) => finish(decision, Outcome::Failed(f), None),
    }
}

/// Undo a confirmed effect through the same actuator, recording the result
/// under the original decision.
pub fn release<A: Actuator>(
    hold: Hold,
    actuator: &mut A,
    authority: &ContainmentAuthority,
    now_ms: u64,
) -> Result<SignedContainmentRecord, AipError> {
    let outcome = match actuator.release(&hold.applied) {
        Ok(()) => Outcome::Released {
            mechanism: hold.applied.mechanism,
            handle: hold.applied.handle.clone(),
        },
        Err(f) => Outcome::Failed(f),
    };
    authority.sign(ContainmentRecord {
        version: CONTAINMENT_VERSION,
        decision: hold.decision,
        outcome,
        recorded_at_ms: now_ms,
    })
}
