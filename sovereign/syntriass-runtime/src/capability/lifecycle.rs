//! Capability lifecycle: states, permitted transitions, and signed approvals.
//!
//! ```text
//! PROPOSED → TESTING → VALIDATED → APPROVED → ACTIVE
//!     ↘          ↘          ↘          ↘        ↓ ↑
//!                    REJECTED          SUSPENDED / REVOKED / SUPERSEDED
//! ```
//!
//! SUPERSEDED → ACTIVE (approver only) is the rollback edge.
//!
//! Only ACTIVE capabilities execute. Every transition names an actor and a
//! role; the table in [`allowed`] is the whole policy. TESTING → VALIDATED
//! requires a passing [`ValidationReport`] for the *same content hash*;
//! VALIDATED → APPROVED requires an Ed25519-signed [`Approval`] from a
//! principal other than the proposer.

use serde::{Deserialize, Serialize};

use super::artifact::Capability;
use super::validate::ValidationReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Proposed,
    Testing,
    Validated,
    Approved,
    Active,
    Rejected,
    Suspended,
    Revoked,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The runtime's validation component.
    Validator,
    /// A human authority who may approve or revoke.
    Approver,
    /// Installation operator: activates approved capabilities.
    Operator,
}

/// Edge table: (from, to, roles permitted).
pub fn allowed(from: State, to: State) -> &'static [Role] {
    use Role::*;
    use State::*;
    match (from, to) {
        (Proposed, Testing) => &[Validator],
        (Testing, Validated) => &[Validator],
        (Proposed | Testing, Rejected) => &[Validator, Approver],
        (Validated | Approved, Rejected) => &[Approver],
        (Validated, Approved) => &[Approver],
        (Approved, Active) => &[Operator],
        (Active, Suspended) => &[Approver, Operator, Validator],
        (Active | Suspended | Approved, Revoked) => &[Approver],
        (Suspended, Active) => &[Approver],
        (Active, Superseded) => &[Operator],
        // Rollback: a previously approved version is re-activated by an
        // approver (its validation and approval records are unchanged and
        // still required by `executable`).
        (Superseded, Active) => &[Approver],
        (Superseded, Revoked) => &[Approver],
        _ => &[],
    }
}

/// Signed approval of one exact artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub capability_hash: String,
    pub validation_report_hash: String,
    pub approver_id: String,
    pub consequential: bool,
    pub decided_at_ms: u64,
    pub signature_hex: String,
}

impl Approval {
    /// Bytes covered by the signature (domain-separated, fixed field order).
    pub fn signed_bytes(
        cap_hash: &str,
        report_hash: &str,
        approver: &str,
        consequential: bool,
        at: u64,
    ) -> Vec<u8> {
        format!("syntriass-capability-approval/v1\n{cap_hash}\n{report_hash}\n{approver}\n{consequential}\n{at}").into_bytes()
    }

    /// Sign an approval.
    pub fn sign(
        cap_hash: &str,
        report: &ValidationReport,
        approver_id: &str,
        consequential: bool,
        at: u64,
        private_key: &[u8],
    ) -> Result<Self, String> {
        let rh = report_hash(report);
        let sig = aip_crypto::sign_ed25519_raw(
            private_key,
            &Self::signed_bytes(cap_hash, &rh, approver_id, consequential, at),
        )
        .map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            capability_hash: cap_hash.into(),
            validation_report_hash: rh,
            approver_id: approver_id.into(),
            consequential,
            decided_at_ms: at,
            signature_hex: hex::encode(sig),
        })
    }

    /// Verify with the approver's public key (offline).
    pub fn verify(&self, public_key: &[u8]) -> bool {
        let Ok(raw) = hex::decode(&self.signature_hex) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(raw.as_slice()) else {
            return false;
        };
        aip_crypto::verify_ed25519_raw(
            public_key,
            &Self::signed_bytes(
                &self.capability_hash,
                &self.validation_report_hash,
                &self.approver_id,
                self.consequential,
                self.decided_at_ms,
            ),
            &sig,
        )
    }
}

/// Hash of a validation report's canonical JSON.
pub fn report_hash(r: &ValidationReport) -> String {
    hex::encode(aip_crypto::sha256(
        &serde_json::to_vec(r).unwrap_or_default(),
    ))
}

/// One recorded transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    pub from: State,
    pub to: State,
    pub actor: String,
    pub role: Role,
    pub at_ms: u64,
    pub reason: String,
}

/// Lifecycle record for one artifact version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub capability: Capability,
    pub capability_hash: String,
    pub state: State,
    pub validation: Option<ValidationReport>,
    pub approval: Option<Approval>,
    pub history: Vec<Transition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    NotPermitted { from: State, to: State, role: Role },
    HashMismatch,
    ValidationMissingOrFailed,
    ApprovalInvalid(&'static str),
    SelfApproval,
}

impl Record {
    /// New record in PROPOSED.
    pub fn propose(cap: Capability) -> Self {
        let h = cap.content_hash();
        Self {
            capability: cap,
            capability_hash: h,
            state: State::Proposed,
            validation: None,
            approval: None,
            history: vec![],
        }
    }

    fn step(
        &mut self,
        to: State,
        actor: &str,
        role: Role,
        at: u64,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        if !allowed(self.state, to).contains(&role) {
            return Err(LifecycleError::NotPermitted {
                from: self.state,
                to,
                role,
            });
        }
        if self.capability.content_hash() != self.capability_hash {
            return Err(LifecycleError::HashMismatch);
        }
        self.history.push(Transition {
            from: self.state,
            to,
            actor: actor.into(),
            role,
            at_ms: at,
            reason: reason.into(),
        });
        self.state = to;
        Ok(())
    }

    /// PROPOSED → TESTING.
    pub fn start_testing(&mut self, actor: &str, at: u64) -> Result<(), LifecycleError> {
        self.step(
            State::Testing,
            actor,
            Role::Validator,
            at,
            "validation started",
        )
    }

    /// TESTING → VALIDATED or REJECTED according to the report.
    pub fn record_validation(
        &mut self,
        report: ValidationReport,
        actor: &str,
        at: u64,
    ) -> Result<(), LifecycleError> {
        if report.capability_hash != self.capability_hash {
            return Err(LifecycleError::HashMismatch);
        }
        let to = if report.passed {
            State::Validated
        } else {
            State::Rejected
        };
        let reason = if report.passed {
            "all independent expert cases passed".to_string()
        } else {
            format!("{} failures", report.failures.len())
        };
        self.step(to, actor, Role::Validator, at, &reason)?;
        self.validation = Some(report);
        Ok(())
    }

    /// VALIDATED → APPROVED with a verified signature from a non-proposer.
    pub fn approve(
        &mut self,
        a: Approval,
        approver_public_key: &[u8],
        at: u64,
    ) -> Result<(), LifecycleError> {
        let report = self
            .validation
            .as_ref()
            .filter(|r| r.passed)
            .ok_or(LifecycleError::ValidationMissingOrFailed)?;
        if a.capability_hash != self.capability_hash {
            return Err(LifecycleError::HashMismatch);
        }
        if a.validation_report_hash != report_hash(report) {
            return Err(LifecycleError::ApprovalInvalid("report hash"));
        }
        if a.approver_id == self.capability.proposed_by {
            return Err(LifecycleError::SelfApproval);
        }
        if !a.verify(approver_public_key) {
            return Err(LifecycleError::ApprovalInvalid("signature"));
        }
        let who = a.approver_id.clone();
        self.step(State::Approved, &who, Role::Approver, at, "signed approval")?;
        self.approval = Some(a);
        Ok(())
    }

    /// Any other permitted transition (activate, suspend, revoke, supersede, reject).
    pub fn transition(
        &mut self,
        to: State,
        actor: &str,
        role: Role,
        at: u64,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        if matches!(to, State::Validated | State::Approved) {
            return Err(LifecycleError::NotPermitted {
                from: self.state,
                to,
                role,
            });
        }
        self.step(to, actor, role, at, reason)
    }

    /// May this record execute now?
    pub fn executable(&self) -> bool {
        self.state == State::Active
            && self.approval.is_some()
            && self.validation.as_ref().is_some_and(|r| r.passed)
            && self.capability.content_hash() == self.capability_hash
    }
}
