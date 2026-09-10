//! The enforcer's signed claim about one decision, and the standing table
//! that only exists because the enforcer is not the observer.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, ProcessInstance, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::decision::Decision;

pub const ENFORCEMENT_DECISION_DOMAIN: &str = "SYNTRIASS/GHOST/ENFORCEMENT_DECISION/v1";
pub const ENFORCEMENT_DECISION_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestKind {
    Exec,
    Connect,
}

impl RequestKind {
    fn code(&self) -> u8 {
        match self {
            RequestKind::Exec => 0x01,
            RequestKind::Connect => 0x02,
        }
    }
}

/// What the enforcer says it decided. A claim: it establishes that the
/// enforcer signed this, and nothing about what the workload then did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub version: u16,
    pub enforcer_id: String,
    pub agent_id: String,
    /// The active epoch at decision time, if any.
    pub epoch_id: Option<[u8; 16]>,
    /// The requesting process instance as the supervisor measured it —
    /// `None` when the measurement failed, never a guess.
    pub process: Option<ProcessInstance>,
    pub request: RequestKind,
    /// Content hash of the program, when one was obtained.
    pub program_hash: Option<[u8; 32]>,
    pub decision: Decision,
    pub decided_at_ms: u64,
}

impl EnforcementDecision {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, ENFORCEMENT_DECISION_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.enforcer_id);
        put_str(&mut buf, &self.agent_id);
        match &self.epoch_id {
            Some(id) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(id);
            }
            None => put_u8(&mut buf, 0),
        }
        match &self.process {
            Some(p) => {
                put_u8(&mut buf, 1);
                put_u32(&mut buf, p.pid);
                put_u64(&mut buf, p.pid_start_time_ticks);
                buf.extend_from_slice(&p.boot_id);
            }
            None => put_u8(&mut buf, 0),
        }
        put_u8(&mut buf, self.request.code());
        match &self.program_hash {
            Some(h) => {
                put_u8(&mut buf, 1);
                buf.extend_from_slice(h);
            }
            None => put_u8(&mut buf, 0),
        }
        match self.decision {
            Decision::Allow => {
                put_u8(&mut buf, 0x01);
                put_u8(&mut buf, 0);
                put_u8(&mut buf, 0);
            }
            Decision::Deny(reason) => {
                let (a, b) = reason.codes();
                put_u8(&mut buf, 0x02);
                put_u8(&mut buf, a);
                put_u8(&mut buf, b);
            }
        }
        put_u64(&mut buf, self.decided_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnforcementDecision {
    pub decision: EnforcementDecision,
    pub attestation: Signature,
}

impl SignedEnforcementDecision {
    pub fn sign(
        decision: EnforcementDecision,
        enforcer_private_key: &[u8],
    ) -> Result<Self, AipError> {
        let attestation = sign_ed25519(
            enforcer_private_key,
            &decision.enforcer_id,
            &decision.canonical_bytes(),
        )?;
        Ok(Self {
            decision,
            attestation,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct EnforcerAnchors {
    keys: BTreeMap<String, Vec<u8>>,
}

impl EnforcerAnchors {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn trust(mut self, enforcer_id: &str, public_key: &[u8]) -> Self {
        self.keys
            .insert(enforcer_id.to_string(), public_key.to_vec());
        self
    }
    pub fn get(&self, enforcer_id: &str) -> Option<&[u8]> {
        self.keys.get(enforcer_id).map(|k| k.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    UnsupportedVersion(u16),
    EnforcerNotAnchored(String),
    SignerIsNotEnforcer,
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(AipError),
}

pub fn verify_decision<'a>(
    signed: &'a SignedEnforcementDecision,
    anchors: &EnforcerAnchors,
) -> Result<&'a EnforcementDecision, RecordError> {
    let d = &signed.decision;
    if d.version != ENFORCEMENT_DECISION_VERSION {
        return Err(RecordError::UnsupportedVersion(d.version));
    }
    let key = anchors
        .get(&d.enforcer_id)
        .ok_or_else(|| RecordError::EnforcerNotAnchored(d.enforcer_id.clone()))?;
    if signed.attestation.signer_id != d.enforcer_id {
        return Err(RecordError::SignerIsNotEnforcer);
    }
    if signed.attestation.payload_hash != d.digest() {
        return Err(RecordError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => Ok(d),
        Ok(false) => Err(RecordError::SignatureInvalid),
        Err(e) => Err(RecordError::Crypto(e)),
    }
}

// ─── The standing table (ADR-008 §2) ───

/// What the enforcer claims it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcerClaim {
    Denied,
    Allowed,
}

/// What the observer — a different component, with a different key,
/// consulted separately — found for the same instance and window. This
/// crate defines the shape so the table can be stated; it never produces
/// one, because producing one is observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverFinding {
    ExecutionObserved,
    /// Covered by a gate-independent mechanism and nothing seen.
    NoExecutionObserved,
    /// Not covered, or the observer could not vouch for the window.
    ObservationUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStanding {
    /// Denied, and independently nothing ran. The gate held.
    Held,
    /// Denied, and independently something ran. **The enforcer was
    /// bypassed.** This is the row the whole separation exists for.
    Bypassed,
    /// Allowed and observed. The ordinary path.
    Ordinary,
    /// Allowed and nothing ran. The workload did not use its permission;
    /// not a violation.
    Unexercised,
    /// The observer cannot vouch for the window. A denial is *not* confirmed
    /// held by the observer's silence — the same rule as everywhere else.
    CannotEstablish,
}

/// Join an enforcer claim with an observer finding.
pub fn standing(claim: EnforcerClaim, finding: ObserverFinding) -> EnforcementStanding {
    match (claim, finding) {
        (_, ObserverFinding::ObservationUnavailable) => EnforcementStanding::CannotEstablish,
        (EnforcerClaim::Denied, ObserverFinding::NoExecutionObserved) => EnforcementStanding::Held,
        (EnforcerClaim::Denied, ObserverFinding::ExecutionObserved) => {
            EnforcementStanding::Bypassed
        }
        (EnforcerClaim::Allowed, ObserverFinding::ExecutionObserved) => {
            EnforcementStanding::Ordinary
        }
        (EnforcerClaim::Allowed, ObserverFinding::NoExecutionObserved) => {
            EnforcementStanding::Unexercised
        }
    }
}
