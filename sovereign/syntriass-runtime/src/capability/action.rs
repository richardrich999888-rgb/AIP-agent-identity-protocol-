//! Signed lifecycle actions: who moved one exact record across one edge.
//!
//! Before this module, activation, supersession, rollback, suspension and
//! revocation recorded whatever `--actor` and `--role` strings the caller
//! passed, and nothing at use time checked how a record came to be ACTIVE:
//! a stored record whose `state` was edited to `ACTIVE` executed.
//!
//! A [`SignedAction`] is an Ed25519 signature, by a configured operator or
//! approver key, over one transition of one record. It binds:
//!
//! - the capability content hash, so it cannot be moved to another record;
//! - the edge (`from` → `to`) and the role, checked against
//!   [`super::lifecycle::allowed`];
//! - `seq`, the index the transition takes in the record's history, and
//!   `prev_chain`, a hash of the history before it, so a signature cannot be
//!   replayed at another position in the same record's life (for example, an
//!   old "resume" re-applied after a later suspension);
//! - the signer id, time and reason exactly as recorded.
//!
//! **Not provided, and stated so it is not assumed:** freshness against a
//! storage rollback. Whoever can rewrite the state directory can truncate a
//! record's history back to an older, genuinely signed activation; every
//! remaining signature still verifies. Detecting that needs the history
//! anchored in an append-only log, which this module does not do.
//!
//! Pure: no IO, no clock. Time is passed in.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::authority::ApprovalPolicy;
use super::lifecycle::{allowed, Record, Role, State, Transition};

/// Domain separation for the signed bytes.
const ACTION_DOMAIN: &[u8] = b"syntriass-lifecycle-action/v1\n";
/// Domain separation for the history chain hash.
const CHAIN_DOMAIN: &[u8] = b"syntriass-lifecycle-history/v1\n";

/// One signed lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAction {
    pub capability_hash: String,
    pub from: State,
    pub to: State,
    pub role: Role,
    pub signer_id: String,
    /// Index this transition takes in the record's history.
    pub seq: u64,
    /// [`history_chain`] of the history before this transition.
    pub prev_chain: String,
    pub at_ms: u64,
    pub reason: String,
    pub signature_hex: String,
}

/// SHA-256 over the canonical JSON of a history prefix, domain separated.
pub fn history_chain(history: &[Transition]) -> String {
    let mut bytes = CHAIN_DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(history).expect("transitions contain no fallible JSON values"));
    hex::encode(aip_crypto::sha256(&bytes))
}

impl SignedAction {
    /// The exact bytes the signature covers (every field but the signature).
    pub fn payload(&self) -> Vec<u8> {
        let mut bytes = ACTION_DOMAIN.to_vec();
        bytes.extend(
            serde_json::to_vec(&(
                &self.capability_hash,
                self.from,
                self.to,
                self.role,
                &self.signer_id,
                self.seq,
                &self.prev_chain,
                self.at_ms,
                &self.reason,
            ))
            .expect("action contains no fallible JSON values"),
        );
        bytes
    }

    /// Sign the transition of `record` from its current state to `to`.
    pub fn sign(
        record: &Record,
        to: State,
        role: Role,
        signer_id: &str,
        at_ms: u64,
        reason: &str,
        private_key: &[u8],
    ) -> Result<Self, String> {
        let mut action = Self {
            capability_hash: record.capability_hash.clone(),
            from: record.state,
            to,
            role,
            signer_id: signer_id.into(),
            seq: record.history.len() as u64,
            prev_chain: history_chain(&record.history),
            at_ms,
            reason: reason.into(),
            signature_hex: String::new(),
        };
        let sig = aip_crypto::sign_ed25519_raw(private_key, &action.payload())
            .map_err(|e| format!("{e:?}"))?;
        action.signature_hex = hex::encode(sig);
        Ok(action)
    }

    /// Verify the signature with the signer's public key (offline).
    pub fn verify(&self, public_key: &[u8]) -> bool {
        let Ok(raw) = hex::decode(&self.signature_hex) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(raw.as_slice()) else {
            return false;
        };
        aip_crypto::verify_ed25519_raw(public_key, &self.payload(), &sig)
    }

    /// Does this action apply to `record` as it stands now?
    pub fn applies_to(&self, record: &Record) -> Result<(), &'static str> {
        if self.capability_hash != record.capability_hash {
            return Err("signed action is for another capability");
        }
        if self.from != record.state {
            return Err("signed action starts from another state");
        }
        if self.seq != record.history.len() as u64
            || self.prev_chain != history_chain(&record.history)
        {
            return Err("signed action is for another point in the record's history");
        }
        if !allowed(self.from, self.to).contains(&self.role) {
            return Err("role not permitted on this edge");
        }
        Ok(())
    }
}

/// Trust anchors for signed actions: one key store per role.
///
/// The validator role has no key here on purpose: validator transitions are
/// made by the runtime's own validation, never claimed by a caller.
pub struct ActionKeys<'a> {
    pub operators: &'a BTreeMap<String, Vec<u8>>,
    pub approvers: &'a BTreeMap<String, Vec<u8>>,
    pub policy: Option<&'a ApprovalPolicy>,
}

impl ActionKeys<'_> {
    /// The public key `signer` may use in `role`, and, for an approver under
    /// strict policy, a current authority grant covering `record`.
    pub fn authorize(
        &self,
        record: &Record,
        role: Role,
        signer: &str,
        at_ms: u64,
        now: u64,
    ) -> Result<&[u8], &'static str> {
        let key = match role {
            Role::Operator => self
                .operators
                .get(signer)
                .ok_or("signer is not a configured operator")?,
            Role::Approver => self
                .approvers
                .get(signer)
                .ok_or("signer is not a configured approver")?,
            Role::Validator => return Err("validator transitions cannot be signed by a caller"),
        };
        if role == Role::Approver {
            if let Some(policy) = self.policy {
                policy
                    .grant(signer)?
                    .authorize(&record.capability, signer, key, at_ms, now)?;
            }
        }
        Ok(key)
    }
}

/// Use-time check: may a record that says it is ACTIVE be trusted to be?
///
/// The state must follow from the last transition, and that transition must
/// be a signed move into ACTIVE whose recorded fields equal the signed ones,
/// at its own position in the history, by a signer currently authorized for
/// its role.
pub fn check_active(record: &Record, keys: &ActionKeys<'_>, now: u64) -> Result<(), &'static str> {
    if record.state != State::Active {
        return Err("record is not active");
    }
    let (last, before) = record
        .history
        .split_last()
        .ok_or("active record has no history")?;
    if last.to != State::Active {
        return Err("stored state does not follow from the recorded history");
    }
    let action = last
        .action
        .as_ref()
        .ok_or("activation is not signed; signed lifecycle required")?;
    let recorded = (
        last.from,
        last.to,
        last.role,
        last.actor.as_str(),
        last.at_ms,
        last.reason.as_str(),
    );
    let signed = (
        action.from,
        action.to,
        action.role,
        action.signer_id.as_str(),
        action.at_ms,
        action.reason.as_str(),
    );
    if recorded != signed || action.capability_hash != record.capability_hash {
        return Err("recorded transition differs from its signed action");
    }
    if action.seq != before.len() as u64 || action.prev_chain != history_chain(before) {
        return Err("signed activation is for another point in the record's history");
    }
    if !allowed(action.from, action.to).contains(&action.role) {
        return Err("role not permitted on this edge");
    }
    let key = keys.authorize(record, action.role, &action.signer_id, action.at_ms, now)?;
    if !action.verify(key) {
        return Err("signed activation signature invalid");
    }
    Ok(())
}
