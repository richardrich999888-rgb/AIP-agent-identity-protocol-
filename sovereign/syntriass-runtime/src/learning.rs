//! Capability lifecycle orchestration (IO layer over the pure
//! [`crate::capability`] modules): bind evidence, propose, validate, approve,
//! activate, revoke. No decision logic lives here — the transition table,
//! validation rules and approval checks are in `capability::{lifecycle,validate}`.
//!
//! Evidence binding rule: a proposal *names* the documents it encodes; the
//! digests are filled in by this module from the corpus, read as the
//! capability's own tenant at its required clearance. A proposer can never
//! supply or vouch for evidence content.

use std::collections::BTreeMap;

use vanian_sovereign::adapters::sqlite_corpus::SqliteCorpus;
use vanian_sovereign::domain::corpus::{Classification, Ident, Principal};
use vanian_sovereign::ports::{PortError, PortErrorKind};

use crate::capability::artifact::Capability;
use crate::capability::lifecycle::{Approval, LifecycleError, Record, Role, State};
use crate::capability::suite::ExpertSuite;
use crate::capability::validate::{validate, ValidationReport};
use crate::ports::CapabilityStore;

fn err(kind: PortErrorKind, m: impl Into<String>) -> PortError {
    PortError::new(kind, m)
}

fn life(e: LifecycleError) -> PortError {
    err(
        PortErrorKind::ContractViolation,
        format!("lifecycle: {e:?}"),
    )
}

/// The principal a capability's evidence is read as (its own tenant and
/// required clearance — never broader).
pub fn evidence_reader(cap: &Capability) -> Result<Principal, PortError> {
    Ok(Principal {
        tenant: Ident::new(&cap.required.tenant)
            .map_err(|e| err(PortErrorKind::InvalidInput, e.to_string()))?,
        clearance: Classification::parse(&cap.required.min_clearance)
            .map_err(|e| err(PortErrorKind::InvalidInput, e.to_string()))?,
    })
}

/// Replace `dependencies.knowledge` with digests read from the corpus for
/// every document id the proposal names. Unknown or unreadable documents are
/// an error (fail closed).
pub fn bind_evidence(cap: &mut Capability, corpus: &SqliteCorpus) -> Result<(), PortError> {
    let reader = evidence_reader(cap)?;
    let names: Vec<String> = cap.dependencies.knowledge.keys().cloned().collect();
    if names.is_empty() {
        return Err(err(
            PortErrorKind::InvalidInput,
            "proposal names no evidence documents",
        ));
    }
    let mut bound = BTreeMap::new();
    for d in names {
        let h = corpus.document_digest(&reader, &d)?.ok_or_else(|| {
            err(
                PortErrorKind::ContractViolation,
                format!("evidence {d} is not readable by {}", cap.required.tenant),
            )
        })?;
        bound.insert(d, hex::encode(h));
    }
    cap.dependencies.knowledge = bound;
    Ok(())
}

fn find(store: &dyn CapabilityStore, hash: &str) -> Result<Record, PortError> {
    store
        .all()?
        .into_iter()
        .find(|r| r.capability_hash == hash)
        .ok_or_else(|| err(PortErrorKind::InvalidInput, format!("no record {hash}")))
}

/// Bind evidence and store a new PROPOSED record. Returns its content hash.
pub fn propose(
    store: &mut dyn CapabilityStore,
    corpus: &SqliteCorpus,
    mut cap: Capability,
) -> Result<String, PortError> {
    bind_evidence(&mut cap, corpus)?;
    let rec = Record::propose(cap);
    let h = rec.capability_hash.clone();
    store.put(&rec)?;
    Ok(h)
}

/// PROPOSED → TESTING → VALIDATED | REJECTED against a signed expert suite.
/// `expert_keys` are the operator's trust anchors (expert id → public key).
pub fn validate_record(
    store: &mut dyn CapabilityStore,
    corpus: &SqliteCorpus,
    hash: &str,
    suite: &ExpertSuite,
    expert_keys: &BTreeMap<String, Vec<u8>>,
    actor: &str,
    at_ms: u64,
) -> Result<ValidationReport, PortError> {
    let mut rec = find(store, hash)?;
    let key = expert_keys.get(&suite.expert_id).ok_or_else(|| {
        err(
            PortErrorKind::ContractViolation,
            format!("{} is not a trusted expert", suite.expert_id),
        )
    })?;
    let reader = evidence_reader(&rec.capability)?;
    let tenant = rec.capability.required.tenant.clone();
    let tenant_of = |d: &str| -> Option<String> {
        corpus
            .document_digest(&reader, d)
            .ok()
            .flatten()
            .map(|_| tenant.clone())
    };
    rec.start_testing(actor, at_ms).map_err(life)?;
    let report = validate(&rec.capability, suite, key, &tenant_of);
    rec.record_validation(report.clone(), actor, at_ms)
        .map_err(life)?;
    store.put(&rec)?;
    Ok(report)
}

/// VALIDATED → APPROVED with the approver's signature.
pub fn approve_record(
    store: &mut dyn CapabilityStore,
    hash: &str,
    approver_id: &str,
    private_key: &[u8],
    public_key: &[u8],
    consequential: bool,
    at_ms: u64,
) -> Result<(), PortError> {
    let mut rec = find(store, hash)?;
    let report = rec
        .validation
        .clone()
        .ok_or_else(|| err(PortErrorKind::ContractViolation, "not validated"))?;
    let a = Approval::sign(
        hash,
        &report,
        approver_id,
        consequential,
        at_ms,
        private_key,
    )
    .map_err(|e| err(PortErrorKind::ContractViolation, e))?;
    rec.approve(a, public_key, at_ms).map_err(life)?;
    store.put(&rec)
}

/// Any other permitted transition by role (activate, suspend, revoke, …).
pub fn transition(
    store: &mut dyn CapabilityStore,
    hash: &str,
    to: State,
    actor: &str,
    role: Role,
    at_ms: u64,
    reason: &str,
) -> Result<(), PortError> {
    let mut rec = find(store, hash)?;
    if to == State::Active && !active_of(store, &rec.capability.id, hash)?.is_empty() {
        return Err(err(
            PortErrorKind::ContractViolation,
            format!(
                "{} already has an active version (use activate with supersede, or rollback)",
                rec.capability.id
            ),
        ));
    }
    rec.transition(to, actor, role, at_ms, reason)
        .map_err(life)?;
    store.put(&rec)
}

fn active_of(
    store: &dyn CapabilityStore,
    id: &str,
    except: &str,
) -> Result<Vec<Record>, PortError> {
    Ok(store
        .all()?
        .into_iter()
        .filter(|r| {
            r.capability.id == id && r.state == State::Active && r.capability_hash != except
        })
        .collect())
}

/// Activate an APPROVED version (operator). At most one version of a
/// capability id is ACTIVE: if another version is active, this fails unless
/// `supersede` is set, in which case that version goes ACTIVE → SUPERSEDED
/// first (it stays approved, so it can be rolled back to). Returns the
/// superseded hashes.
pub fn activate(
    store: &mut dyn CapabilityStore,
    hash: &str,
    actor: &str,
    supersede: bool,
    at_ms: u64,
    reason: &str,
) -> Result<Vec<String>, PortError> {
    let rec = find(store, hash)?;
    let others = active_of(store, &rec.capability.id, hash)?;
    if !others.is_empty() && !supersede {
        return Err(err(
            PortErrorKind::ContractViolation,
            format!(
                "{} already has an active version; activate with supersede",
                rec.capability.id
            ),
        ));
    }
    if rec.state != State::Approved {
        return Err(err(
            PortErrorKind::ContractViolation,
            format!("{hash} is {:?}, not APPROVED", rec.state),
        ));
    }
    let mut done = vec![];
    for mut o in others {
        o.transition(
            State::Superseded,
            actor,
            Role::Operator,
            at_ms,
            &format!("superseded by {hash}"),
        )
        .map_err(life)?;
        store.put(&o)?;
        done.push(o.capability_hash.clone());
    }
    let mut rec = rec;
    rec.transition(State::Active, actor, Role::Operator, at_ms, reason)
        .map_err(life)?;
    store.put(&rec)?;
    Ok(done)
}

/// Roll back to a SUPERSEDED version (approver): the currently ACTIVE
/// version of the same id is SUSPENDED, then the target is re-activated.
/// The target must still be executable-if-active (validation + approval
/// intact, hash unchanged); staleness checks still apply at request time.
/// Returns the suspended hashes.
pub fn rollback(
    store: &mut dyn CapabilityStore,
    target: &str,
    approver: &str,
    at_ms: u64,
    reason: &str,
) -> Result<Vec<String>, PortError> {
    let mut rec = find(store, target)?;
    if rec.state != State::Superseded {
        return Err(err(
            PortErrorKind::ContractViolation,
            format!("{target} is {:?}, not SUPERSEDED", rec.state),
        ));
    }
    if rec.approval.is_none() || !rec.validation.as_ref().is_some_and(|v| v.passed) {
        return Err(err(
            PortErrorKind::ContractViolation,
            "rollback target lacks validation or approval",
        ));
    }
    let mut done = vec![];
    for mut o in active_of(store, &rec.capability.id, target)? {
        o.transition(
            State::Suspended,
            approver,
            Role::Approver,
            at_ms,
            &format!("rolled back to {target}: {reason}"),
        )
        .map_err(life)?;
        store.put(&o)?;
        done.push(o.capability_hash.clone());
    }
    rec.transition(
        State::Active,
        approver,
        Role::Approver,
        at_ms,
        &format!("rollback: {reason}"),
    )
    .map_err(life)?;
    store.put(&rec)?;
    Ok(done)
}

/// Milliseconds since the Unix epoch (lifecycle timestamps).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
