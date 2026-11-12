//! Offline, operator-provisioned approval authority. No embedded trust is accepted.
//! A policy-bound signature cannot fall back to legacy approval when policy is absent.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use vanian_sovereign::domain::corpus::Classification;

use super::artifact::Capability;
use super::lifecycle::{report_hash, Record};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    pub expert_id: String,
    pub public_key_sha256: String,
    pub tenant: String,
    pub security_domain: String,
    pub capability_ids: BTreeSet<String>,
    pub min_version: u32,
    pub max_version: u32,
    pub max_clearance: String,
    pub valid_from_ms: u64,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

/// Presence (even an empty map) enables strict approval policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPolicy {
    pub authorities: BTreeMap<String, AuthorityGrant>,
}

impl AuthorityGrant {
    pub fn hash(&self) -> String {
        let mut bytes = b"syntriass-approval-authority/v1\n".to_vec();
        bytes.extend(serde_json::to_vec(self).expect("authority contains no fallible JSON values"));
        hex::encode(aip_crypto::sha256(&bytes))
    }

    pub fn authorize(
        &self,
        cap: &Capability,
        expert: &str,
        public_key: &[u8],
        decided_at: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        if self.revoked {
            return Err("approval authority revoked");
        }
        if self.expert_id != expert || expert.is_empty() {
            return Err("approval authority identity mismatch");
        }
        if public_key.len() != 32
            || self.public_key_sha256 != hex::encode(aip_crypto::sha256(public_key))
        {
            return Err("approval authority trust anchor mismatch");
        }
        if self.valid_from_ms >= self.expires_at_ms
            || decided_at < self.valid_from_ms
            || decided_at > now
            || now >= self.expires_at_ms
        {
            return Err("approval authority not valid at decision/use time");
        }
        if self.tenant != cap.required.tenant
            || self.security_domain != cap.required.security_domain
        {
            return Err("approval authority tenant/domain mismatch");
        }
        if !self.capability_ids.contains(&cap.id) {
            return Err("capability outside approval authority scope");
        }
        if self.min_version == 0
            || self.min_version > self.max_version
            || cap.version < self.min_version
            || cap.version > self.max_version
        {
            return Err("capability version outside approval authority policy");
        }
        let ceiling = Classification::parse(&self.max_clearance)
            .map_err(|_| "invalid authority clearance")?;
        let required = Classification::parse(&cap.required.min_clearance)
            .map_err(|_| "invalid capability clearance")?;
        if required.rank() > ceiling.rank() {
            return Err("capability exceeds authority clearance");
        }
        Ok(())
    }
}

impl ApprovalPolicy {
    pub fn grant(&self, expert: &str) -> Result<&AuthorityGrant, &'static str> {
        self.authorities
            .get(expert)
            .ok_or("no configured approval authority")
    }
}

/// Verify current content/report/signature and, when enabled, current grant.
/// This does not authenticate lifecycle actor strings or unsigned history.
pub fn check(
    record: &Record,
    keys: &BTreeMap<String, Vec<u8>>,
    policy: Option<&ApprovalPolicy>,
    now: u64,
) -> Result<(), &'static str> {
    if record.capability_hash != record.capability.content_hash() {
        return Err("capability content changed");
    }
    let report = record
        .validation
        .as_ref()
        .filter(|r| r.passed)
        .ok_or("validation missing or failed")?;
    let approval = record.approval.as_ref().ok_or("approval missing")?;
    if report.capability_hash != record.capability_hash
        || approval.capability_hash != record.capability_hash
        || approval.validation_report_hash != report_hash(report)
    {
        return Err("approval capability/validation binding mismatch");
    }
    if approval.approver_id == record.capability.proposed_by {
        return Err("self approval refused");
    }
    let key = keys
        .get(&approval.approver_id)
        .ok_or("approval signer not trusted")?;
    if !approval.verify(key) {
        return Err("approval signature invalid");
    }
    match (policy, approval.authority_hash.as_deref()) {
        (Some(policy), Some(hash)) => {
            let grant = policy.grant(&approval.approver_id)?;
            grant.authorize(
                &record.capability,
                &approval.approver_id,
                key,
                approval.decided_at_ms,
                now,
            )?;
            if grant.hash() != hash {
                return Err("approval authority policy changed; fresh approval required");
            }
        }
        (Some(_), None) => return Err("legacy approval lacks required authority binding"),
        (None, Some(_)) => {
            return Err("policy-bound approval requires configured authority policy")
        }
        (None, None) => {} // Existing owner-controlled legacy mode; not C2-qualified.
    }
    Ok(())
}
