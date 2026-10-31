//! Organisational capability memory: what experience may change. Pure.
//!
//! Remembering is not acquiring. An experience is a stored fact; it never
//! edits an active capability. The only path from experience to behaviour is:
//!
//! 1. record (verified, same tenant/domain — [`super::experience::admit`]);
//! 2. [`review`]: run the ACTIVE capability on verified experiences and list
//!    disagreements (a possible improvement — or an expert error);
//! 3. an engineer proposes a NEW VERSION (same id, higher version);
//! 4. an expert signs a suite containing the old cases plus the new ones;
//! 5. [`upgrade_check`]: old vs new on that suite — regressions, fixes and
//!    every behaviour change, plus scope changes, for the approver;
//! 6. the new version goes through the unchanged lifecycle (validation by the
//!    signed suite, independent approval) and is activated, superseding the
//!    old one; 7. the old version stays APPROVED-and-SUPERSEDED so an approver
//!    can roll back (`Superseded → Active`, approver only).

use serde::{Deserialize, Serialize};

use super::artifact::Capability;
use super::experience::{Experience, Verification};
use super::suite::ExpertSuite;
use super::validate::label;

/// A verified experience the active capability decides differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disagreement {
    pub experience_id: String,
    pub expected: String,
    pub got: String,
}

/// Result of reviewing one capability against stored experience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Review {
    pub capability_id: String,
    pub capability_version: u32,
    pub considered: usize,
    pub agreed: usize,
    pub disagreements: Vec<Disagreement>,
    /// Not usable as evidence: unverified, self-reported, self-verified, or no expected outcome.
    pub skipped_unverified: usize,
    /// Other tenant's experience: never read.
    pub skipped_other_tenant: usize,
}

/// Is `e` independently verified evidence with a known expected outcome?
fn usable(e: &Experience) -> Option<&str> {
    match (&e.verification, &e.expected_outcome) {
        (Verification::Verified { verifier, .. }, Some(x)) if verifier != &e.actor => Some(x),
        _ => None,
    }
}

/// Run `cap` on every usable experience of its own tenant. Read-only.
pub fn review(cap: &Capability, experiences: &[Experience]) -> Result<Review, String> {
    let compiled = cap.compile().map_err(|e| format!("{e:?}"))?;
    let mut r = Review {
        capability_id: cap.id.clone(),
        capability_version: cap.version,
        considered: 0,
        agreed: 0,
        disagreements: vec![],
        skipped_unverified: 0,
        skipped_other_tenant: 0,
    };
    for e in experiences {
        if e.tenant != cap.required.tenant || e.security_domain != cap.required.security_domain {
            r.skipped_other_tenant += 1;
            continue;
        }
        let Some(expected) = usable(e) else {
            r.skipped_unverified += 1;
            continue;
        };
        r.considered += 1;
        let got = label(&cap.execute(&compiled, &e.task));
        if got == expected {
            r.agreed += 1;
        } else {
            r.disagreements.push(Disagreement {
                experience_id: e.id.clone(),
                expected: expected.into(),
                got,
            });
        }
    }
    Ok(r)
}

/// One suite case on which the two versions differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub case_id: String,
    pub expected: String,
    pub old: String,
    pub new: String,
}

/// Old-vs-new comparison on one signed suite (input to the approver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeCheck {
    pub capability_id: String,
    pub from_version: u32,
    pub to_version: u32,
    pub from_hash: String,
    pub to_hash: String,
    pub suite_hash: String,
    pub suite_signature_ok: bool,
    pub cases: usize,
    pub old_passed: usize,
    pub new_passed: usize,
    /// Old right, new wrong. Must be empty.
    pub regressions: Vec<Change>,
    /// Old wrong, new right.
    pub fixes: Vec<Change>,
    /// Every case where outputs differ (superset of the two above).
    pub changes: Vec<Change>,
    /// Blocking scope changes (tenant, clearance, domain, outcomes).
    pub scope_violations: Vec<String>,
    /// Non-blocking but reported: applicability terms added/removed, guards removed.
    pub scope_notes: Vec<String>,
    pub acceptable: bool,
    pub reasons: Vec<String>,
}

fn diff<'a>(a: &'a [String], b: &'a [String]) -> Vec<&'a String> {
    a.iter().filter(|x| !b.contains(x)).collect()
}

/// Compare `old` and `new` on a suite signed by the trusted expert. The
/// upgrade is acceptable only if the suite verifies and belongs to the
/// capability's tenant, the id is unchanged, the version increases, no
/// blocking scope change is made, there are no regressions and the new
/// version passes every case. Acceptability is advice to the approver; the
/// lifecycle still requires validation and a signed approval.
pub fn upgrade_check(
    old: &Capability,
    new: &Capability,
    suite: &ExpertSuite,
    expert_public_key: &[u8],
) -> UpgradeCheck {
    let mut reasons = vec![];
    let sig = suite.verify(expert_public_key);
    if !sig {
        reasons.push("suite signature does not verify".into());
    }
    if suite.tenant != old.required.tenant {
        reasons.push("suite belongs to another tenant".into());
    }
    if old.id != new.id {
        reasons.push("capability id differs".into());
    }
    if new.version <= old.version {
        reasons.push("version does not increase".into());
    }
    let mut violations = vec![];
    if old.required != new.required {
        violations.push(format!(
            "required scope changed: {:?} -> {:?}",
            old.required, new.required
        ));
    }
    for o in diff(&new.outcomes, &old.outcomes) {
        violations.push(format!("new outcome {o}"));
    }
    let mut notes = vec![];
    let (ot, nt) = (&old.applicability.any_terms, &new.applicability.any_terms);
    let added = diff(nt, ot);
    let removed = diff(ot, nt);
    if !added.is_empty() {
        notes.push(format!("applicability terms added: {added:?}"));
    }
    if !removed.is_empty() {
        notes.push(format!("applicability terms removed: {removed:?}"));
    }
    if new.procedure.text_guards.len() < old.procedure.text_guards.len()
        || new.procedure.numeric_guards.len() < old.procedure.numeric_guards.len()
    {
        notes.push("scope guards removed".into());
    }
    let (co, cn) = (old.compile(), new.compile());
    let mut check = UpgradeCheck {
        capability_id: new.id.clone(),
        from_version: old.version,
        to_version: new.version,
        from_hash: old.content_hash(),
        to_hash: new.content_hash(),
        suite_hash: suite.hash(),
        suite_signature_ok: sig,
        cases: suite.cases.len(),
        old_passed: 0,
        new_passed: 0,
        regressions: vec![],
        fixes: vec![],
        changes: vec![],
        scope_violations: violations,
        scope_notes: notes,
        acceptable: false,
        reasons,
    };
    let (Ok(co), Ok(cn)) = (co, cn) else {
        check.reasons.push("a version does not compile".into());
        return check;
    };
    for c in &suite.cases {
        let o = label(&old.execute(&co, &c.text));
        let n = label(&new.execute(&cn, &c.text));
        check.old_passed += usize::from(o == c.expected);
        check.new_passed += usize::from(n == c.expected);
        if o != n {
            let ch = Change {
                case_id: c.id.clone(),
                expected: c.expected.clone(),
                old: o.clone(),
                new: n.clone(),
            };
            if o == c.expected {
                check.regressions.push(ch.clone());
            } else if n == c.expected {
                check.fixes.push(ch.clone());
            }
            check.changes.push(ch);
        }
    }
    if !check.regressions.is_empty() {
        check
            .reasons
            .push(format!("{} regression(s)", check.regressions.len()));
    }
    if check.new_passed != check.cases {
        check.reasons.push(format!(
            "new version fails {} case(s)",
            check.cases - check.new_passed
        ));
    }
    if !check.scope_violations.is_empty() {
        check.reasons.push("blocking scope change".into());
    }
    check.acceptable = check.reasons.is_empty();
    check
}
