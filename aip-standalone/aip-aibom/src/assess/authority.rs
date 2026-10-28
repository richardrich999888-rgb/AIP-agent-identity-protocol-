//! C5 permissions and C8 delegation relationships.
//!
//! Every authority standing comes from `aip_core::delegation::
//! verify_delegation_chain`, with the issuer keys, the revocation set and the
//! present time taken from the assessor's context. The engine adds two
//! comparisons and no verification: whether the verified scope contains a
//! declared action, and whether the present lies inside the chain's signed
//! window.

use super::{Inputs, Sheet};
use crate::evidence::{AssessorContext, AuthorityChain};
use crate::finding::FindingKind;
use crate::model::Component;
use crate::standing::{combine, Lapse, Standing, Verifier};
use aip_core::delegation::verify_delegation_chain;
use aip_types::{CapabilityScope, ScopeAction};
use std::collections::BTreeSet;

/// What the core said about one offered chain.
enum Outcome {
    Rejected(String),
    Valid {
        scope: CapabilityScope,
        lapse: Option<Lapse>,
        unbounded: bool,
    },
}

struct Evaluated<'a> {
    index: usize,
    chain: &'a AuthorityChain,
    outcome: Outcome,
}

impl Evaluated<'_> {
    fn standing(&self) -> Standing {
        match &self.outcome {
            Outcome::Rejected(reason) => Standing::EvidenceRejected {
                reason: reason.clone(),
            },
            Outcome::Valid { lapse: Some(l), .. } => Standing::Lapsed { lapse: l.clone() },
            Outcome::Valid { lapse: None, .. } => Standing::Verified {
                verifier: Verifier::DelegationChain,
            },
        }
    }

    fn is_live(&self) -> bool {
        matches!(self.outcome, Outcome::Valid { lapse: None, .. })
    }
}

fn evaluate<'a>(index: usize, chain: &'a AuthorityChain, ctx: &AssessorContext) -> Evaluated<'a> {
    let outcome = match verify_delegation_chain(&chain.root, &chain.delegations, &ctx.issuer_keys) {
        Err(e) => Outcome::Rejected(format!("verify_delegation_chain refused the chain: {e:?}")),
        Ok(scope) => {
            let now = ctx.present_time_ms;
            let (from, until) = chain.window();
            let revoked = chain.jtis().iter().any(|j| ctx.revoked_jtis.contains(j));
            let lapse = if revoked {
                Some(Lapse::Revoked)
            } else if let Some(u) = until.filter(|u| now > *u) {
                Some(Lapse::Expired { valid_until_ms: u })
            } else if now < from {
                Some(Lapse::NotYetValid {
                    valid_from_ms: from,
                })
            } else {
                None
            };
            Outcome::Valid {
                scope,
                lapse,
                unbounded: until.is_none(),
            }
        }
    };
    Evaluated {
        index,
        chain,
        outcome,
    }
}

/// The leaf scope as written — unauthenticated — used only to decide which
/// declared field a *failed* chain had been offered in support of.
fn claimed_scope(chain: &AuthorityChain) -> &CapabilityScope {
    match chain.delegations.last() {
        Some(h) => &h.scope,
        None => &chain.root.scope,
    }
}

/// Stable label for an action, for findings.
pub(crate) fn action_label(a: &ScopeAction) -> String {
    match a {
        ScopeAction::Standard(s) => format!("standard:{s:?}"),
        ScopeAction::Custom(c) => format!("custom:{c}"),
    }
}

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    let agent = i.manifest.agent.id.as_str();
    let ctx = i.context;
    let mut for_agent = Vec::new();
    let mut from_agent = Vec::new();
    let mut foreign = 0usize;
    for (idx, c) in i.bundle.authority.iter().enumerate() {
        let issued_by_agent = c.delegations.iter().any(|h| h.issuer_id == agent);
        if c.holder() == agent {
            for_agent.push(evaluate(idx, c, ctx));
        } else if issued_by_agent {
            from_agent.push(evaluate(idx, c, ctx));
        } else {
            foreign += 1;
        }
    }
    if foreign > 0 {
        sheet.finding(
            Component::Permissions,
            "bundle.authority",
            FindingKind::ForeignEvidence { count: foreign },
        );
    }
    chain_findings(&for_agent, sheet);
    chain_findings(&from_agent, sheet);
    permissions(i, &for_agent, sheet);
    delegated_from(i, &for_agent, sheet);
    delegates_to(i, &from_agent, sheet);
}

fn chain_findings(chains: &[Evaluated<'_>], sheet: &mut Sheet) {
    for e in chains {
        let path = format!("bundle.authority[{}]", e.index);
        match &e.outcome {
            Outcome::Rejected(reason) => sheet.finding(
                Component::Permissions,
                path,
                FindingKind::EvidenceRejected {
                    reason: reason.clone(),
                },
            ),
            Outcome::Valid {
                unbounded: true, ..
            } => sheet.finding(
                Component::Permissions,
                path,
                FindingKind::UnboundedAuthority,
            ),
            Outcome::Valid { .. } => {}
        }
    }
}

fn action_standing(a: &ScopeAction, chains: &[Evaluated<'_>]) -> Standing {
    combine(chains.iter().filter_map(|e| match &e.outcome {
        Outcome::Rejected(_) if claimed_scope(e.chain).contains(a) => Some(e.standing()),
        Outcome::Rejected(_) => None,
        Outcome::Valid { scope, .. } if scope.denied.contains(a) => Some(Standing::Contradicted {
            reason: format!(
                "a verified chain held by this agent explicitly denies {}",
                action_label(a)
            ),
        }),
        Outcome::Valid { scope, .. } if scope.contains(a) => Some(e.standing()),
        Outcome::Valid { .. } => None,
    }))
}

fn permissions(i: &Inputs<'_>, chains: &[Evaluated<'_>], sheet: &mut Sheet) {
    let p = &i.manifest.permissions;
    for (k, a) in p.allowed.iter().enumerate() {
        let path = format!("$.permissions.allowed[{k}]");
        let standing = action_standing(a, chains);
        if standing == Standing::SelfReported {
            sheet.finding(
                Component::Permissions,
                path.clone(),
                FindingKind::PermissionNotBacked,
            );
        }
        sheet.field(Component::Permissions, path, standing);
    }

    let declared: BTreeSet<String> = p.allowed.iter().map(action_label).collect();
    let mut undeclared = BTreeSet::new();
    for e in chains.iter().filter(|e| e.is_live()) {
        if let Outcome::Valid { scope, .. } = &e.outcome {
            for a in scope.allowed.iter().filter(|a| scope.contains(a)) {
                let label = action_label(a);
                if !declared.contains(&label) {
                    undeclared.insert(label);
                }
            }
        }
    }
    for action in undeclared {
        sheet.finding(
            Component::Permissions,
            "$.permissions.allowed",
            FindingKind::UndeclaredAuthority { action },
        );
    }
}

fn delegated_from(i: &Inputs<'_>, chains: &[Evaluated<'_>], sheet: &mut Sheet) {
    let agent = i.manifest.agent.id.as_str();
    let declared = &i.manifest.relationships.delegated_from;
    for (k, x) in declared.iter().enumerate() {
        let standing = combine(
            chains
                .iter()
                .filter(|e| e.chain.issuers().contains(&x.as_str()))
                .map(Evaluated::standing),
        );
        sheet.field(
            Component::Relationships,
            format!("$.relationships.delegated_from[{k}]"),
            standing,
        );
    }
    let mut undeclared = BTreeSet::new();
    for e in chains.iter().filter(|e| e.is_live()) {
        for issuer in e.chain.issuers() {
            if issuer != agent && !declared.iter().any(|d| d == issuer) {
                undeclared.insert(issuer.to_string());
            }
        }
    }
    for issuer in undeclared {
        sheet.finding(
            Component::Relationships,
            "$.relationships.delegated_from",
            FindingKind::UndeclaredDelegator { issuer },
        );
    }
}

fn delegates_to(i: &Inputs<'_>, chains: &[Evaluated<'_>], sheet: &mut Sheet) {
    let agent = i.manifest.agent.id.as_str();
    for (k, y) in i.manifest.relationships.delegates_to.iter().enumerate() {
        let standing = combine(
            chains
                .iter()
                .filter(|e| {
                    e.chain
                        .delegations
                        .iter()
                        .any(|h| h.issuer_id == agent && &h.grantee_id == y)
                })
                .map(Evaluated::standing),
        );
        sheet.field(
            Component::Relationships,
            format!("$.relationships.delegates_to[{k}]"),
            standing,
        );
    }
}
