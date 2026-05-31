//! Capability Scope Engine — Named scopes, scope intersection, scoped token issuance.
//!
//! ## Named Scopes (§6-v2)
//!
//! Four built-in named scopes define the standard capability hierarchy:
//!
//! ```text
//! ADMIN ⊇ ORCHESTRATOR ⊇ AUDIT_READER ⊇ SUBMITTER
//! ```
//!
//! ## Scope Intersection (NM-A1 — Novel Mechanism)
//!
//! A delegation child's scope must be ⊆ the parent's scope.
//! This is enforced via lattice MEET: `effective = intersection(parent, child)`.
//! If the intersection is empty, the delegation is rejected.

use aip_crypto::{sha256, sign_ed25519};
use aip_types::*;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Named Scope Constructors ───

/// SUBMITTER scope: may only submit tasks for processing.
/// Lowest privilege. Cannot read audit logs, manage other agents, or delegate.
pub fn scope_submitter() -> CapabilityScope {
    CapabilityScope {
        allowed: vec![ScopeAction::Standard(Action::Write)],
        denied: vec![
            ScopeAction::Standard(Action::Admin),
            ScopeAction::Standard(Action::Delete),
        ],
    }
}

/// AUDIT_READER scope: may read audit logs and submission status.
/// Cannot write, delete, or perform admin operations.
pub fn scope_audit_reader() -> CapabilityScope {
    CapabilityScope {
        allowed: vec![ScopeAction::Standard(Action::Read)],
        denied: vec![
            ScopeAction::Standard(Action::Write),
            ScopeAction::Standard(Action::Admin),
            ScopeAction::Standard(Action::Delete),
        ],
    }
}

/// ORCHESTRATOR scope: may read, write, execute, and delegate sub-tasks.
/// Cannot perform admin operations (user management, system config).
pub fn scope_orchestrator() -> CapabilityScope {
    CapabilityScope {
        allowed: vec![
            ScopeAction::Standard(Action::Read),
            ScopeAction::Standard(Action::Write),
            ScopeAction::Standard(Action::Execute),
            ScopeAction::Standard(Action::Delegate),
        ],
        denied: vec![ScopeAction::Standard(Action::Admin)],
    }
}

/// ADMIN scope: full access including user management and system configuration.
/// Highest privilege. Can revoke tokens, manage scopes, and delegate anything.
pub fn scope_admin() -> CapabilityScope {
    CapabilityScope::all()
}

// ─── Scope Algebra (NM-A1) ───

/// Check if `action` is permitted by `scope`.
///
/// A permitted action must be in `allowed` and NOT in `denied`.
pub fn scope_permits(scope: &CapabilityScope, action: &ScopeAction) -> bool {
    scope.contains(action)
}

/// Check if `child` scope is a subset of `parent` scope (child ⊆ parent).
///
/// This is the fundamental invariant of capability attenuation:
/// a delegated token can never exceed the grantor's scope.
///
/// Returns `true` iff every action in `child.allowed` is also in `parent.allowed`.
pub fn is_scope_subset(child: &CapabilityScope, parent: &CapabilityScope) -> bool {
    child
        .allowed
        .iter()
        .all(|action| parent.allowed.contains(action) && !parent.denied.contains(action))
}

/// Compute the intersection (MEET) of two scopes.
///
/// The result contains only actions permitted by BOTH parent and child.
/// If the intersection is empty, returns `None` (⊥ in the capability lattice).
///
/// This is the core of Novel Mechanism NM-A1:
/// "Scope intersection enforcement in delegation ensures that no delegation
///  chain can expand privileges beyond the root grant."
pub fn scope_intersection(
    parent: &CapabilityScope,
    child: &CapabilityScope,
) -> Option<CapabilityScope> {
    let allowed: Vec<ScopeAction> = child
        .allowed
        .iter()
        .filter(|a| parent.allowed.contains(a) && !parent.denied.contains(a))
        .cloned()
        .collect();

    if allowed.is_empty() {
        return None; // MEET produces ⊥ — delegation would grant nothing
    }

    // Deny union: anything denied by either parent or child is denied in result
    let mut denied = parent.denied.clone();
    for d in &child.denied {
        if !denied.contains(d) {
            denied.push(d.clone());
        }
    }

    Some(CapabilityScope { allowed, denied })
}

// ─── Scoped Token Issuance ───

/// Issue a scoped token to an agent.
///
/// The token is signed by the issuer (identified by `issuer_id` and `issuer_private_key`).
/// A fresh JTI (token ID) is generated using CSPRNG.
pub fn issue_scoped_token(
    issuer_id: &str,
    issuer_private_key: &[u8],
    agent_id: &str,
    scope: CapabilityScope,
    expires_in_ms: Option<u64>,
) -> Result<ScopedToken, AipError> {
    let now_ms = now_ms();
    let jti = random_jti();

    // Canonical token payload for signing
    let payload = canonical_token_payload(&jti, issuer_id, agent_id, &scope, now_ms);
    let issuer_sig = sign_ed25519(issuer_private_key, issuer_id, &payload)?;

    Ok(ScopedToken {
        jti,
        agent_id: agent_id.to_string(),
        issuer_id: issuer_id.to_string(),
        scope,
        issued_at: now_ms,
        expires_at: expires_in_ms.map(|d| now_ms + d),
        issuer_sig,
    })
}

/// Verify a scoped token's signature against the issuer's public key.
pub fn verify_scoped_token(
    token: &ScopedToken,
    issuer_public_key: &[u8],
) -> Result<bool, AipError> {
    let payload = canonical_token_payload(
        &token.jti,
        &token.issuer_id,
        &token.agent_id,
        &token.scope,
        token.issued_at,
    );
    let expected_hash = sha256(&payload);
    if token.issuer_sig.payload_hash != expected_hash {
        return Ok(false);
    }
    aip_crypto::verify_ed25519(issuer_public_key, &token.issuer_sig)
}

/// Check if a scoped token has expired.
pub fn is_token_expired(token: &ScopedToken) -> bool {
    token.expires_at.is_some_and(|exp| now_ms() > exp)
}

// ─── Violation Detection ───

/// Check if performing `action` with this `token` would be a scope violation.
///
/// Returns `true` if the token does NOT permit the action — i.e., the action
/// would be blocked and should be logged as a scope violation.
pub fn is_scope_violation(token: &ScopedToken, action: &ScopeAction) -> bool {
    !scope_permits(&token.scope, action)
}

// ─── Internal Helpers ───

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn random_jti() -> [u8; 16] {
    let mut jti = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut jti);
    // Set version 4 UUID bits
    jti[6] = (jti[6] & 0x0F) | 0x40;
    jti[8] = (jti[8] & 0x3F) | 0x80;
    jti
}

fn canonical_token_payload(
    jti: &[u8; 16],
    issuer_id: &str,
    agent_id: &str,
    scope: &CapabilityScope,
    issued_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(jti);
    buf.extend_from_slice(issuer_id.as_bytes());
    buf.extend_from_slice(agent_id.as_bytes());
    for action in &scope.allowed {
        let action_bytes = encode_scope_action(action);
        buf.extend_from_slice(&action_bytes);
    }
    buf.push(0xFF); // Separator between allowed and denied
    for action in &scope.denied {
        let action_bytes = encode_scope_action(action);
        buf.extend_from_slice(&action_bytes);
    }
    buf.extend_from_slice(&issued_at.to_le_bytes());
    buf
}

fn encode_scope_action(action: &ScopeAction) -> Vec<u8> {
    match action {
        ScopeAction::Standard(a) => vec![0x00, *a as u8],
        ScopeAction::Custom(s) => {
            let mut v = vec![0x01];
            v.extend_from_slice(s.as_bytes());
            v.push(0x00); // null terminator
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::generate_ed25519_keypair;

    fn make_issuer() -> (String, Vec<u8>, Vec<u8>) {
        let kp = generate_ed25519_keypair();
        let prov = ProvenanceTriple {
            model_commitment: sha256(b"model"),
            environment_commitment: sha256(b"env"),
            toolchain_commitment: sha256(b"tool"),
        };
        let id = aip_crypto::derive_aip_id(&kp.public_key, &prov);
        (id, kp.private_key, kp.public_key)
    }

    // ── Named scope tests ──

    #[test]
    fn test_submitter_scope_allows_write_only() {
        let s = scope_submitter();
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Write)));
        assert!(!scope_permits(&s, &ScopeAction::Standard(Action::Read)));
        assert!(!scope_permits(&s, &ScopeAction::Standard(Action::Admin)));
        assert!(!scope_permits(&s, &ScopeAction::Standard(Action::Delete)));
    }

    #[test]
    fn test_admin_scope_allows_all() {
        let s = scope_admin();
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Read)));
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Write)));
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Admin)));
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Execute)));
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Delegate)));
    }

    #[test]
    fn test_audit_reader_blocks_write() {
        let s = scope_audit_reader();
        assert!(scope_permits(&s, &ScopeAction::Standard(Action::Read)));
        assert!(!scope_permits(&s, &ScopeAction::Standard(Action::Write)));
    }

    // ── Scope algebra tests ──

    #[test]
    fn test_submitter_is_subset_of_admin() {
        assert!(is_scope_subset(&scope_submitter(), &scope_admin()));
    }

    #[test]
    fn test_admin_is_not_subset_of_submitter() {
        assert!(!is_scope_subset(&scope_admin(), &scope_submitter()));
    }

    #[test]
    fn test_scope_intersection_returns_narrower() {
        let parent = scope_orchestrator(); // Read, Write, Execute, Delegate
        let child = scope_audit_reader(); // Read only
        let result = scope_intersection(&parent, &child);
        assert!(result.is_some());
        let effective = result.unwrap();
        assert!(scope_permits(
            &effective,
            &ScopeAction::Standard(Action::Read)
        ));
        assert!(!scope_permits(
            &effective,
            &ScopeAction::Standard(Action::Write)
        ));
    }

    #[test]
    fn test_scope_intersection_disjoint_returns_none() {
        let parent = scope_audit_reader(); // Read only
        let child = scope_submitter(); // Write only
        let result = scope_intersection(&parent, &child);
        assert!(result.is_none(), "Disjoint scopes must produce ⊥");
    }

    // ── Token issuance & verification tests ──

    #[test]
    fn test_issue_and_verify_scoped_token() {
        let (issuer_id, priv_key, pub_key) = make_issuer();
        let token = issue_scoped_token(
            &issuer_id,
            &priv_key,
            "aip1agent",
            scope_orchestrator(),
            Some(3_600_000), // 1 hour
        )
        .unwrap();

        assert_eq!(token.issuer_id, issuer_id);
        assert_eq!(token.agent_id, "aip1agent");
        assert!(!is_token_expired(&token));
        assert!(verify_scoped_token(&token, &pub_key).unwrap());
    }

    #[test]
    fn test_tampered_token_fails_verification() {
        let (issuer_id, priv_key, pub_key) = make_issuer();
        let mut token =
            issue_scoped_token(&issuer_id, &priv_key, "aip1agent", scope_submitter(), None)
                .unwrap();

        // Tamper: escalate scope after issuance
        token.scope = scope_admin();
        assert!(!verify_scoped_token(&token, &pub_key).unwrap());
    }

    // ── Scope violation detection tests ──

    #[test]
    fn test_submitter_token_scope_violation_on_admin_action() {
        let (issuer_id, priv_key, _) = make_issuer();
        let token = issue_scoped_token(&issuer_id, &priv_key, "aip1agent", scope_submitter(), None)
            .unwrap();

        // SUBMITTER token attempting admin action → violation
        assert!(is_scope_violation(
            &token,
            &ScopeAction::Standard(Action::Admin)
        ));
        // SUBMITTER token doing a write → no violation
        assert!(!is_scope_violation(
            &token,
            &ScopeAction::Standard(Action::Write)
        ));
    }

    #[test]
    fn test_custom_scope_action() {
        let scope = CapabilityScope {
            allowed: vec![ScopeAction::Custom("ai.airon.infer".to_string())],
            denied: vec![],
        };
        assert!(scope_permits(
            &scope,
            &ScopeAction::Custom("ai.airon.infer".to_string())
        ));
        assert!(!scope_permits(&scope, &ScopeAction::Standard(Action::Read)));
    }
}
