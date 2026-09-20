//! Cryptographic trust roots for delegation and supervisor approval.
//!
//! These replace the two fail-closed stubs the core ships with.
//! [`TrustedStoreVerifier`](ot_accountability_core::authority::TrustedStoreVerifier)
//! accepts whatever the store hands it, which is correct only when the store
//! *is* the trust boundary — a local policy file on a host you control.
//! [`DenyAllCoSignatures`](ot_accountability_core::aip::DenyAllCoSignatures)
//! refuses everything, so multi-sig tools are uninvocable rather than
//! unguarded. Both are honest defaults and neither is a trust root.
//!
//! # Signed delegation
//!
//! [`SignedEdgeVerifier`] requires each edge to carry an ML-DSA signature by
//! the parent that issued it, over
//! [`DelegationEdge::canonical_terms`] — every field that decides what the
//! edge confers. Widen a scope, raise a clearance, extend an expiry, and the
//! signature stops verifying. That is what lets a delegation graph be read
//! from somewhere the gateway does not control: a database, a config service,
//! a peer. Without it, write access to the store is authority to grant
//! authority.
//!
//! # Approval that means one call
//!
//! [`PqcCoSignatureVerifier`] binds a supervisor's approval to the specific
//! invocation — the agent, the edge, the tool, **and the digest of the exact
//! arguments** — with an expiry. An approval over `(edge, tool)` alone would
//! be a standing permission: obtain one `send_command` co-signature and every
//! later `send_command` is authorised, including the ones the supervisor
//! would have refused. The signature says "I approve *this*", not "I approve
//! of this verb".
//!
//! # Who may sign for whom
//!
//! A verified signature says who held the key, never whose key it is. Both
//! verifiers therefore consult an explicit registry — [`IssuerRegistry`] for
//! delegation, [`CoSignatureAuthority`] for approvals — and a key nobody
//! registered signs for nobody.

use std::collections::BTreeMap;

use ot_accountability_core::aip::{CoSignatureRequest, CoSignatureVerifier};
use ot_accountability_core::authority::{DelegationEdge, EdgeVerifier};
use ot_pqc::verify_attestation_json;
use serde_json::{json, Value};

/// Signing context for delegation edges, keeping these signatures
/// domain-separated: a signature made to delegate authority must not be
/// replayable as an identity proof or a supervisor approval.
pub const EDGE_CONTEXT: &[u8] = b"OT-DELEGATION-EDGE-v1";

/// Signing context for supervisor co-signatures.
pub const COSIGNATURE_CONTEXT: &[u8] = b"OT-SUPERVISOR-COSIGNATURE-v1";

/// Something that can produce attestation envelopes over a payload.
///
/// This is the custody boundary. Everything in this module signs through it
/// rather than through a concrete key type, so a deployment whose signing
/// keys live in an HSM or KMS implements this trait once and nothing else
/// changes — the payload shapes, the domain-separation contexts, and the
/// verifiers stay identical. [`SignatureKeyPair`](ot_pqc::SignatureKeyPair)
/// implements it for software keys, which the keyring stores with enforced
/// file permissions; the trait is what keeps that a swappable choice rather
/// than an architecture.
pub trait AttestationSigner {
    /// Signs `payload` under `context`, returning the attestation envelope.
    fn attest(&self, payload: Value, context: &[u8]) -> Result<Value, String>;

    /// The 64-hex identity of the verifying key, as registries store it.
    fn identity_hex(&self) -> String;
}

impl AttestationSigner for ot_pqc::SignatureKeyPair {
    fn attest(&self, payload: Value, context: &[u8]) -> Result<Value, String> {
        ot_pqc::attest_json(payload, self, context).map_err(|e| format!("cannot sign: {e}"))
    }

    fn identity_hex(&self) -> String {
        self.verifying_key().identity_hex()
    }
}

/// Which signing keys may issue delegations on behalf of which DIDs.
#[derive(Debug, Default, Clone)]
pub struct IssuerRegistry {
    keys: BTreeMap<String, Vec<String>>,
}

impl IssuerRegistry {
    /// An empty registry: no DID has an authorised issuing key, so a
    /// signature-checking verifier refuses every edge.
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorises `key_identity` (the ML-DSA verifying key's `identity_hex`)
    /// to issue delegations as `did`.
    pub fn authorise(mut self, did: impl Into<String>, key_identity: impl Into<String>) -> Self {
        let entry = self.keys.entry(did.into()).or_default();
        let key = key_identity.into();
        if !entry.contains(&key) {
            entry.push(key);
        }
        self
    }

    /// True when `key_identity` may sign as `did`.
    pub fn may_issue(&self, did: &str, key_identity: &str) -> bool {
        self.keys
            .get(did)
            .is_some_and(|keys| keys.iter().any(|k| k == key_identity))
    }

    /// How many DIDs have an authorised key.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when nothing is authorised.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Accepts only edges signed by the parent that issued them.
pub struct SignedEdgeVerifier {
    issuers: IssuerRegistry,
}

impl SignedEdgeVerifier {
    /// A verifier over an issuer registry.
    pub fn new(issuers: IssuerRegistry) -> Self {
        Self { issuers }
    }

    /// The issuer registry.
    pub fn issuers(&self) -> &IssuerRegistry {
        &self.issuers
    }
}

impl EdgeVerifier for SignedEdgeVerifier {
    fn verify(&self, edge: &DelegationEdge) -> bool {
        let Some(envelope) = &edge.signature else {
            return false;
        };
        let Ok(verified) = verify_attestation_json(envelope, None) else {
            return false;
        };
        // The key must be one this DID is allowed to speak with. A valid
        // signature by an unregistered key is a valid signature by a stranger.
        if !self
            .issuers
            .may_issue(&edge.parent_did, &verified.signer_identity)
        {
            return false;
        }
        // And it must cover *these* terms. Comparing the parsed values rather
        // than re-serialising keeps this independent of key ordering.
        verified.payload == edge.canonical_terms()
    }
}

/// Signs an edge's terms, producing the envelope for
/// [`DelegationEdge::signature`].
///
/// The signing side of [`SignedEdgeVerifier`], here so a provisioning tool
/// and the verifier cannot drift about what gets covered.
pub fn sign_edge(edge: &DelegationEdge, issuer: &dyn AttestationSigner) -> Result<Value, String> {
    issuer.attest(edge.canonical_terms(), EDGE_CONTEXT)
}

/// Which keys may co-sign for which delegation edges.
#[derive(Debug, Default, Clone)]
pub struct CoSignatureAuthority {
    by_edge: BTreeMap<String, Vec<String>>,
}

impl CoSignatureAuthority {
    /// An empty authority: nothing may co-sign, so multi-sig tools stay
    /// uninvocable — the same posture as the stub it replaces, until an
    /// operator names a supervisor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorises `key_identity` to co-sign invocations under `edge_id`.
    ///
    /// Scoped per edge rather than globally: a supervisor who may approve a
    /// spacecraft command on one mission should not thereby be able to
    /// approve one on another.
    pub fn authorise(
        mut self,
        edge_id: impl Into<String>,
        key_identity: impl Into<String>,
    ) -> Self {
        let entry = self.by_edge.entry(edge_id.into()).or_default();
        let key = key_identity.into();
        if !entry.contains(&key) {
            entry.push(key);
        }
        self
    }

    /// True when `key_identity` may co-sign under `edge_id`.
    pub fn may_cosign(&self, edge_id: &str, key_identity: &str) -> bool {
        self.by_edge
            .get(edge_id)
            .is_some_and(|keys| keys.iter().any(|k| k == key_identity))
    }
}

/// The payload a supervisor signs to approve one invocation.
///
/// Every field is load-bearing. The agent and edge say who is acting under
/// what grant; the tool and argument digest make the approval specific to
/// this call rather than to a verb; the expiry stops an approval becoming a
/// standing permission if it is captured.
pub fn cosignature_payload(
    agent_did: &str,
    edge_id: &str,
    tool_name: &str,
    input_params_digest: &str,
    expires_at_utc: &str,
) -> Value {
    json!({
        "agentDid": agent_did,
        "edgeId": edge_id,
        "toolName": tool_name,
        "inputParamsDigest": input_params_digest,
        "expiresAtUtc": expires_at_utc,
    })
}

/// Signs an approval for one invocation.
pub fn sign_cosignature(
    agent_did: &str,
    edge_id: &str,
    tool_name: &str,
    input_params_digest: &str,
    expires_at_utc: &str,
    supervisor: &dyn AttestationSigner,
) -> Result<String, String> {
    let envelope = supervisor.attest(
        cosignature_payload(
            agent_did,
            edge_id,
            tool_name,
            input_params_digest,
            expires_at_utc,
        ),
        COSIGNATURE_CONTEXT,
    )?;
    // Serialised because the AIP request carries the co-signature as a string
    // — it travels in an MCP `_meta` field and is recorded verbatim in the
    // sealed packet, where an auditor can re-verify it.
    serde_json::to_string(&envelope).map_err(|e| format!("cannot serialize co-signature: {e}"))
}

/// Verifies ML-DSA supervisor approvals bound to a specific invocation.
pub struct PqcCoSignatureVerifier {
    authority: CoSignatureAuthority,
}

impl PqcCoSignatureVerifier {
    /// A verifier over a co-signature authority.
    pub fn new(authority: CoSignatureAuthority) -> Self {
        Self { authority }
    }
}

impl CoSignatureVerifier for PqcCoSignatureVerifier {
    fn verify(&self, request: &CoSignatureRequest) -> bool {
        let Ok(envelope) = serde_json::from_str::<Value>(request.signature) else {
            return false;
        };
        let Ok(verified) = verify_attestation_json(&envelope, None) else {
            return false;
        };
        if !self
            .authority
            .may_cosign(request.edge_id, &verified.signer_identity)
        {
            return false;
        }
        // The approval must be for exactly this call. Rebuilding the expected
        // payload and comparing means a mismatch in *any* bound field —
        // agent, edge, tool, arguments — fails, without a per-field check
        // somebody could forget to add when the payload grows.
        let Some(expires) = verified.payload.get("expiresAtUtc").and_then(Value::as_str) else {
            return false;
        };
        let expected = cosignature_payload(
            request.agent_did,
            request.edge_id,
            request.tool_name,
            request.input_params_digest,
            expires,
        );
        if verified.payload != expected {
            return false;
        }
        // ISO-8601 UTC of a fixed shape orders correctly as a string, which
        // keeps this clock-free: the caller supplies adjudication time.
        request.now_utc < expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ot_accountability_core::authority::{ClearanceLevel, EdgeStatus};
    use ot_pqc::{CryptoSuite, SignatureKeyPair};

    const OFFICER: &str = "did:syntriass:officer:OFF-1";
    const AGENT: &str = "did:syntriass:agent:AGT-1";
    const NOW: &str = "2026-06-01T00:00:00.000Z";
    const EXPIRES: &str = "2026-06-01T00:05:00.000Z";

    fn key(seed: u8) -> SignatureKeyPair {
        SignatureKeyPair::from_seed(CryptoSuite::X25519MlKem1024MlDsa87, &[seed; 32])
            .expect("keygen")
    }

    fn edge() -> DelegationEdge {
        DelegationEdge {
            edge_id: "edge-1".into(),
            parent_did: OFFICER.into(),
            child_did: AGENT.into(),
            scope: vec!["read_catalog".into(), "send_command".into()],
            multi_sig_tools: vec!["send_command".into()],
            clearance_level: ClearanceLevel::Secret,
            valid_from_utc: "2026-01-01T00:00:00.000Z".into(),
            expires_at_utc: "2027-01-01T00:00:00.000Z".into(),
            status: EdgeStatus::Active,
            signature: None,
        }
    }

    fn signed_edge(issuer: &SignatureKeyPair) -> DelegationEdge {
        let mut e = edge();
        e.signature = Some(sign_edge(&e, issuer).expect("sign"));
        e
    }

    fn verifier(issuer: &SignatureKeyPair) -> SignedEdgeVerifier {
        SignedEdgeVerifier::new(
            IssuerRegistry::new().authorise(OFFICER, issuer.verifying_key().identity_hex()),
        )
    }

    #[test]
    fn an_edge_signed_by_its_authorised_parent_verifies() {
        let officer = key(1);
        assert!(verifier(&officer).verify(&signed_edge(&officer)));
    }

    #[test]
    fn an_unsigned_edge_is_refused_however_well_formed() {
        let officer = key(1);
        assert!(
            !verifier(&officer).verify(&edge()),
            "an unsigned edge passed a signature-checking verifier"
        );
    }

    #[test]
    fn widening_the_terms_after_signing_breaks_the_signature() {
        let officer = key(1);
        let v = verifier(&officer);

        // Each of these is a real privilege escalation an attacker with write
        // access to the store would attempt.
        let mut wider_scope = signed_edge(&officer);
        wider_scope.scope.push("purge_archive".into());
        assert!(
            !v.verify(&wider_scope),
            "a widened scope kept its signature"
        );

        let mut higher_clearance = signed_edge(&officer);
        higher_clearance.clearance_level = ClearanceLevel::TopSecret;
        assert!(
            !v.verify(&higher_clearance),
            "a raised clearance kept its signature"
        );

        let mut longer = signed_edge(&officer);
        longer.expires_at_utc = "2099-01-01T00:00:00.000Z".into();
        assert!(!v.verify(&longer), "an extended expiry kept its signature");

        let mut shed_obligation = signed_edge(&officer);
        shed_obligation.multi_sig_tools.clear();
        assert!(
            !v.verify(&shed_obligation),
            "a dropped multi-sig obligation kept its signature"
        );

        let mut reassigned = signed_edge(&officer);
        reassigned.child_did = "did:syntriass:agent:SOMEONE-ELSE".into();
        assert!(
            !v.verify(&reassigned),
            "a reassigned edge kept its signature"
        );
    }

    #[test]
    fn a_valid_signature_by_an_unregistered_key_signs_for_nobody() {
        let officer = key(1);
        let stranger = key(2);
        // Perfectly valid signature — over the right terms, even.
        let forged = {
            let mut e = edge();
            e.signature = Some(sign_edge(&e, &stranger).expect("sign"));
            e
        };
        assert!(!verifier(&officer).verify(&forged));
    }

    #[test]
    fn a_key_authorised_for_one_did_cannot_issue_as_another() {
        let officer = key(1);
        let v = verifier(&officer);
        let mut other_parent = edge();
        other_parent.parent_did = "did:syntriass:officer:OFF-2".into();
        other_parent.signature = Some(sign_edge(&other_parent, &officer).expect("sign"));
        assert!(
            !v.verify(&other_parent),
            "a key issued a delegation as a DID it was never authorised for"
        );
    }

    #[test]
    fn an_empty_issuer_registry_refuses_everything() {
        let officer = key(1);
        let v = SignedEdgeVerifier::new(IssuerRegistry::new());
        assert!(v.issuers().is_empty());
        assert!(!v.verify(&signed_edge(&officer)));
    }

    // ── Co-signatures ────────────────────────────────────────────────────

    fn cosign_verifier(supervisor: &SignatureKeyPair) -> PqcCoSignatureVerifier {
        PqcCoSignatureVerifier::new(
            CoSignatureAuthority::new()
                .authorise("edge-1", supervisor.verifying_key().identity_hex()),
        )
    }

    fn approval(supervisor: &SignatureKeyPair, params_digest: &str) -> String {
        sign_cosignature(
            AGENT,
            "edge-1",
            "send_command",
            params_digest,
            EXPIRES,
            supervisor,
        )
        .expect("sign")
    }

    fn request<'a>(
        signature: &'a str,
        params_digest: &'a str,
        now: &'a str,
    ) -> CoSignatureRequest<'a> {
        CoSignatureRequest {
            edge_id: "edge-1",
            tool_name: "send_command",
            agent_did: AGENT,
            input_params_digest: params_digest,
            now_utc: now,
            signature,
        }
    }

    #[test]
    fn an_approval_for_this_exact_call_verifies() {
        let supervisor = key(3);
        let sig = approval(&supervisor, "d1");
        assert!(cosign_verifier(&supervisor).verify(&request(&sig, "d1", NOW)));
    }

    #[test]
    fn an_approval_does_not_generalise_to_a_different_call() {
        let supervisor = key(3);
        let v = cosign_verifier(&supervisor);
        // Approved for SAFE_MODE's arguments…
        let sig = approval(&supervisor, "digest-of-SAFE_MODE");
        // …and presented for DEORBIT's. This is the whole point: an approval
        // over the verb alone would have authorised it.
        assert!(!v.verify(&request(&sig, "digest-of-DEORBIT", NOW)));

        // Nor to a different tool, agent, or edge.
        let mut other_tool = request(&sig, "digest-of-SAFE_MODE", NOW);
        other_tool.tool_name = "purge_archive";
        assert!(!v.verify(&other_tool));

        let mut other_agent = request(&sig, "digest-of-SAFE_MODE", NOW);
        other_agent.agent_did = "did:syntriass:agent:AGT-2";
        assert!(!v.verify(&other_agent));

        let mut other_edge = request(&sig, "digest-of-SAFE_MODE", NOW);
        other_edge.edge_id = "edge-2";
        assert!(!v.verify(&other_edge));
    }

    #[test]
    fn an_approval_expires_rather_than_standing_forever() {
        let supervisor = key(3);
        let v = cosign_verifier(&supervisor);
        let sig = approval(&supervisor, "d1");
        assert!(v.verify(&request(&sig, "d1", NOW)));
        // One millisecond past the expiry.
        assert!(!v.verify(&request(&sig, "d1", "2026-06-01T00:05:00.001Z")));
        assert!(!v.verify(&request(&sig, "d1", "2027-01-01T00:00:00.000Z")));
    }

    #[test]
    fn an_unauthorised_supervisor_cannot_approve_anything() {
        let supervisor = key(3);
        let impostor = key(4);
        let sig = approval(&impostor, "d1");
        assert!(!cosign_verifier(&supervisor).verify(&request(&sig, "d1", NOW)));
    }

    #[test]
    fn a_tampered_or_malformed_approval_is_refused() {
        let supervisor = key(3);
        let v = cosign_verifier(&supervisor);
        // Not JSON at all.
        assert!(!v.verify(&request("not-an-envelope", "d1", NOW)));
        // JSON, but not an attestation envelope.
        assert!(!v.verify(&request("{\"hello\":\"world\"}", "d1", NOW)));
        // A real envelope with its payload edited: same signature, new claim.
        let sig = approval(&supervisor, "d1");
        let mut envelope: Value = serde_json::from_str(&sig).unwrap();
        envelope["payload"]["inputParamsDigest"] = json!("d2");
        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(!v.verify(&request(&tampered, "d2", NOW)));
    }

    #[test]
    fn an_empty_cosignature_authority_keeps_multisig_tools_uninvocable() {
        let supervisor = key(3);
        let sig = approval(&supervisor, "d1");
        let v = PqcCoSignatureVerifier::new(CoSignatureAuthority::new());
        assert!(!v.verify(&request(&sig, "d1", NOW)));
    }
}
