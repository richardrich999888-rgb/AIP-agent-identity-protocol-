//! Who was actually on the other end of the wire.
//!
//! # The hole this closes
//!
//! Until now `agentDid` reached the funnel as a *claim* — a string in the
//! request saying which agent was calling. Everything downstream was rigorous
//! about that string: the delegation graph resolved from it, clearance
//! narrowed along it, every packet recorded it. But nothing established that
//! the caller was that agent. The ledger faithfully recorded **who said they
//! were acting**, which is not the same thing as who acted, and the whole
//! value of non-repudiable evidence rests on the difference.
//!
//! A [`PrincipalBinding`] is the missing fact: this session was authenticated,
//! by this method, to this credential, at this time. It is sealed into the
//! evidence packet, so an offline verifier reading an exported ledger can
//! check not just that a call was authorised but that the caller was proven
//! to be the agent the authorisation was granted to.
//!
//! # Enrolment is where a human vouches
//!
//! A credential does not name an agent by itself: a key is a key. The
//! [`CredentialRegistry`] is the map from agent DID to the credentials
//! authorised to speak for it, and populating it is a deliberate act —
//! enrolment — that gets anchored in the lifecycle chain like any other
//! authority decision. That is on purpose. The moment where "this key is that
//! agent" is decided is exactly the moment worth having an audit record of.
//!
//! # What this module is not
//!
//! It holds no verification machinery. Checking a TLS peer certificate,
//! validating a SPIFFE SVID, or verifying a signature over a challenge are
//! transport concerns and live with the transport. What lives here is the
//! *record* of that having happened, because the record has to travel with
//! the evidence to somewhere the transport does not reach.

use serde_json::{json, Value};
use std::collections::BTreeMap;

/// How a caller's identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthMethod {
    /// Nothing was proven. Recorded explicitly rather than left absent,
    /// because "we did not check" is itself a fact an auditor needs, and an
    /// omitted field could equally mean "an older writer produced this".
    Unauthenticated,
    /// The caller signed a challenge the gateway issued, with a key enrolled
    /// against the DID it claimed.
    ProofOfPossession,
    /// A client certificate presented on the transport channel.
    MutualTls,
    /// A SPIFFE verifiable identity document from the workload's platform.
    Spiffe,
    /// A hardware or enclave quote — TPM, TEE, or a cloud instance identity
    /// document.
    PlatformAttestation,
}

impl AuthMethod {
    /// The wire vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::ProofOfPossession => "PROOF_OF_POSSESSION",
            Self::MutualTls => "MUTUAL_TLS",
            Self::Spiffe => "SPIFFE",
            Self::PlatformAttestation => "PLATFORM_ATTESTATION",
        }
    }

    /// Parses the wire vocabulary.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "UNAUTHENTICATED" => Self::Unauthenticated,
            "PROOF_OF_POSSESSION" => Self::ProofOfPossession,
            "MUTUAL_TLS" => Self::MutualTls,
            "SPIFFE" => Self::Spiffe,
            "PLATFORM_ATTESTATION" => Self::PlatformAttestation,
            _ => return None,
        })
    }

    /// True when something was actually proven.
    ///
    /// The one method that returns false is the one that proves nothing, so
    /// callers gate on this rather than on a list they might forget to update
    /// when a method is added.
    pub fn is_proven(self) -> bool {
        self != Self::Unauthenticated
    }
}

/// The established identity of a session's caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalBinding {
    /// The agent DID the caller was proven to speak for.
    pub agent_did: String,
    /// How it was proven.
    pub method: AuthMethod,
    /// SHA-256 of the credential that proved it — a certificate, a public
    /// key, an attestation document. The digest rather than the credential
    /// so the ledger identifies exactly what was presented without becoming
    /// a place secrets accumulate.
    pub credential_digest: String,
    /// ISO-8601 UTC.
    pub verified_at_utc: String,
}

impl PrincipalBinding {
    /// A binding for a proven identity.
    pub fn proven(
        agent_did: impl Into<String>,
        method: AuthMethod,
        credential_digest: impl Into<String>,
        verified_at_utc: impl Into<String>,
    ) -> Self {
        Self {
            agent_did: agent_did.into(),
            method,
            credential_digest: credential_digest.into(),
            verified_at_utc: verified_at_utc.into(),
        }
    }

    /// A binding recording that nothing was proven.
    pub fn unauthenticated(agent_did: impl Into<String>, at_utc: impl Into<String>) -> Self {
        Self {
            agent_did: agent_did.into(),
            method: AuthMethod::Unauthenticated,
            credential_digest: String::new(),
            verified_at_utc: at_utc.into(),
        }
    }

    /// True when the caller actually proved who it was.
    pub fn is_proven(&self) -> bool {
        self.method.is_proven()
    }

    /// The canonical JSON shape sealed into an evidence packet.
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "agentDid": self.agent_did,
            "method": self.method.as_str(),
            "verifiedAtUtc": self.verified_at_utc,
        });
        // Omitted when there is nothing to name, rather than written as an
        // empty string that could be mistaken for a real digest.
        if !self.credential_digest.is_empty() {
            out["credentialDigest"] = json!(self.credential_digest);
        }
        out
    }

    /// Reads a binding back from a sealed packet's `principal` field.
    pub fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            agent_did: value.get("agentDid")?.as_str()?.to_string(),
            method: AuthMethod::parse(value.get("method")?.as_str()?)?,
            credential_digest: value
                .get("credentialDigest")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            verified_at_utc: value.get("verifiedAtUtc")?.as_str()?.to_string(),
        })
    }
}

/// The anchor type recording that a credential became authoritative.
pub const ENROLMENT_ANCHOR: &str = "AGENT_CREDENTIAL_ENROLMENT";

/// The anchor type recording that a credential was withdrawn.
pub const REVOCATION_ANCHOR: &str = "AGENT_CREDENTIAL_REVOCATION";

/// Which credentials may speak for which agents.
///
/// A key is only a key until somebody says whose it is. This is that
/// statement, and [`CredentialRegistry::enrol`] is the deliberate act that
/// makes it — the point at which an operator takes responsibility for the
/// binding.
#[derive(Debug, Default, Clone)]
pub struct CredentialRegistry {
    bindings: BTreeMap<String, Vec<CredentialRecord>>,
}

/// One enrolled credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    /// SHA-256 of the credential.
    pub digest: String,
    /// How this credential authenticates.
    pub method: AuthMethod,
    /// Whether it is still accepted.
    pub revoked: bool,
    /// ISO-8601 UTC of enrolment.
    pub enrolled_at_utc: String,
}

impl CredentialRegistry {
    /// An empty registry: nothing may speak for anything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorises `digest` to speak for `agent_did`.
    ///
    /// Enrolling the same digest twice is idempotent rather than an error, so
    /// replaying an enrolment journal converges instead of accumulating
    /// duplicates — but a *revoked* credential is never silently reinstated
    /// by a replay, since that would let an old record undo a withdrawal.
    pub fn enrol(&mut self, agent_did: &str, digest: &str, method: AuthMethod, at_utc: &str) {
        let records = self.bindings.entry(agent_did.to_string()).or_default();
        if records.iter().any(|r| r.digest == digest) {
            return;
        }
        records.push(CredentialRecord {
            digest: digest.to_string(),
            method,
            revoked: false,
            enrolled_at_utc: at_utc.to_string(),
        });
    }

    /// Withdraws a credential. The agent keeps any others it holds, so a
    /// compromised key can be pulled without taking the agent offline.
    pub fn revoke(&mut self, agent_did: &str, digest: &str) {
        if let Some(records) = self.bindings.get_mut(agent_did) {
            for record in records.iter_mut().filter(|r| r.digest == digest) {
                record.revoked = true;
            }
        }
    }

    /// Withdraws every credential an agent holds.
    pub fn revoke_all(&mut self, agent_did: &str) {
        if let Some(records) = self.bindings.get_mut(agent_did) {
            for record in records.iter_mut() {
                record.revoked = true;
            }
        }
    }

    /// True when `digest` is currently authorised to speak for `agent_did`
    /// using `method`.
    ///
    /// The method must match what was enrolled: a key enrolled for
    /// proof-of-possession does not become a valid TLS client certificate
    /// because its bytes happen to hash the same way.
    pub fn is_bound(&self, agent_did: &str, digest: &str, method: AuthMethod) -> bool {
        self.bindings.get(agent_did).is_some_and(|records| {
            records
                .iter()
                .any(|r| !r.revoked && r.digest == digest && r.method == method)
        })
    }

    /// Every credential enrolled for an agent, revoked ones included — the
    /// history is audit material.
    pub fn records_for(&self, agent_did: &str) -> &[CredentialRecord] {
        self.bindings
            .get(agent_did)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// How many agents have any credential enrolled.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// True when nothing is enrolled.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// The canonical payload for an [`ENROLMENT_ANCHOR`], so the moment a
    /// credential became authoritative is itself on the tamper-evident record.
    pub fn enrolment_payload(digest: &str, method: AuthMethod) -> Value {
        json!({ "credentialDigest": digest, "method": method.as_str() })
    }

    /// The canonical payload for a [`REVOCATION_ANCHOR`].
    pub fn revocation_payload(digest: &str, reason: &str) -> Value {
        json!({ "credentialDigest": digest, "reason": reason })
    }

    /// Rebuilds the registry by replaying lifecycle anchors in chain order.
    ///
    /// This is what makes credential history auditable rather than merely
    /// configured: an offline verifier holding an exported ledger can
    /// reconstruct exactly which keys could speak for which agents at any
    /// point, and cannot be told a different story than the chain tells.
    pub fn from_anchors(anchors: &[Value]) -> Self {
        let mut registry = Self::new();
        for anchor in anchors {
            registry.apply_anchor(anchor);
        }
        registry
    }

    /// Applies one lifecycle anchor.
    ///
    /// Order matters and is respected: a revocation followed by a
    /// re-enrolment of the same digest re-authorises it, because that is a
    /// deliberate operator decision recorded in sequence. What cannot happen
    /// is a *replayed* older enrolment undoing a later revocation — see
    /// [`CredentialRegistry::enrol`], which never resurrects a withdrawn
    /// record.
    pub fn apply_anchor(&mut self, anchor: &Value) {
        let Some(did) = anchor.get("agentDid").and_then(Value::as_str) else {
            return;
        };
        let Some(digest) = anchor
            .pointer("/payload/credentialDigest")
            .and_then(Value::as_str)
        else {
            return;
        };
        let at = anchor
            .get("timestampUtc")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match anchor.get("anchorType").and_then(Value::as_str) {
            Some(ENROLMENT_ANCHOR) => {
                let Some(method) = anchor
                    .pointer("/payload/method")
                    .and_then(Value::as_str)
                    .and_then(AuthMethod::parse)
                else {
                    return;
                };
                // A replayed anchor must not reinstate a revoked credential,
                // so re-enrolment after revocation replaces the record rather
                // than being absorbed by the idempotence in `enrol`.
                self.bindings
                    .entry(did.to_string())
                    .or_default()
                    .retain(|r| !(r.digest == digest && r.revoked));
                self.enrol(did, digest, method, at);
            }
            Some(REVOCATION_ANCHOR) => self.revoke(did, digest),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "did:syntriass:agent:AGT-1";
    const T: &str = "2026-08-27T00:00:00.000Z";

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    #[test]
    fn nothing_speaks_for_an_agent_until_a_credential_is_enrolled() {
        let mut registry = CredentialRegistry::new();
        assert!(!registry.is_bound(AGENT, &digest('a'), AuthMethod::ProofOfPossession));
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, T);
        assert!(registry.is_bound(AGENT, &digest('a'), AuthMethod::ProofOfPossession));
        // A different key, however valid in itself, speaks for nobody here.
        assert!(!registry.is_bound(AGENT, &digest('b'), AuthMethod::ProofOfPossession));
        // Nor does the right key for a different agent.
        assert!(!registry.is_bound(
            "did:syntriass:agent:AGT-2",
            &digest('a'),
            AuthMethod::ProofOfPossession
        ));
    }

    #[test]
    fn a_credential_is_bound_to_the_method_it_was_enrolled_for() {
        let mut registry = CredentialRegistry::new();
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, T);
        // The same bytes presented as a TLS certificate prove nothing: what
        // was vouched for was a signing key, not a certificate.
        assert!(!registry.is_bound(AGENT, &digest('a'), AuthMethod::MutualTls));
    }

    #[test]
    fn revoking_one_credential_leaves_the_agents_others_working() {
        let mut registry = CredentialRegistry::new();
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, T);
        registry.enrol(AGENT, &digest('b'), AuthMethod::ProofOfPossession, T);
        registry.revoke(AGENT, &digest('a'));
        assert!(!registry.is_bound(AGENT, &digest('a'), AuthMethod::ProofOfPossession));
        assert!(registry.is_bound(AGENT, &digest('b'), AuthMethod::ProofOfPossession));

        registry.revoke_all(AGENT);
        assert!(!registry.is_bound(AGENT, &digest('b'), AuthMethod::ProofOfPossession));
        // The history survives revocation: what was authorised when is audit
        // material, not something to delete.
        assert_eq!(registry.records_for(AGENT).len(), 2);
    }

    #[test]
    fn replaying_an_enrolment_never_reinstates_a_revoked_credential() {
        let mut registry = CredentialRegistry::new();
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, T);
        registry.revoke(AGENT, &digest('a'));
        // A replayed journal, or an attacker re-sending an old enrolment.
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, T);
        assert!(
            !registry.is_bound(AGENT, &digest('a'), AuthMethod::ProofOfPossession),
            "a replayed enrolment undid a revocation"
        );
        assert_eq!(
            registry.records_for(AGENT).len(),
            1,
            "and did not duplicate"
        );
    }

    #[test]
    fn a_binding_round_trips_through_its_sealed_form() {
        let binding =
            PrincipalBinding::proven(AGENT, AuthMethod::ProofOfPossession, digest('a'), T);
        let json = binding.to_json();
        assert_eq!(json["method"], "PROOF_OF_POSSESSION");
        assert_eq!(json["credentialDigest"], digest('a'));
        assert_eq!(PrincipalBinding::from_json(&json), Some(binding));
    }

    #[test]
    fn an_unauthenticated_session_records_that_fact_rather_than_hiding_it() {
        let binding = PrincipalBinding::unauthenticated(AGENT, T);
        assert!(!binding.is_proven());
        let json = binding.to_json();
        assert_eq!(json["method"], "UNAUTHENTICATED");
        // No empty digest that could be mistaken for a real one.
        assert!(json.get("credentialDigest").is_none());
        assert_eq!(PrincipalBinding::from_json(&json), Some(binding));
    }

    #[test]
    fn every_method_but_the_empty_one_counts_as_proven() {
        assert!(!AuthMethod::Unauthenticated.is_proven());
        for method in [
            AuthMethod::ProofOfPossession,
            AuthMethod::MutualTls,
            AuthMethod::Spiffe,
            AuthMethod::PlatformAttestation,
        ] {
            assert!(method.is_proven(), "{method:?}");
            assert_eq!(AuthMethod::parse(method.as_str()), Some(method));
        }
        assert_eq!(AuthMethod::parse("SOMETHING_ELSE"), None);
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use serde_json::json;

    const AGENT: &str = "did:syntriass:agent:AGT-1";

    fn anchor(seq: u64, kind: &str, payload: Value, ts: &str) -> Value {
        json!({
            "anchorId": format!("{AGENT}#anchor-{seq}"),
            "sequenceNumber": seq,
            "anchorType": kind,
            "agentDid": AGENT,
            "timestampUtc": ts,
            "payload": payload,
        })
    }

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    #[test]
    fn replaying_the_chain_reconstructs_who_could_speak_for_whom() {
        let anchors = [
            anchor(
                1,
                ENROLMENT_ANCHOR,
                CredentialRegistry::enrolment_payload(&digest('a'), AuthMethod::ProofOfPossession),
                "2026-08-01T00:00:00.000Z",
            ),
            anchor(
                2,
                ENROLMENT_ANCHOR,
                CredentialRegistry::enrolment_payload(&digest('b'), AuthMethod::MutualTls),
                "2026-08-02T00:00:00.000Z",
            ),
            anchor(
                3,
                REVOCATION_ANCHOR,
                CredentialRegistry::revocation_payload(&digest('a'), "key rotation"),
                "2026-08-03T00:00:00.000Z",
            ),
        ];
        let registry = CredentialRegistry::from_anchors(&anchors);
        assert!(!registry.is_bound(AGENT, &digest('a'), AuthMethod::ProofOfPossession));
        assert!(registry.is_bound(AGENT, &digest('b'), AuthMethod::MutualTls));
        // The withdrawn credential is still on the record: what was
        // authorised when is the audit question.
        assert_eq!(registry.records_for(AGENT).len(), 2);
    }

    #[test]
    fn the_chains_order_is_authoritative_including_a_deliberate_re_enrolment() {
        // enrol → revoke → enrol is three operator decisions in sequence, and
        // the final state is enrolled. An attacker cannot forge this ordering
        // without breaking the chain, which is what makes trusting it sound.
        let anchors = [
            anchor(
                1,
                ENROLMENT_ANCHOR,
                CredentialRegistry::enrolment_payload(&digest('a'), AuthMethod::ProofOfPossession),
                "t1",
            ),
            anchor(
                2,
                REVOCATION_ANCHOR,
                CredentialRegistry::revocation_payload(&digest('a'), "suspected compromise"),
                "t2",
            ),
            anchor(
                3,
                ENROLMENT_ANCHOR,
                CredentialRegistry::enrolment_payload(&digest('a'), AuthMethod::ProofOfPossession),
                "t3",
            ),
        ];
        assert!(CredentialRegistry::from_anchors(&anchors).is_bound(
            AGENT,
            &digest('a'),
            AuthMethod::ProofOfPossession
        ));

        // The direct API keeps its separate guarantee: a config replay that
        // re-runs an old enrolment does *not* resurrect a withdrawn key,
        // because there is no chain order there to vouch for the intent.
        let mut registry = CredentialRegistry::new();
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, "t1");
        registry.revoke(AGENT, &digest('a'));
        registry.enrol(AGENT, &digest('a'), AuthMethod::ProofOfPossession, "t1");
        assert!(!registry.is_bound(AGENT, &digest('a'), AuthMethod::ProofOfPossession));
    }

    #[test]
    fn malformed_or_unrelated_anchors_are_ignored_rather_than_guessed_at() {
        let anchors = [
            // Not a credential anchor.
            anchor(
                1,
                "AGENT_GENESIS",
                json!({ "modelDigest": digest('z') }),
                "t",
            ),
            // Enrolment with no method.
            anchor(
                2,
                ENROLMENT_ANCHOR,
                json!({ "credentialDigest": digest('a') }),
                "t",
            ),
            // Enrolment with an unknown method — must not default to something.
            anchor(
                3,
                ENROLMENT_ANCHOR,
                json!({ "credentialDigest": digest('a'), "method": "VIBES" }),
                "t",
            ),
            // No digest at all.
            anchor(4, ENROLMENT_ANCHOR, json!({ "method": "MUTUAL_TLS" }), "t"),
        ];
        let registry = CredentialRegistry::from_anchors(&anchors);
        assert!(registry.is_empty() || registry.records_for(AGENT).is_empty());
    }
}
