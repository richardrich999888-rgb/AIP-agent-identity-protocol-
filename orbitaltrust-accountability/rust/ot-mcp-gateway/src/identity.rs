//! Establishing that the caller is the agent it says it is.
//!
//! # The rule that makes this worth anything
//!
//! **A credential the client controls proves nothing.** If the proof is just
//! a field in the request body, a caller who wants to be someone else simply
//! writes someone else's name in it. So every attestor here draws on one of
//! exactly two things the client cannot forge:
//!
//! - **The channel.** A TLS client certificate, a SPIFFE SVID from the
//!   workload's platform, a hardware quote — extracted by the transport from
//!   the connection itself and handed in as a [`PeerCredential`]. The message
//!   body has no say.
//! - **A challenge the gateway issued.** For transports with no channel
//!   identity — stdio being the obvious one — the gateway issues a
//!   single-use nonce and the caller signs it. The signature travels in the
//!   message, which is fine, because the thing being signed is not the
//!   client's to choose.
//!
//! What is never acceptable is a self-asserted identity field, which is
//! precisely what this module exists to replace.
//!
//! # Why a nonce and not a timestamp
//!
//! A signature over a timestamp is replayable for as long as the clock skew
//! window allows, and every captured request becomes a credential for that
//! window. A gateway-issued nonce, consumed on first use, means a captured
//! proof is worth exactly one already-completed session.
//!
//! # Enrolment, not derivation
//!
//! A verified signature says "whoever holds key K signed this". It does not
//! say K belongs to agent A. That statement lives in the
//! [`CredentialRegistry`], put there by a deliberate enrolment, and every
//! attestor checks it. A caller with a perfectly valid key that nobody
//! enrolled is a caller with no identity here.

use ot_accountability_core::identity::{AuthMethod, CredentialRegistry, PrincipalBinding};
use ot_accountability_core::sha256_hex;
use ot_pqc::verify_attestation_json;
use serde_json::Value;
use std::sync::{Arc, RwLock};

/// A registry shared between the gateway and its attestor.
///
/// Shared rather than owned so a revocation takes effect on the next
/// authentication instead of the next restart. A compromised key that stays
/// usable until someone reboots the proxy is a key that is still compromised,
/// and the window is exactly when it matters most.
pub type SharedRegistry = Arc<RwLock<CredentialRegistry>>;

/// Wraps a registry for sharing.
pub fn shared(registry: CredentialRegistry) -> SharedRegistry {
    Arc::new(RwLock::new(registry))
}

/// The signing context for identity challenges, keeping these signatures
/// domain-separated from every other ML-DSA signature in the system: a
/// signature made for one purpose must not be replayable as another.
pub const CHALLENGE_CONTEXT: &[u8] = b"OT-MCP-GATEWAY-IDENTITY-CHALLENGE-v1";

/// Why an identity could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// No proof was offered at all.
    NoProofOffered,
    /// The challenge was absent, already spent, or not the one issued.
    BadChallenge(String),
    /// The proof did not verify cryptographically.
    ProofInvalid(String),
    /// The credential verified, but nobody enrolled it for this agent.
    NotEnrolled {
        /// The DID the caller claimed.
        agent_did: String,
        /// SHA-256 of what it presented.
        credential_digest: String,
    },
    /// The transport supplied a credential of a kind this attestor cannot check.
    UnsupportedCredential(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProofOffered => write!(f, "no proof of identity was offered"),
            Self::BadChallenge(why) => write!(f, "challenge rejected: {why}"),
            Self::ProofInvalid(why) => write!(f, "proof did not verify: {why}"),
            Self::NotEnrolled {
                agent_did,
                credential_digest,
            } => write!(
                f,
                "credential {}… is not enrolled for {agent_did}",
                &credential_digest[..credential_digest.len().min(12)]
            ),
            Self::UnsupportedCredential(kind) => {
                write!(f, "this attestor cannot verify a {kind} credential")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// What the transport extracted from the connection itself.
///
/// Constructed by the transport from the channel, never parsed out of a
/// request body — that distinction is the entire security value of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCredential {
    /// The channel carries no identity — plain stdio, an unauthenticated
    /// socket. Proof must come from a signed challenge instead.
    None,
    /// A DER-encoded X.509 client certificate from a mutual-TLS handshake.
    ClientCertificate(Vec<u8>),
    /// A SPIFFE ID and the SVID bytes that carried it, already validated
    /// against the trust bundle by the TLS layer.
    Spiffe {
        /// The `spiffe://` URI.
        id: String,
        /// The document bytes, for digesting into the record.
        document: Vec<u8>,
    },
    /// A hardware or enclave quote: TPM, TEE, or cloud instance identity.
    PlatformQuote {
        /// What produced it, for the record.
        issuer: String,
        /// The quote bytes.
        document: Vec<u8>,
    },
}

impl PeerCredential {
    /// SHA-256 of the credential material, or `None` when there is none.
    pub fn digest(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::ClientCertificate(der) => Some(sha256_hex(&hex_of(der))),
            Self::Spiffe { document, .. } | Self::PlatformQuote { document, .. } => {
                Some(sha256_hex(&hex_of(document)))
            }
        }
    }

    /// The authentication method this credential represents.
    pub fn method(&self) -> AuthMethod {
        match self {
            Self::None => AuthMethod::Unauthenticated,
            Self::ClientCertificate(_) => AuthMethod::MutualTls,
            Self::Spiffe { .. } => AuthMethod::Spiffe,
            Self::PlatformQuote { .. } => AuthMethod::PlatformAttestation,
        }
    }

    /// A short label for diagnostics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientCertificate(_) => "client-certificate",
            Self::Spiffe { .. } => "spiffe",
            Self::PlatformQuote { .. } => "platform-quote",
        }
    }
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Supplies unpredictable challenge nonces.
///
/// A trait so tests can be deterministic while production uses real entropy.
/// A predictable nonce would let an attacker pre-compute a signature for a
/// challenge that has not been issued yet, which defeats the whole mechanism.
pub trait NonceSource: Send + Sync {
    /// A fresh nonce. Must be unpredictable and must not repeat.
    fn next_nonce(&self) -> String;
}

/// Nonces from the operating system's entropy source.
#[derive(Debug, Default)]
pub struct OsNonce;

impl NonceSource for OsNonce {
    fn next_nonce(&self) -> String {
        let mut bytes = [0u8; 32];
        // A failure here means the OS entropy source is unavailable, which is
        // not a condition to paper over with a weaker nonce: panicking is the
        // safe outcome, because the alternative is issuing a guessable
        // challenge and calling the result an authenticated session.
        getrandom::fill(&mut bytes).expect("OS entropy is unavailable");
        hex_of(&bytes)
    }
}

/// A fixed nonce. **Tests only** — a constant challenge is replayable by
/// definition, so this must never be wired into a deployment.
#[derive(Debug, Clone)]
pub struct FixedNonce(pub String);

impl NonceSource for FixedNonce {
    fn next_nonce(&self) -> String {
        self.0.clone()
    }
}

/// Establishes the identity behind a session.
pub trait IdentityAttestor: Send + Sync {
    /// A challenge for the caller to sign, when this attestor uses one.
    /// `None` for attestors that read identity from the channel instead.
    fn issue_challenge(&self) -> Option<String> {
        None
    }

    /// Verifies that the caller may act as `claimed_did`.
    ///
    /// `peer` is what the transport took from the channel; `proof` is the
    /// `_meta.governance.identityProof` value from the request body;
    /// `challenge` is the nonce this session was issued, if any.
    fn verify(
        &self,
        claimed_did: &str,
        peer: &PeerCredential,
        proof: &Value,
        challenge: Option<&str>,
        now_utc: &str,
    ) -> Result<PrincipalBinding, IdentityError>;
}

/// Verifies an ML-DSA signature over a gateway-issued challenge.
///
/// The path for transports with no channel identity. The caller signs the
/// nonce with a key enrolled against its DID, wrapped in the workspace's
/// attestation envelope — which already binds the embedded verifying key to
/// its claimed identity digest, so an attacker cannot swap in their own key
/// while keeping a trusted identity string.
pub struct PqcChallengeAttestor {
    registry: SharedRegistry,
    nonces: Box<dyn NonceSource>,
}

impl PqcChallengeAttestor {
    /// An attestor over a shared enrolment registry, using OS entropy.
    pub fn new(registry: SharedRegistry) -> Self {
        Self {
            registry,
            nonces: Box::new(OsNonce),
        }
    }

    /// Overrides the nonce source. Only [`FixedNonce`] in tests should ever
    /// need this.
    pub fn with_nonce_source(mut self, nonces: Box<dyn NonceSource>) -> Self {
        self.nonces = nonces;
        self
    }

    /// The shared enrolment registry.
    pub fn registry(&self) -> &SharedRegistry {
        &self.registry
    }
}

impl IdentityAttestor for PqcChallengeAttestor {
    fn issue_challenge(&self) -> Option<String> {
        Some(self.nonces.next_nonce())
    }

    fn verify(
        &self,
        claimed_did: &str,
        _peer: &PeerCredential,
        proof: &Value,
        challenge: Option<&str>,
        now_utc: &str,
    ) -> Result<PrincipalBinding, IdentityError> {
        if proof.is_null() {
            return Err(IdentityError::NoProofOffered);
        }
        let Some(challenge) = challenge else {
            return Err(IdentityError::BadChallenge(
                "no challenge is outstanding for this session".into(),
            ));
        };

        let verified = verify_attestation_json(proof, None)
            .map_err(|e| IdentityError::ProofInvalid(e.to_string()))?;

        // The signature is valid — over *what*? It must be over the nonce
        // this session was issued, or it is a replay of some other exchange.
        let signed_nonce = verified
            .payload
            .get("challenge")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                IdentityError::ProofInvalid("payload does not name a challenge".into())
            })?;
        if signed_nonce != challenge {
            return Err(IdentityError::BadChallenge(
                "the signed challenge is not the one issued to this session".into(),
            ));
        }
        // And it must be over *this* DID: a proof signed for agent A must not
        // be liftable into a session claiming to be agent B.
        let signed_did = verified
            .payload
            .get("agentDid")
            .and_then(Value::as_str)
            .ok_or_else(|| IdentityError::ProofInvalid("payload does not name an agent".into()))?;
        if signed_did != claimed_did {
            return Err(IdentityError::ProofInvalid(format!(
                "proof was signed for {signed_did}, not {claimed_did}"
            )));
        }

        // A valid signature says who holds the key, not whose key it is.
        // Enrolment is what says that.
        let digest = verified.signer_identity.clone();
        let enrolled = self
            .registry
            .read()
            .map(|r| r.is_bound(claimed_did, &digest, AuthMethod::ProofOfPossession))
            // A poisoned lock means some other thread panicked mid-update and
            // the registry's state is unknown. Refusing is the only safe
            // reading of "unknown" for an authorisation question.
            .unwrap_or(false);
        if !enrolled {
            return Err(IdentityError::NotEnrolled {
                agent_did: claimed_did.to_string(),
                credential_digest: digest,
            });
        }

        Ok(PrincipalBinding::proven(
            claimed_did,
            AuthMethod::ProofOfPossession,
            digest,
            now_utc,
        ))
    }
}

/// Takes identity from the channel: mutual TLS, SPIFFE, or a platform quote.
///
/// The transport is responsible for having *validated* the credential —
/// chain, expiry, trust bundle — before handing it over. This attestor's job
/// is the remaining question: does the validated credential belong to the
/// agent now claiming it.
pub struct ChannelCredentialAttestor {
    registry: SharedRegistry,
}

impl ChannelCredentialAttestor {
    /// An attestor over a shared enrolment registry.
    pub fn new(registry: SharedRegistry) -> Self {
        Self { registry }
    }

    /// The shared enrolment registry.
    pub fn registry(&self) -> &SharedRegistry {
        &self.registry
    }
}

impl IdentityAttestor for ChannelCredentialAttestor {
    fn verify(
        &self,
        claimed_did: &str,
        peer: &PeerCredential,
        _proof: &Value,
        _challenge: Option<&str>,
        now_utc: &str,
    ) -> Result<PrincipalBinding, IdentityError> {
        let Some(digest) = peer.digest() else {
            return Err(IdentityError::UnsupportedCredential(
                peer.label().to_string(),
            ));
        };
        let method = peer.method();
        let enrolled = self
            .registry
            .read()
            .map(|r| r.is_bound(claimed_did, &digest, method))
            .unwrap_or(false);
        if !enrolled {
            return Err(IdentityError::NotEnrolled {
                agent_did: claimed_did.to_string(),
                credential_digest: digest,
            });
        }
        Ok(PrincipalBinding::proven(
            claimed_did,
            method,
            digest,
            now_utc,
        ))
    }
}

/// Proves nothing and says so.
///
/// **Development only.** It exists so an unauthenticated deployment is an
/// explicit, named choice at the call site rather than the silent default
/// that happens when nobody configures an attestor. Every session it
/// establishes records `UNAUTHENTICATED`, and a funnel with the default
/// `require_verified_identity` will refuse to act on it — so wiring this in
/// does not quietly disable the guarantee, it disables the gateway until
/// somebody also relaxes the funnel on purpose.
pub struct UnauthenticatedAttestor;

impl IdentityAttestor for UnauthenticatedAttestor {
    fn verify(
        &self,
        claimed_did: &str,
        _peer: &PeerCredential,
        _proof: &Value,
        _challenge: Option<&str>,
        now_utc: &str,
    ) -> Result<PrincipalBinding, IdentityError> {
        Ok(PrincipalBinding::unauthenticated(claimed_did, now_utc))
    }
}

/// Builds the payload a client signs to answer a challenge.
///
/// Both fields are load-bearing: the challenge stops replay across sessions,
/// and the DID stops a valid proof for one agent being lifted into another
/// agent's session.
pub fn challenge_payload(agent_did: &str, challenge: &str) -> Value {
    serde_json::json!({ "agentDid": agent_did, "challenge": challenge })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ot_pqc::{attest_json, CryptoSuite, SignatureKeyPair};

    const AGENT: &str = "did:syntriass:agent:AGT-1";
    const NOW: &str = "2026-08-27T12:00:00.000Z";
    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn keypair(seed: u8) -> SignatureKeyPair {
        SignatureKeyPair::from_seed(CryptoSuite::X25519MlKem1024MlDsa87, &[seed; 32])
            .expect("keygen")
    }

    fn sign(pair: &SignatureKeyPair, did: &str, challenge: &str) -> Value {
        attest_json(challenge_payload(did, challenge), pair, CHALLENGE_CONTEXT).expect("sign")
    }

    fn attestor(pair: &SignatureKeyPair) -> PqcChallengeAttestor {
        let mut registry = CredentialRegistry::new();
        registry.enrol(
            AGENT,
            &pair.verifying_key().identity_hex(),
            AuthMethod::ProofOfPossession,
            NOW,
        );
        PqcChallengeAttestor::new(shared(registry))
            .with_nonce_source(Box::new(FixedNonce(NONCE.to_string())))
    }

    #[test]
    fn an_enrolled_key_signing_the_issued_challenge_establishes_the_identity() {
        let pair = keypair(1);
        let a = attestor(&pair);
        let challenge = a.issue_challenge().unwrap();
        let binding = a
            .verify(
                AGENT,
                &PeerCredential::None,
                &sign(&pair, AGENT, &challenge),
                Some(&challenge),
                NOW,
            )
            .expect("should verify");
        assert!(binding.is_proven());
        assert_eq!(binding.agent_did, AGENT);
        assert_eq!(binding.method, AuthMethod::ProofOfPossession);
        assert_eq!(
            binding.credential_digest,
            pair.verifying_key().identity_hex()
        );
    }

    #[test]
    fn a_valid_signature_over_the_wrong_challenge_is_a_replay_and_is_refused() {
        let pair = keypair(1);
        let a = attestor(&pair);
        // Captured from an earlier session.
        let stale = sign(&pair, AGENT, "aaaa");
        let err = a
            .verify(AGENT, &PeerCredential::None, &stale, Some(NONCE), NOW)
            .unwrap_err();
        assert!(matches!(err, IdentityError::BadChallenge(_)), "{err}");
    }

    #[test]
    fn a_proof_signed_for_one_agent_cannot_be_lifted_into_anothers_session() {
        let pair = keypair(1);
        let mut registry = CredentialRegistry::new();
        // The same key is legitimately enrolled for both agents.
        registry.enrol(
            AGENT,
            &pair.verifying_key().identity_hex(),
            AuthMethod::ProofOfPossession,
            NOW,
        );
        registry.enrol(
            "did:syntriass:agent:AGT-2",
            &pair.verifying_key().identity_hex(),
            AuthMethod::ProofOfPossession,
            NOW,
        );
        let a = PqcChallengeAttestor::new(shared(registry))
            .with_nonce_source(Box::new(FixedNonce(NONCE.to_string())));

        // A proof made out to AGT-1, presented in a session claiming AGT-2.
        let proof = sign(&pair, AGENT, NONCE);
        let err = a
            .verify(
                "did:syntriass:agent:AGT-2",
                &PeerCredential::None,
                &proof,
                Some(NONCE),
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, IdentityError::ProofInvalid(_)), "{err}");
    }

    #[test]
    fn a_perfectly_valid_key_that_nobody_enrolled_has_no_identity_here() {
        let enrolled = keypair(1);
        let stranger = keypair(2);
        let a = attestor(&enrolled);
        let err = a
            .verify(
                AGENT,
                &PeerCredential::None,
                &sign(&stranger, AGENT, NONCE),
                Some(NONCE),
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, IdentityError::NotEnrolled { .. }), "{err}");
    }

    #[test]
    fn a_revoked_credential_stops_working_immediately() {
        let pair = keypair(1);
        let mut registry = CredentialRegistry::new();
        let digest = pair.verifying_key().identity_hex();
        registry.enrol(AGENT, &digest, AuthMethod::ProofOfPossession, NOW);
        registry.revoke(AGENT, &digest);
        let a = PqcChallengeAttestor::new(shared(registry))
            .with_nonce_source(Box::new(FixedNonce(NONCE.to_string())));
        assert!(matches!(
            a.verify(
                AGENT,
                &PeerCredential::None,
                &sign(&pair, AGENT, NONCE),
                Some(NONCE),
                NOW
            )
            .unwrap_err(),
            IdentityError::NotEnrolled { .. }
        ));
    }

    #[test]
    fn a_forged_proof_does_not_verify() {
        let pair = keypair(1);
        let a = attestor(&pair);
        let mut tampered = sign(&pair, AGENT, NONCE);
        // Same signature, different signed content.
        tampered["payload"]["challenge"] = serde_json::json!("something-else");
        let err = a
            .verify(AGENT, &PeerCredential::None, &tampered, Some(NONCE), NOW)
            .unwrap_err();
        assert!(matches!(err, IdentityError::ProofInvalid(_)), "{err}");
    }

    #[test]
    fn offering_no_proof_at_all_is_refused_rather_than_defaulting_open() {
        let pair = keypair(1);
        let a = attestor(&pair);
        assert_eq!(
            a.verify(AGENT, &PeerCredential::None, &Value::Null, Some(NONCE), NOW)
                .unwrap_err(),
            IdentityError::NoProofOffered
        );
        // And a proof with no outstanding challenge is refused too: there is
        // nothing for it to be an answer to.
        assert!(matches!(
            a.verify(
                AGENT,
                &PeerCredential::None,
                &sign(&pair, AGENT, NONCE),
                None,
                NOW
            )
            .unwrap_err(),
            IdentityError::BadChallenge(_)
        ));
    }

    #[test]
    fn channel_credentials_authenticate_by_their_own_method_and_no_other() {
        let cert = PeerCredential::ClientCertificate(vec![1, 2, 3, 4]);
        let digest = cert.digest().unwrap();
        let mut registry = CredentialRegistry::new();
        registry.enrol(AGENT, &digest, AuthMethod::MutualTls, NOW);
        let a = ChannelCredentialAttestor::new(shared(registry));

        let binding = a
            .verify(AGENT, &cert, &Value::Null, None, NOW)
            .expect("should verify");
        assert_eq!(binding.method, AuthMethod::MutualTls);
        assert_eq!(binding.credential_digest, digest);

        // The same bytes arriving as a SPIFFE document are not that
        // certificate: the enrolment was for a TLS credential.
        let spoofed = PeerCredential::Spiffe {
            id: "spiffe://example/agent".into(),
            document: vec![1, 2, 3, 4],
        };
        assert!(matches!(
            a.verify(AGENT, &spoofed, &Value::Null, None, NOW)
                .unwrap_err(),
            IdentityError::NotEnrolled { .. }
        ));

        // And a channel carrying no identity cannot be talked into providing one.
        assert!(matches!(
            a.verify(AGENT, &PeerCredential::None, &Value::Null, None, NOW)
                .unwrap_err(),
            IdentityError::UnsupportedCredential(_)
        ));
    }

    #[test]
    fn the_development_attestor_is_honest_about_proving_nothing() {
        let binding = UnauthenticatedAttestor
            .verify(AGENT, &PeerCredential::None, &Value::Null, None, NOW)
            .unwrap();
        assert!(!binding.is_proven());
        assert_eq!(binding.method, AuthMethod::Unauthenticated);
        assert!(binding.credential_digest.is_empty());
    }

    #[test]
    fn os_nonces_are_unique_and_full_width() {
        let source = OsNonce;
        let a = source.next_nonce();
        let b = source.next_nonce();
        assert_ne!(a, b, "a repeating nonce is a replayable challenge");
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
