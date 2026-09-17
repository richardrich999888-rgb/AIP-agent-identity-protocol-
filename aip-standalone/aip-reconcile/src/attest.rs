//! SD-09 — signing the reconciliation verdict.
//!
//! The reconciler computes a verdict ([`Reconciliation`]) but, until now, signed
//! nothing: `Reconciliation::canonical_bytes` documents itself as "for audit and
//! any later signing by a party that is one. This crate signs nothing." This
//! module is that party — a **fourth authority**, distinct from the agent, the
//! decision point, and the observer — that attests *"this reconciler produced
//! exactly this verdict"*.
//!
//! Why it matters: a bare [`Reconciliation`] read back from bytes is faithful
//! but unattributable — nothing binds it to the reconciler that computed it. A
//! [`SignedReconciliation`] can be committed to NEXORA, exported to an auditor,
//! and checked offline against trust anchors the verifier supplies. It unblocks
//! the committed-verdict path (SD-10/11/12) in
//! `SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md` §13.
//!
//! # What a signature here does and does not mean
//!
//! It means: *this reconciler key signed these exact verdict bytes.* It does
//! **not** upgrade the verdict's evidence strength — a `CannotProve` stays
//! `CannotProve` when signed, and an `Attested` verdict is still `Attested`, not
//! `Proven`. Signing attributes the verdict; it never strengthens it. The
//! reconciler remains the single authority that classifies divergence; this adds
//! a signature over its output, not a second opinion.
//!
//! # Boundaries (change-guard)
//!
//! - The signed preimage is domain-separated
//!   ([`RECONCILIATION_ATTESTATION_DOMAIN`], distinct from
//!   [`crate::RECONCILIATION_DOMAIN`]) and length-prefixed via
//!   `aip_types::canonical`, so a verdict's own canonical bytes can never be
//!   replayed as an attestation, and identity/version fields cannot be swapped.
//! - Trust anchors come from the verifier, never from the artifact.
//! - No existing signed struct, canonical encoder, or wire version changes; this
//!   is an additive new signed object.

use std::collections::HashMap;

use aip_crypto::custody::{Custodian, CustodyError, InMemoryCustodian};
use aip_crypto::{sha256, verify_ed25519};
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u32};
use aip_types::Signature;
use serde::{Deserialize, Serialize};

use crate::result::Reconciliation;

/// Domain tag for a reconciliation attestation. Distinct from
/// [`crate::RECONCILIATION_DOMAIN`] (the verdict's own encoding) so a signature
/// over one can never be valid over the other.
pub const RECONCILIATION_ATTESTATION_DOMAIN: &str = "SYNTRIASS/GHOST/RECONCILIATION_ATTESTATION/v1";

/// Version of the attestation envelope. Bumped only if the preimage layout
/// changes; the wrapped [`Reconciliation`] carries its own version.
pub const RECONCILIATION_ATTESTATION_VERSION: u16 = 1;

/// A reconciliation verdict signed by an independent reconciler authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReconciliation {
    pub version: u16,
    /// The signing reconciler's identity. Must equal `attestation.signer_id`.
    pub reconciler_id: String,
    /// Which of the reconciler's keys signed this; verifiers anchor
    /// `(reconciler_id, key_version)` pairs so rotation does not invalidate
    /// history and revocation is the removal of one pair.
    pub key_version: u32,
    pub reconciliation: Reconciliation,
    pub attestation: Signature,
}

impl SignedReconciliation {
    /// The exact bytes the reconciler signs. Domain-tagged and length-prefixed,
    /// binding the envelope version, the reconciler identity, the key version,
    /// and the whole verdict (via its own canonical encoding).
    pub fn signing_preimage(
        version: u16,
        reconciler_id: &str,
        key_version: u32,
        reconciliation: &Reconciliation,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, RECONCILIATION_ATTESTATION_DOMAIN);
        put_u16(&mut buf, version);
        put_str(&mut buf, reconciler_id);
        put_u32(&mut buf, key_version);
        // Length-prefixed embedding of the verdict's own canonical bytes: the
        // verdict encoding is injective, and the outer length prefix keeps this
        // preimage injective too.
        put_bytes(&mut buf, &reconciliation.canonical_bytes());
        buf
    }

    fn preimage(&self) -> Vec<u8> {
        Self::signing_preimage(
            self.version,
            &self.reconciler_id,
            self.key_version,
            &self.reconciliation,
        )
    }

    /// The verdict this attestation vouches for. A consumer that acts on the
    /// verdict must verify first; reading it does not imply it was checked.
    pub fn reconciliation(&self) -> &Reconciliation {
        &self.reconciliation
    }

    /// Verify against anchors the **verifier** supplies (never keys carried in
    /// the artifact). Checks, in order: envelope version, that the
    /// `(reconciler_id, key_version)` pair is trusted, that the signature's
    /// `signer_id` matches the claimed `reconciler_id`, that its committed
    /// payload hash matches the recomputed preimage, and finally the Ed25519
    /// signature. Any failure is a refusal, never a warning.
    pub fn verify(
        &self,
        anchors: &ReconcilerTrustAnchors,
    ) -> Result<(), ReconciliationAttestationError> {
        use ReconciliationAttestationError as E;
        if self.version != RECONCILIATION_ATTESTATION_VERSION {
            return Err(E::UnsupportedVersion(self.version));
        }
        let key = anchors
            .get(&self.reconciler_id, self.key_version)
            .ok_or_else(|| E::UntrustedReconciler {
                reconciler_id: self.reconciler_id.clone(),
                key_version: self.key_version,
            })?;
        if self.attestation.signer_id != self.reconciler_id {
            return Err(E::SignerMismatch);
        }
        if self.attestation.payload_hash != sha256(&self.preimage()) {
            return Err(E::PayloadHashMismatch);
        }
        match verify_ed25519(key, &self.attestation) {
            Ok(true) => Ok(()),
            _ => Err(E::SignatureInvalid),
        }
    }
}

/// Why a [`SignedReconciliation`] failed verification. Each is a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationAttestationError {
    UnsupportedVersion(u16),
    UntrustedReconciler {
        reconciler_id: String,
        key_version: u32,
    },
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
}

impl std::fmt::Display for ReconciliationAttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported attestation version {v}"),
            Self::UntrustedReconciler {
                reconciler_id,
                key_version,
            } => write!(
                f,
                "untrusted reconciler {reconciler_id:?} key {key_version}"
            ),
            Self::SignerMismatch => write!(f, "signature signer_id does not match reconciler_id"),
            Self::PayloadHashMismatch => {
                write!(f, "committed payload hash does not match the verdict")
            }
            Self::SignatureInvalid => write!(f, "signature did not verify"),
        }
    }
}

impl std::error::Error for ReconciliationAttestationError {}

/// The reconciler's signing key holder. Custody-based so the key may be wrapped
/// at rest or held off-host, exactly like the collector's evidence key; the raw
/// key is never exposed by this type.
pub struct ReconcilerSigner {
    reconciler_id: String,
    key_version: u32,
    custodian: Box<dyn Custodian>,
}

impl std::fmt::Debug for ReconcilerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconcilerSigner")
            .field("reconciler_id", &self.reconciler_id)
            .field("key_version", &self.key_version)
            .field("backend", &self.custodian.backend())
            .finish()
    }
}

impl ReconcilerSigner {
    /// Build from raw key bytes (development and tests). Production holds the key
    /// in a custodian via [`ReconcilerSigner::with_custodian`].
    pub fn new(
        reconciler_id: impl Into<String>,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, CustodyError> {
        Ok(Self {
            reconciler_id: reconciler_id.into(),
            key_version,
            custodian: Box::new(InMemoryCustodian::new(private_key, public_key)?),
        })
    }

    /// Build from any custodian (wrapped-file, HSM, …).
    pub fn with_custodian(
        reconciler_id: impl Into<String>,
        key_version: u32,
        custodian: Box<dyn Custodian>,
    ) -> Self {
        Self {
            reconciler_id: reconciler_id.into(),
            key_version,
            custodian,
        }
    }

    pub fn reconciler_id(&self) -> &str {
        &self.reconciler_id
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    pub fn public_key(&self) -> &[u8] {
        self.custodian.public_key()
    }

    /// Attest a verdict. The verdict is copied verbatim; signing never mutates
    /// or strengthens it.
    pub fn sign(
        &self,
        reconciliation: &Reconciliation,
    ) -> Result<SignedReconciliation, CustodyError> {
        let preimage = SignedReconciliation::signing_preimage(
            RECONCILIATION_ATTESTATION_VERSION,
            &self.reconciler_id,
            self.key_version,
            reconciliation,
        );
        let attestation = self.custodian.sign(&self.reconciler_id, &preimage)?;
        Ok(SignedReconciliation {
            version: RECONCILIATION_ATTESTATION_VERSION,
            reconciler_id: self.reconciler_id.clone(),
            key_version: self.key_version,
            reconciliation: reconciliation.clone(),
            attestation,
        })
    }
}

/// The verifier's set of trusted reconciler keys, keyed by
/// `(reconciler_id, key_version)` — the same shape observer anchors use, so
/// rotation and revocation work identically across authorities.
#[derive(Debug, Clone, Default)]
pub struct ReconcilerTrustAnchors {
    keys: HashMap<(String, u32), Vec<u8>>,
}

impl ReconcilerTrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, reconciler_id: &str, key_version: u32, public_key: &[u8]) -> Self {
        self.keys.insert(
            (reconciler_id.to_string(), key_version),
            public_key.to_vec(),
        );
        self
    }

    pub fn revoke(&mut self, reconciler_id: &str, key_version: u32) {
        self.keys.remove(&(reconciler_id.to_string(), key_version));
    }

    pub fn get(&self, reconciler_id: &str, key_version: u32) -> Option<&[u8]> {
        self.keys
            .get(&(reconciler_id.to_string(), key_version))
            .map(|k| k.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{
        ActionComparison, EvidenceStrength, IdentityComparison, LineageComparison, Provenance,
        ReasonCode, Reconciliation, ReconciliationResult, TemporalComparison, WireCorroboration,
    };
    use aip_crypto::{generate_ed25519_keypair, sign_ed25519};

    const RID: &str = "reconciler.pilot.example";
    const KV: u32 = 1;

    /// A representative verdict. Built as an in-crate literal (the struct is
    /// `#[non_exhaustive]` only to other crates); the exact values do not matter
    /// to the attestation, only that they round-trip through the signature.
    fn sample() -> Reconciliation {
        Reconciliation {
            version: 5,
            result: ReconciliationResult::CannotProve,
            strength: EvidenceStrength::Heuristic,
            reason: ReasonCode::ActionEvidenceUnavailable,
            decision_id: None,
            availability: aip_observe::no_observer(),
            identity: IdentityComparison::NoReference,
            action: ActionComparison::Unobservable,
            temporal: TemporalComparison::Indeterminate,
            lineage: LineageComparison::NotEvaluated,
            wire: WireCorroboration::NotEvaluated,
            replay_detected: false,
            evidence: Vec::new(),
            verification_time_ms: 1_000,
            provenance: Provenance::Engine,
        }
    }

    fn signer_and_anchors() -> (ReconcilerSigner, ReconcilerTrustAnchors) {
        let kp = generate_ed25519_keypair();
        let signer = ReconcilerSigner::new(RID, KV, &kp.private_key, &kp.public_key).unwrap();
        let anchors = ReconcilerTrustAnchors::new().trust(RID, KV, &kp.public_key);
        (signer, anchors)
    }

    #[test]
    fn a_signed_verdict_verifies_against_the_reconciler_anchor() {
        let (signer, anchors) = signer_and_anchors();
        let signed = signer.sign(&sample()).unwrap();
        assert_eq!(signed.verify(&anchors), Ok(()));
        // Signing does not strengthen: a CannotProve stays CannotProve.
        assert_eq!(
            signed.reconciliation().result,
            ReconciliationResult::CannotProve
        );
    }

    #[test]
    fn a_mutated_verdict_no_longer_verifies() {
        let (signer, anchors) = signer_and_anchors();
        let mut signed = signer.sign(&sample()).unwrap();
        // Flip the verdict to the strongest ghost signal after signing.
        signed.reconciliation.result = ReconciliationResult::UnattributedEffect;
        assert_eq!(
            signed.verify(&anchors),
            Err(ReconciliationAttestationError::PayloadHashMismatch)
        );
    }

    #[test]
    fn a_swapped_reconciler_id_is_refused() {
        let (signer, anchors) = signer_and_anchors();
        let mut signed = signer.sign(&sample()).unwrap();
        signed.reconciler_id = "someone.else".into();
        // Not in the anchor set → untrusted (and, were it trusted, the signer_id
        // in the envelope would still not match).
        assert!(matches!(
            signed.verify(&anchors),
            Err(ReconciliationAttestationError::UntrustedReconciler { .. })
        ));
    }

    #[test]
    fn an_untrusted_key_version_is_refused() {
        let (signer, anchors) = signer_and_anchors();
        let mut signed = signer.sign(&sample()).unwrap();
        signed.key_version = 999;
        assert!(matches!(
            signed.verify(&anchors),
            Err(ReconciliationAttestationError::UntrustedReconciler { .. })
        ));
    }

    #[test]
    fn a_forger_with_another_key_does_not_verify() {
        let (signer, _anchors) = signer_and_anchors();
        let signed = signer.sign(&sample()).unwrap();
        // Anchors that trust a DIFFERENT key for the same id/version.
        let attacker = generate_ed25519_keypair();
        let hostile = ReconcilerTrustAnchors::new().trust(RID, KV, &attacker.public_key);
        assert_eq!(
            signed.verify(&hostile),
            Err(ReconciliationAttestationError::SignatureInvalid)
        );
    }

    #[test]
    fn a_bare_verdict_signature_is_not_a_valid_attestation() {
        // Domain separation is load-bearing: a signature over the verdict's own
        // canonical bytes (not the attestation preimage) must not verify as a
        // SignedReconciliation, even under the right key.
        let kp = generate_ed25519_keypair();
        let anchors = ReconcilerTrustAnchors::new().trust(RID, KV, &kp.public_key);
        let r = sample();
        let bare = sign_ed25519(&kp.private_key, RID, &r.canonical_bytes()).unwrap();
        let forged = SignedReconciliation {
            version: RECONCILIATION_ATTESTATION_VERSION,
            reconciler_id: RID.into(),
            key_version: KV,
            reconciliation: r,
            attestation: bare,
        };
        assert_eq!(
            forged.verify(&anchors),
            Err(ReconciliationAttestationError::PayloadHashMismatch)
        );
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        let (signer, anchors) = signer_and_anchors();
        let mut signed = signer.sign(&sample()).unwrap();
        signed.version = 2;
        assert_eq!(
            signed.verify(&anchors),
            Err(ReconciliationAttestationError::UnsupportedVersion(2))
        );
    }
}
