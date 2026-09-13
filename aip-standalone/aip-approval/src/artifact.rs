//! What was shown to the human, sealed by the surface that showed it.

use aip_crypto::{sha256, sign_ed25519, verify_ed25519};
use aip_types::canonical::*;
use aip_types::{AipError, ScopeAction, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain tag leading the canonical encoding. Distinct from every other tag
/// in the workspace, so an approval signature cannot be presented as an
/// expectation, an observer head, a warrant or an enforcement decision.
pub const APPROVAL_ARTIFACT_DOMAIN: &str = "SYNTRIASS/GHOST/APPROVAL_ARTIFACT/v1";

/// Structure version. A verifier refuses any other value rather than
/// interpreting it.
pub const APPROVAL_ARTIFACT_VERSION: u16 = 1;

/// How the bytes reached the human. Recorded because it bounds what the
/// digest means: a digest over Markdown source is not a digest over what a
/// renderer drew, and a digest over a screenshot is not a digest over text.
///
/// **None of these makes the comparison semantic.** The comparison is over
/// digests; a form that renders differently on two clients is a limitation
/// the surface owns, and this enum exists so the limitation is recorded
/// rather than assumed away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderedForm {
    /// The exact UTF-8 the surface displayed, digested verbatim.
    PlainText,
    /// Markdown source. The rendered output is not what was digested.
    MarkdownSource,
    /// A rendered image of the surface. Digest is over image bytes.
    ScreenCapture,
    /// A structured payload the surface rendered from (JSON, a form model).
    /// The digest is over a canonical serialisation the surface chose.
    StructuredPayload,
}

impl RenderedForm {
    fn code(&self) -> u8 {
        match self {
            RenderedForm::PlainText => 0x01,
            RenderedForm::MarkdownSource => 0x02,
            RenderedForm::ScreenCapture => 0x03,
            RenderedForm::StructuredPayload => 0x04,
        }
    }
}

/// The surface's statement of what it put in front of a human, and what that
/// human approved.
///
/// Signed by the **approval surface** — the console, the chat client, the
/// ticketing system. Not by the agent, and not by the decision point. That
/// separation is the whole mechanism: an agent that could sign this could
/// manufacture agreement with whatever it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalArtifact {
    pub version: u16,
    /// The surface that rendered and signed. A verifier maps it to an anchor.
    pub surface_id: String,
    /// The decision this approval is for. Joins to
    /// `ExpectedExecution.decision_id`.
    pub decision_id: [u8; 16],
    /// `SHA-256(ExpectedExecution::signing_preimage())` as the surface
    /// understood it. Binds the approval to one exact expectation, so an
    /// artifact cannot be moved onto a different one that happens to share a
    /// decision id.
    pub expectation_digest: [u8; 32],
    /// Digest of exactly the bytes shown, in the form named below.
    pub shown_digest: [u8; 32],
    pub shown_form: RenderedForm,
    /// The action kind as the surface described it to the human.
    pub shown_action: ScopeAction,
    /// Digest of the parameters as shown, computed with the same
    /// `ActionParameters::digest` construction the decision point uses — so
    /// the two are comparable at all.
    pub shown_parameter_digest: [u8; 32],
    /// An opaque reference to the approving human, chosen by the surface.
    /// **Nothing here authenticates a person**; it is a forensic handle.
    pub approver_ref: String,
    /// The surface's clock. Carried for forensics; the comparison never uses
    /// it, because a divergence is arithmetic and needs no ordering.
    pub approved_at_ms: u64,
}

impl ApprovalArtifact {
    /// The exact bytes the signature covers. Prefix-free: every variable
    /// field is length-prefixed, every enum a fixed code.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, APPROVAL_ARTIFACT_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.surface_id);
        buf.extend_from_slice(&self.decision_id);
        buf.extend_from_slice(&self.expectation_digest);
        buf.extend_from_slice(&self.shown_digest);
        put_u8(&mut buf, self.shown_form.code());
        encode_scope_action(&mut buf, &self.shown_action);
        buf.extend_from_slice(&self.shown_parameter_digest);
        put_str(&mut buf, &self.approver_ref);
        put_u64(&mut buf, self.approved_at_ms);
        buf
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

/// An artifact plus the surface's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApprovalArtifact {
    pub artifact: ApprovalArtifact,
    pub attestation: Signature,
}

impl SignedApprovalArtifact {
    /// Sign with the surface's key. `signer_id` is the surface, so an
    /// artifact signed for someone else is refused at the source.
    pub fn sign(artifact: ApprovalArtifact, surface_private_key: &[u8]) -> Result<Self, AipError> {
        let attestation = sign_ed25519(
            surface_private_key,
            &artifact.surface_id,
            &artifact.canonical_bytes(),
        )?;
        Ok(Self {
            artifact,
            attestation,
        })
    }
}

/// The verifier's trust decision: which approval surfaces, under which keys.
/// Supplied by the verifier — never by the artifact.
#[derive(Debug, Clone, Default)]
pub struct ApprovalSurfaceAnchors {
    keys: BTreeMap<String, Vec<u8>>,
}

impl ApprovalSurfaceAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, surface_id: &str, public_key: &[u8]) -> Self {
        self.keys
            .insert(surface_id.to_string(), public_key.to_vec());
        self
    }

    pub fn get(&self, surface_id: &str) -> Option<&[u8]> {
        self.keys.get(surface_id).map(|k| k.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    UnsupportedVersion(u16),
    /// The surface is not anchored. Not "unknown surface": the verifier has
    /// no opinion about surfaces it was not provisioned for.
    SurfaceNotAnchored(String),
    /// `attestation.signer_id` is not the artifact's `surface_id`.
    SignerIsNotSurface,
    /// The anchored key for this surface is the agent's own key: the agent
    /// holds the surface key, so the artifact is the agent's self-report
    /// wearing a different name.
    SurfaceKeyIsAgentKey,
    PayloadHashMismatch,
    SignatureInvalid,
    Crypto(AipError),
}

/// An artifact that verified against the verifier's own anchors.
///
/// The field is private and there is no constructor: the only way to obtain
/// one is [`verify_artifact`], so a comparison cannot be handed an artifact
/// nobody checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApprovalArtifact(ApprovalArtifact);

impl VerifiedApprovalArtifact {
    pub fn artifact(&self) -> &ApprovalArtifact {
        &self.0
    }
}

/// Verify an artifact against `anchors`. The verifier's anchors win: an
/// artifact cannot name the key it is judged against.
///
/// `agent_public_key` is the key of the agent the decision concerns, when the
/// verifier knows it. If the surface anchor *is* that key, the artifact is
/// refused — the same refusal `verify_expected_execution_for_agent` makes for
/// a decision point, and for the same reason.
pub fn verify_artifact(
    signed: &SignedApprovalArtifact,
    anchors: &ApprovalSurfaceAnchors,
    agent_public_key: Option<&[u8]>,
) -> Result<VerifiedApprovalArtifact, ArtifactError> {
    let a = &signed.artifact;
    if a.version != APPROVAL_ARTIFACT_VERSION {
        return Err(ArtifactError::UnsupportedVersion(a.version));
    }
    let key = anchors
        .get(&a.surface_id)
        .ok_or_else(|| ArtifactError::SurfaceNotAnchored(a.surface_id.clone()))?;
    if let Some(agent_key) = agent_public_key {
        if key == agent_key {
            return Err(ArtifactError::SurfaceKeyIsAgentKey);
        }
    }
    if signed.attestation.signer_id != a.surface_id {
        return Err(ArtifactError::SignerIsNotSurface);
    }
    if signed.attestation.payload_hash != a.digest() {
        return Err(ArtifactError::PayloadHashMismatch);
    }
    match verify_ed25519(key, &signed.attestation) {
        Ok(true) => Ok(VerifiedApprovalArtifact(a.clone())),
        Ok(false) => Err(ArtifactError::SignatureInvalid),
        Err(e) => Err(ArtifactError::Crypto(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_types::Action;

    fn artifact() -> ApprovalArtifact {
        ApprovalArtifact {
            version: APPROVAL_ARTIFACT_VERSION,
            surface_id: "surface:console-1".into(),
            decision_id: [3u8; 16],
            expectation_digest: [4u8; 32],
            shown_digest: [5u8; 32],
            shown_form: RenderedForm::PlainText,
            shown_action: ScopeAction::Standard(Action::Read),
            shown_parameter_digest: [6u8; 32],
            approver_ref: "operator-7".into(),
            approved_at_ms: 1_000,
        }
    }

    #[test]
    fn canonical_bytes_lead_with_the_domain_tag() {
        let bytes = artifact().canonical_bytes();
        let tag = APPROVAL_ARTIFACT_DOMAIN.as_bytes();
        assert_eq!(&bytes[4..4 + tag.len()], tag);
    }

    #[test]
    fn every_field_is_inside_the_preimage() {
        let base = artifact();
        let mut variants = vec![base.clone()];
        variants.push({
            let mut a = base.clone();
            a.surface_id.push('x');
            a
        });
        variants.push({
            let mut a = base.clone();
            a.decision_id[0] ^= 1;
            a
        });
        variants.push({
            let mut a = base.clone();
            a.expectation_digest[0] ^= 1;
            a
        });
        variants.push({
            let mut a = base.clone();
            a.shown_digest[0] ^= 1;
            a
        });
        variants.push({
            let mut a = base.clone();
            a.shown_form = RenderedForm::ScreenCapture;
            a
        });
        variants.push({
            let mut a = base.clone();
            a.shown_action = ScopeAction::Standard(Action::Write);
            a
        });
        variants.push({
            let mut a = base.clone();
            a.shown_parameter_digest[0] ^= 1;
            a
        });
        variants.push({
            let mut a = base.clone();
            a.approver_ref.push('x');
            a
        });
        variants.push({
            let mut a = base.clone();
            a.approved_at_ms += 1;
            a
        });
        let digests: std::collections::BTreeSet<[u8; 32]> =
            variants.iter().map(|a| a.digest()).collect();
        assert_eq!(
            digests.len(),
            variants.len(),
            "a field mutation left the digest unchanged"
        );
    }

    #[test]
    fn the_preimage_is_injective_across_adjacent_string_fields() {
        let mut a = artifact();
        a.surface_id = "ab".into();
        a.approver_ref = "c".into();
        let mut b = a.clone();
        b.surface_id = "a".into();
        b.approver_ref = "bc".into();
        assert_ne!(a.digest(), b.digest());
    }
}
