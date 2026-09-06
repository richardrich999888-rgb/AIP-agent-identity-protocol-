//! AIRI's own error type.
//!
//! `aip_types::AipError` is a fieldless enum with fixed wire discriminants;
//! adding AIRI's failure modes to it would change that wire surface for
//! every existing consumer. AIRI therefore carries its own error, which can
//! also say *which* field failed — a verifier that reports only
//! "SignatureInvalid" makes an operator guess.

/// Why an AIRI event, chain, or corroboration was refused.
///
/// Every variant is a refusal. There is no variant that means "accepted
/// with reservations": a caller either gets a verified value or an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiriError {
    /// The event declares a structure version this build does not implement.
    /// Refused rather than interpreted: fields may have moved.
    UnsupportedVersion(u16),
    /// The signature does not cover these bytes, or the key does not match.
    SignatureInvalid,
    /// `signature.payload_hash` is not the hash of the recomputed preimage —
    /// the event was altered after signing.
    PayloadHashMismatch,
    /// The public key is not a well-formed Ed25519 key.
    InvalidPublicKey,
    /// `signature.signer_id` is not the event's `agent_id`. An agent may
    /// only sign for itself.
    SignerIsNotTheAgent { signer_id: String, agent_id: String },
    /// A required field was empty.
    MissingField(&'static str),
    /// A field exceeded the bound in the specification.
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    /// A chain defect; see [`crate::ChainDefect`].
    Chain(crate::ChainDefect),
}

impl std::fmt::Display for AiriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "AIRI event version {v} is not implemented by this verifier"
                )
            }
            Self::SignatureInvalid => write!(f, "AIRI event signature did not verify"),
            Self::PayloadHashMismatch => {
                write!(
                    f,
                    "AIRI event was altered after signing (payload hash mismatch)"
                )
            }
            Self::InvalidPublicKey => write!(f, "not a well-formed Ed25519 public key"),
            Self::SignerIsNotTheAgent {
                signer_id,
                agent_id,
            } => write!(
                f,
                "event is signed by {signer_id} but claims to be about {agent_id}"
            ),
            Self::MissingField(x) => write!(f, "required AIRI field `{x}` is empty"),
            Self::FieldTooLong { field, len, max } => {
                write!(f, "AIRI field `{field}` is {len} bytes, limit {max}")
            }
            Self::Chain(d) => write!(f, "AIRI chain defect: {d:?}"),
        }
    }
}

impl std::error::Error for AiriError {}

impl From<crate::ChainDefect> for AiriError {
    fn from(d: crate::ChainDefect) -> Self {
        Self::Chain(d)
    }
}
