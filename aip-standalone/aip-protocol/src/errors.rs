//! Error types for the AIP v4 accountability layer.

pub type AipResult<T> = Result<T, AipError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AipError {
    InvalidMagic {
        expected: &'static str,
        got: [u8; 4],
    },
    InvalidPrivateKey,
    InvalidPublicKey,
    SignatureInvalid,
    EncodingError {
        reason: String,
    },
    ValidationFailed {
        reason: String,
    },
}

impl std::fmt::Display for AipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic { expected, got } => {
                write!(f, "invalid magic: expected {expected}, got {got:02X?}")
            }
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::SignatureInvalid => write!(f, "signature invalid"),
            Self::EncodingError { reason } => write!(f, "encoding error: {reason}"),
            Self::ValidationFailed { reason } => write!(f, "validation failed: {reason}"),
        }
    }
}

impl std::error::Error for AipError {}
