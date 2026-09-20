//! One error type, every variant named after what an operator would need
//! to know to fix it.

use std::fmt;

#[derive(Debug)]
pub enum HsmError {
    /// The module could not be loaded or initialised. Usually the path.
    Module { path: String, detail: String },
    /// No token with the requested label is present in any slot.
    TokenNotFound { label: String, present: Vec<String> },
    /// The module rejected the PIN, or the login itself.
    Login(String),
    /// The PIN could not be read from where it was said to be.
    Pin(String),
    /// No key object with the requested label of the requested type.
    KeyNotFound { label: String },
    /// More than one key object under the label. Not resolved by guessing.
    AmbiguousKey { label: String, count: usize },
    /// The key's policy would allow it to leave the module.
    KeyPolicy { label: String, detail: String },
    /// The public object under the label does not verify what the private
    /// object signs. A mislabelled or replaced public half.
    KeyPairMismatch { label: String },
    /// `CKA_EC_POINT` was not an Ed25519 public key in a form this crate
    /// recognises.
    EcPoint(String),
    /// A PKCS#11 call failed. The function and return code are carried
    /// verbatim so the vendor's documentation can be consulted.
    Pkcs11 { function: String, detail: String },
    /// The mutex around the session was poisoned by a panic on another
    /// thread. Refusing to sign is the correct response: the session's
    /// state is unknown.
    SessionPoisoned,
    /// The module returned a signature of the wrong length.
    SignatureLength(usize),
    /// A configuration field was empty or otherwise unusable.
    Config(String),
}

impl fmt::Display for HsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Module { path, detail } => {
                write!(f, "PKCS#11 module `{path}` could not be loaded: {detail}")
            }
            Self::TokenNotFound { label, present } => write!(
                f,
                "no token labelled `{label}`; tokens present: {present:?}"
            ),
            Self::Login(d) => write!(f, "login to the token was refused: {d}"),
            Self::Pin(d) => write!(f, "the PIN could not be read: {d}"),
            Self::KeyNotFound { label } => {
                write!(f, "no Ed25519 private key labelled `{label}` on the token")
            }
            Self::AmbiguousKey { label, count } => write!(
                f,
                "{count} Ed25519 private keys are labelled `{label}`; refusing to guess which \
                 one is meant"
            ),
            Self::KeyPolicy { label, detail } => write!(
                f,
                "the key labelled `{label}` has a policy that would let it leave the module \
                 ({detail}); refusing to use it, because a key that can be exported makes the \
                 module a slow file"
            ),
            Self::KeyPairMismatch { label } => write!(
                f,
                "the public key labelled `{label}` does not verify a signature made by the \
                 private key labelled `{label}`; the pair is not a pair"
            ),
            Self::EcPoint(d) => write!(f, "CKA_EC_POINT is not an Ed25519 public key: {d}"),
            Self::Pkcs11 { function, detail } => write!(f, "{function} failed: {detail}"),
            Self::SessionPoisoned => write!(
                f,
                "the PKCS#11 session lock was poisoned by a panic elsewhere; refusing to sign \
                 on a session whose state is unknown"
            ),
            Self::SignatureLength(n) => {
                write!(f, "the module returned a {n}-byte signature; Ed25519 is 64")
            }
            Self::Config(d) => write!(f, "configuration: {d}"),
        }
    }
}

impl std::error::Error for HsmError {}

impl HsmError {
    /// Wrap a cryptoki error with the name of the call that failed.
    pub(crate) fn from_cryptoki(function: &'static str, e: cryptoki::error::Error) -> Self {
        Self::Pkcs11 {
            function: function.to_string(),
            detail: e.to_string(),
        }
    }
}
