//! Layer 1 — RAW. What the external tool actually emitted, unmodified.
//!
//! # Why three layers and not one
//!
//! The requirement is that RAW, NORMALIZED and CLASSIFICATION stay separate. It
//! is not tidiness. An adapter that normalised in place would leave nobody able
//! to check the normalisation, and an adapter that classified during parsing
//! would let a parsing bug become an evidence-class promotion.
//!
//! So: [`RawCapture`] holds bytes and a digest of them and offers no way to
//! change either. `normalize` reads it and produces a separate value.
//! `classify` reads *that* and produces a third. Each layer can be checked
//! against the one below it, and the run's stored artefact is the raw bytes.

use serde::{Deserialize, Serialize};

/// Bytes as the external tool produced them, with a digest taken at capture.
///
/// There is no setter, no `bytes_mut`, and no way to rebuild one with different
/// content and the same digest: `new` is the only constructor and it computes
/// the digest itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCapture {
    /// The tool that produced these bytes, as the deployment names it.
    tool: String,
    /// What the tool version reported about itself, when it reports one.
    tool_version: Option<String>,
    /// Capture time on the collector's clock, milliseconds.
    captured_at_ms: u64,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl RawCapture {
    pub fn new(
        tool: &str,
        tool_version: Option<&str>,
        captured_at_ms: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, CaptureError> {
        if tool.is_empty() || tool.len() > 128 {
            return Err(CaptureError::Malformed {
                reason: "tool name must be 1-128 bytes",
            });
        }
        if bytes.is_empty() {
            return Err(CaptureError::Malformed {
                reason: "an empty capture is not a capture",
            });
        }
        let digest = aip_crypto::sha256(&bytes);
        Ok(Self {
            tool: tool.to_owned(),
            tool_version: tool_version.map(str::to_owned),
            captured_at_ms,
            bytes,
            digest,
        })
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }
    pub fn tool_version(&self) -> Option<&str> {
        self.tool_version.as_deref()
    }
    pub fn captured_at_ms(&self) -> u64 {
        self.captured_at_ms
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Whether the held bytes still hash to the digest taken at capture.
    ///
    /// Cannot fail through this API — the fields are private and there is no
    /// mutator. It exists so a caller that deserialised a `RawCapture` from a
    /// trace file can check the file was not edited, which is the case that
    /// matters.
    pub fn integrity_holds(&self) -> bool {
        aip_crypto::sha256(&self.bytes) == self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    Malformed { reason: &'static str },
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for CaptureError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capture_hashes_what_it_holds() {
        let c = RawCapture::new("apriltag", Some("3.4.5"), 1_000, b"payload".to_vec()).unwrap();
        assert!(c.integrity_holds());
        assert_eq!(c.digest(), aip_crypto::sha256(b"payload"));
        assert_eq!(c.bytes(), b"payload");
    }

    #[test]
    fn two_captures_of_different_bytes_have_different_digests() {
        let a = RawCapture::new("t", None, 1, b"a".to_vec()).unwrap();
        let b = RawCapture::new("t", None, 1, b"b".to_vec()).unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn an_edited_trace_file_fails_its_own_integrity_check() {
        // The case the digest exists for: a capture round-tripped through a
        // file someone then edited.
        let c = RawCapture::new("t", None, 1, b"original".to_vec()).unwrap();
        let mut json: serde_json::Value = serde_json::to_value(&c).unwrap();
        json["bytes"] = serde_json::to_value(b"tampered!".to_vec()).unwrap();
        let edited: RawCapture = serde_json::from_value(json).unwrap();
        assert!(
            !edited.integrity_holds(),
            "an edited capture must not pass its own integrity check"
        );
    }

    #[test]
    fn malformed_captures_are_refused() {
        assert!(RawCapture::new("", None, 1, b"x".to_vec()).is_err());
        assert!(RawCapture::new("t", None, 1, vec![]).is_err());
        assert!(RawCapture::new(&"x".repeat(129), None, 1, b"x".to_vec()).is_err());
    }
}
