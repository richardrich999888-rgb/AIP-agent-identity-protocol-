//! Documents, principals and classification.
//!
//! Classification is a total order; a principal may read a document only
//! within its own tenant and at or below its clearance. The order is encoded
//! as an integer rank so the storage adapter can enforce it inside SQL.

use serde::{Deserialize, Serialize};

/// Maximum identifier length accepted from any external source.
pub const MAX_ID_LEN: usize = 128;
/// Maximum document body accepted for ingestion (bytes). Bounds memory and
/// prompt size in a resource-constrained deployment.
pub const MAX_BODY_LEN: usize = 1 << 20;

/// Sensitivity label. Ordered: `Public < Internal < Restricted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Classification {
    Public,
    Internal,
    Restricted,
}

impl Classification {
    /// Integer rank used by the storage layer's SQL filter.
    pub fn rank(self) -> i64 {
        match self {
            Classification::Public => 0,
            Classification::Internal => 1,
            Classification::Restricted => 2,
        }
    }

    /// Parse the CLI/manifest spelling. Unknown labels are an error, never a
    /// default: an unlabelled document must not silently become `Public`.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "public" => Ok(Classification::Public),
            "internal" => Ok(Classification::Internal),
            "restricted" => Ok(Classification::Restricted),
            other => Err(DomainError::UnknownClassification(other.to_string())),
        }
    }
}

/// Validated tenant or document identifier: 1..=128 bytes of
/// `[A-Za-z0-9._-]`. Restricting the alphabet keeps identifiers safe to
/// embed in prompts, filenames and citation markers without escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ident(String);

impl Ident {
    /// Validate and wrap an identifier.
    pub fn new(s: &str) -> Result<Self, DomainError> {
        let ok_len = !s.is_empty() && s.len() <= MAX_ID_LEN;
        let ok_chars = s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
        if ok_len && ok_chars {
            Ok(Ident(s.to_string()))
        } else {
            Err(DomainError::InvalidIdent(
                s.chars().take(MAX_ID_LEN).collect(),
            ))
        }
    }

    /// Borrow the identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A document as ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub tenant: Ident,
    pub doc_id: Ident,
    pub title: String,
    pub classification: Classification,
    pub body: String,
}

impl Document {
    /// Validate size limits. Called by every ingestion path.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.body.len() > MAX_BODY_LEN {
            return Err(DomainError::BodyTooLarge(self.body.len()));
        }
        if self.title.len() > 512 {
            return Err(DomainError::TitleTooLarge(self.title.len()));
        }
        Ok(())
    }
}

/// The party a retrieval is performed for. Constructed by the
/// authentication layer, never from model output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub tenant: Ident,
    pub clearance: Classification,
}

/// A retrieved passage, already filtered for the principal.
#[derive(Debug, Clone, PartialEq)]
pub struct Passage {
    pub doc_id: Ident,
    pub title: String,
    pub classification: Classification,
    pub text: String,
    /// SQLite FTS5 bm25 score; lower is better. Context only.
    pub bm25: f64,
}

/// Domain validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidIdent(String),
    UnknownClassification(String),
    BodyTooLarge(usize),
    TitleTooLarge(usize),
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_order_is_total_and_ranked() {
        assert!(Classification::Public < Classification::Internal);
        assert!(Classification::Internal < Classification::Restricted);
        assert_eq!(Classification::Restricted.rank(), 2);
    }

    #[test]
    fn unknown_classification_is_refused_not_defaulted() {
        assert!(Classification::parse("secret").is_err());
        assert!(Classification::parse("").is_err());
        assert_eq!(
            Classification::parse("internal"),
            Ok(Classification::Internal)
        );
    }

    #[test]
    fn ident_rejects_injection_characters() {
        assert!(Ident::new("doc-01.v2_a").is_ok());
        for bad in ["", "a b", "a]b", "../x", "a\nb", &"x".repeat(129)] {
            assert!(Ident::new(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn oversized_body_rejected() {
        let d = Document {
            tenant: Ident::new("t").unwrap(),
            doc_id: Ident::new("d").unwrap(),
            title: "t".into(),
            classification: Classification::Public,
            body: "x".repeat(MAX_BODY_LEN + 1),
        };
        assert_eq!(
            d.validate(),
            Err(DomainError::BodyTooLarge(MAX_BODY_LEN + 1))
        );
    }
}
