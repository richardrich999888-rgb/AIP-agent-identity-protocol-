//! Profile references: commitments to documents defined elsewhere.
//!
//! # Why a reference and not the content
//!
//! Skill 17 is the universal abstraction; the vertical profiles — UAS, UGV,
//! robotics, industrial, critical edge, space, enterprise — arrive later. If
//! the core carried profile *content*, every new vertical would extend a core
//! type, which is the schema fork the architecture rule forbids.
//!
//! A profile is therefore a `(kind, id, digest)` commitment. The core names
//! which profile applied and pins its bytes; it does not know what is in it.
//! Adding a vertical later requires no change here.
//!
//! # What the digest is and is not
//!
//! It is a commitment: it lets a verifier that holds the profile document
//! confirm this record meant *that* document. It is not evidence the profile
//! was followed, enforced, or even read. Nothing in this crate resolves it.

use aip_types::canonical::{put_bytes, put_str, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::SystemError;

/// The profile slots the model defines. Closed: a new slot is a version
/// change, not a string a caller invents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProfileKind {
    /// What the system is permitted to be able to do.
    Capability,
    /// How its intelligence is executed — runtime, container, isolation.
    Execution,
    /// What independent observation is available to it, and of what.
    Observation,
    /// How it communicates, including disconnected operation.
    Communication,
    /// Safety envelope and constraints.
    Safety,
    /// Where and how it is deployed.
    Deployment,
    /// The environment class it operates in. The slot vertical profiles will
    /// occupy; deliberately empty of meaning in Skill 17.
    Environment,
}

impl ProfileKind {
    /// Stable wire code, explicit rather than positional.
    pub fn code(self) -> u8 {
        match self {
            Self::Capability => 0x01,
            Self::Execution => 0x02,
            Self::Observation => 0x03,
            Self::Communication => 0x04,
            Self::Safety => 0x05,
            Self::Deployment => 0x06,
            Self::Environment => 0x07,
        }
    }
}

/// Maximum bytes in a profile id.
const MAX_PROFILE_ID: usize = 128;

/// A commitment to one profile document.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileRef {
    pub kind: ProfileKind,
    id: String,
    /// SHA-256 of the profile document's canonical bytes, as its own
    /// specification defines them.
    pub digest: [u8; 32],
}

impl ProfileRef {
    /// Validate and build. Ids are bounded and printable-ASCII: they are
    /// hashed into signed artifacts, so an unbounded or non-normalised id is
    /// a place for two documents to encode alike.
    pub fn new(kind: ProfileKind, id: &str, digest: [u8; 32]) -> Result<Self, SystemError> {
        if id.is_empty() || id.len() > MAX_PROFILE_ID {
            return Err(SystemError::MalformedProfile {
                reason: "profile id must be 1-128 bytes",
            });
        }
        if !id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'\\' && b != b'"')
        {
            return Err(SystemError::MalformedProfile {
                reason: "profile id must be printable ASCII without quote or backslash",
            });
        }
        Ok(Self {
            kind,
            id: id.to_owned(),
            digest,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Append to a canonical encoding.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.kind.code());
        put_str(buf, &self.id);
        put_bytes(buf, &self.digest);
    }
}
