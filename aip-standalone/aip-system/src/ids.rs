//! The four identifiers this model adds, and the one shared shape behind them.
//!
//! # Why four distinct types and not four `String`s
//!
//! The whole point of this crate is that these identities do not collapse. A
//! `String` platform id and a `String` hardware id are the same type, so
//! nothing stops one being passed where the other belongs — the compiler
//! cannot see the difference, a reviewer has to, and eventually a reviewer
//! does not. Distinct newtypes make the substitution a compile error rather
//! than an incident.
//!
//! There is deliberately **no** conversion between them: no `From`, no
//! `as_platform()`, no shared constructor taking a kind parameter. The only
//! way to obtain a `HardwareId` is to parse one.
//!
//! # The shape
//!
//! `namespace:value` — because these identities come from many sources and a
//! bare opaque string loses which. A TPM endorsement key, a DMI system UUID, a
//! manufacturer serial and an operator-assigned tail number are all hardware
//! or platform identities, and a verifier comparing two of them must know it
//! is comparing like with like.
//!
//! Both halves are constrained: non-empty, bounded, and drawn from a
//! restricted ASCII set. That is not cosmetic. These strings end up in
//! canonical byte encodings that are hashed and embedded in signed artifacts;
//! an unbounded or unnormalised identifier is a place for two different
//! values to encode identically, or for one value to encode two ways.

use std::fmt;

use crate::error::SystemError;

/// Maximum bytes in a namespace or a value. Generous for real identifiers
/// (a TPM EK hash in hex is 64) and small enough that a canonical encoding
/// stays bounded.
const MAX_PART: usize = 96;

/// Characters permitted in either half.
///
/// Alphanumerics plus `-` `_` `.` `~` `+`. No `:` (it is the separator), no
/// whitespace, no case folding, no Unicode. Byte-for-byte comparison is then
/// the same as semantic comparison, which is what an injective encoding
/// requires — two identifiers that differ only by normalisation would
/// otherwise hash differently while meaning the same thing, or the reverse.
fn part_is_permitted(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= MAX_PART
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+'))
}

/// The validated `namespace:value` shape shared by the four identifiers.
///
/// Private field: a caller cannot construct one without passing validation,
/// and cannot mutate one afterwards into something that would not have passed.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct NamespacedId {
    text: String,
    /// Byte index of the `:`. Stored so accessors need no rescan.
    sep: usize,
}

impl NamespacedId {
    fn parse(kind: &'static str, s: &str) -> Result<Self, SystemError> {
        let malformed = |reason| SystemError::MalformedId { kind, reason };
        // `split_once` rather than `split(':')`: exactly one separator, so a
        // value containing a colon cannot be read as a different namespace.
        let (ns, value) = s
            .split_once(':')
            .ok_or_else(|| malformed("expected the form namespace:value"))?;
        if !part_is_permitted(ns) {
            return Err(malformed(
                "namespace must be 1-96 chars of [A-Za-z0-9-_.~+]",
            ));
        }
        if !part_is_permitted(value) {
            return Err(malformed("value must be 1-96 chars of [A-Za-z0-9-_.~+]"));
        }
        Ok(Self {
            sep: ns.len(),
            text: s.to_owned(),
        })
    }

    /// Where this identifier came from — `tpm-ek`, `dmi-uuid`, `tail-number`,
    /// `operator`, and so on. A verifier comparing two identifiers must
    /// compare namespaces too, or it is comparing unlike things.
    pub fn namespace(&self) -> &str {
        &self.text[..self.sep]
    }

    /// The identifier within its namespace.
    pub fn value(&self) -> &str {
        &self.text[self.sep + 1..]
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for NamespacedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<NamespacedId> for String {
    fn from(v: NamespacedId) -> String {
        v.text
    }
}

impl TryFrom<String> for NamespacedId {
    type Error = SystemError;
    fn try_from(s: String) -> Result<Self, SystemError> {
        // Deserialization goes through the same validation as construction.
        // Without this, `serde_json::from_str` would be a way to build an
        // identifier the constructor would have refused.
        Self::parse("id", &s)
    }
}

/// Declare one identifier newtype. Each gets its own constructor and no
/// conversion to any sibling.
macro_rules! id_type {
    ($name:ident, $kind:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(NamespacedId);

        impl $name {
            /// Parse and validate. The only way to obtain one.
            pub fn parse(s: &str) -> Result<Self, SystemError> {
                NamespacedId::parse($kind, s).map(Self)
            }
            pub fn namespace(&self) -> &str {
                self.0.namespace()
            }
            pub fn value(&self) -> &str {
                self.0.value()
            }
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

id_type!(
    SystemId,
    "system id",
    "The autonomous system as a durable thing in the world.\n\n\
     Persists across agent versions, executions, compute replacement and — \
     for a platform-bearing system — even platform replacement. It is the \
     identity an operator, a regulator or an incident report means by \"that \
     system\".\n\n\
     It is **not** the intelligence (that is an AIP-ID), **not** a run (that \
     is an execution id), and **not** a machine (that is a hardware id)."
);

id_type!(
    PlatformId,
    "platform id",
    "The physical platform: airframe, chassis, hull, cabinet.\n\n\
     Outlives the compute mounted in it. A flight computer swapped in the \
     field leaves the platform identity untouched, which is why this cannot \
     be a hardware id.\n\n\
     `None` is correct and common — an enterprise agent has no platform, and \
     inventing one would make a fact out of nothing."
);

id_type!(
    HardwareId,
    "hardware id",
    "The compute host: the machine executing the intelligence.\n\n\
     Deliberately not `boot_id`, which identifies a *boot*. A host rebooted \
     is the same hardware with a different `boot_id`, and a model that \
     conflated the two would report a hardware change on every restart and \
     miss a real one.\n\n\
     Typical namespaces: `tpm-ek`, `dmi-uuid`, `serial`. This crate does not \
     attest any of them — an identifier here is a claim about hardware, never \
     evidence of it."
);

id_type!(
    MissionId,
    "mission id",
    "The mission or task context an execution served.\n\n\
     Many executions may serve one mission and an execution serves one \
     mission. It carries no authority: a mission is what was being attempted, \
     never permission to attempt it."
);
