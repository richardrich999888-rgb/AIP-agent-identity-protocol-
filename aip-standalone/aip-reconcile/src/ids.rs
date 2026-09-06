//! Identifier newtypes at the reconciliation boundary.
//!
//! Every producer upstream uses `[u8; 16]` for several unrelated identifiers
//! — `decision_id`, `batch_id`, `probe_run_id`, `packet_id`, `jti`, nonces.
//! Inside this crate they must not be confusable, so each one that
//! reconciliation reasons about gets its own type. Construction is explicit
//! (`from_bytes`); there is no `From<[u8; 16]>` and no `Deref` to the array,
//! so a `batch_id` cannot be handed to a function expecting a `DecisionId`
//! without the caller writing the conversion out.

use serde::{Deserialize, Serialize};

macro_rules! bytes16_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(b: [u8; 16]) -> Self {
                Self(b)
            }
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for b in &self.0 {
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }
        }
    };
}

bytes16_id! {
    /// The decision-point-issued correlation key. Equals `DecisionRecord.decision_id`
    /// in the agent's packet and `ExpectedExecution.decision_id`; an
    /// observation's `claimed_decision_id` is the **claimed** counterpart.
    DecisionId
}

bytes16_id! {
    /// A probe-chosen batch identifier. Never a correlation key.
    BatchId
}

bytes16_id! {
    /// A probe run epoch. Never a correlation key.
    ProbeRunId
}

/// Position in one observer's attested chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObserverSequence(pub u64);

/// Identifier of an observer (collector) as anchored by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObserverId(pub String);

/// Identifier of a decision point as anchored by the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecisionPointId(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_distinct_types_with_explicit_construction() {
        let raw = [7u8; 16];
        let d = DecisionId::from_bytes(raw);
        let b = BatchId::from_bytes(raw);
        // Same bytes, different types: the compiler refuses `d == b`. What we
        // can check at runtime is that both round-trip their own bytes.
        assert_eq!(d.as_bytes(), &raw);
        assert_eq!(b.as_bytes(), &raw);
        assert!(format!("{d:?}").starts_with("DecisionId("));
        assert!(format!("{b:?}").starts_with("BatchId("));
    }
}
