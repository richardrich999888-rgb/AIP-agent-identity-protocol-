//! `ObservedBoot` — a host-boot identity that came from verified observation.
//!
//! # The defect this type closes
//!
//! An earlier draft of this crate took the observed boot id as a bare
//! `Option<[u8; 16]>`. Nothing in the signature or its documentation required
//! those bytes to have come from an anchored observer, so a caller could pass
//! the boot id out of the agent's own **self-reported** `ExecutionBinding` and
//! receive a `Bound` disposition.
//!
//! That is exactly the failure this skill exists to prevent — a self-reported
//! platform identity silently establishing an authoritative binding — and it
//! was prevented only by caller discipline, which is not prevention.
//!
//! # The fix
//!
//! The boot id is now a newtype with a private field, and the only
//! constructors verify an [`AttestedBatch`] against the verifier's own
//! [`ObserverTrustAnchors`] before extracting anything from it. There is no
//! `from_bytes`, no `new`, and no `From<[u8; 16]>`. A caller holding
//! self-reported bytes has nothing to call.
//!
//! This is the same discipline `aip-reconcile` uses for `ActionComparison`'s
//! positive variants and Skill 18 uses for `EffectDisposition::Confirmed`: put
//! the invariant in the type system, where forgetting it is a compile error
//! rather than a review miss.
//!
//! # What it still does not establish
//!
//! That the observer is honest about which host it watches, or that the
//! verifier's registry is correct. Both are verifier trust decisions, in the
//! same class as anchoring an issuer key. This type raises the floor from
//! "any bytes" to "bytes an anchored observer signed"; it does not make the
//! anchoring itself self-proving, and nothing can.

use aip_observe::{verify_attested_batch, AttestedBatch, ObserverTrustAnchors, VerifyError};
use serde::{Deserialize, Serialize};

/// A host-boot identity extracted from an attested, verified observation.
///
/// Serialisable so a resolved binding can travel, but **not deserialisable
/// into a trusted value by construction**: see the `serde` note on the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObservedBoot {
    /// The measured `boot_id`.
    ///
    /// Private, so the only route in is a constructor below. Serde can still
    /// reconstruct one from a serialized binding — which is correct, because a
    /// *recorded* binding is a record of a past verification, not a new claim.
    /// A verifier re-deriving trust from a transported record must re-verify
    /// the underlying batch, exactly as it must re-verify any other evidence.
    boot_id: [u8; 16],
}

impl ObservedBoot {
    /// The boot id an anchored observer measured for `execution`'s process.
    ///
    /// Verifies `batch` against `anchors` first. Returns `Ok(None)` when the
    /// batch verifies but contains no observation of a process — a verified
    /// batch that saw nothing is not an error, it is an absence, and the two
    /// must not be conflated.
    ///
    /// The `Err` case is a batch that did not verify: an untrusted observer, a
    /// wrong key version, a bad signature, an unsupported version. **A failed
    /// verification yields no boot id at all**, so a caller cannot proceed
    /// with a value it did not earn.
    pub fn from_attested(
        batch: &AttestedBatch,
        anchors: &ObserverTrustAnchors,
    ) -> Result<Option<Self>, VerifyError> {
        verify_attested_batch(batch, anchors)?;
        Ok(batch.batch.observations.first().map(|o| Self {
            boot_id: o.observed.process.boot_id,
        }))
    }

    /// As [`ObservedBoot::from_attested`], for the observation at `index`.
    ///
    /// Useful when a batch carries several observations and the caller has
    /// already selected one — typically the one the reconciler matched.
    pub fn from_attested_at(
        batch: &AttestedBatch,
        anchors: &ObserverTrustAnchors,
        index: usize,
    ) -> Result<Option<Self>, VerifyError> {
        verify_attested_batch(batch, anchors)?;
        Ok(batch.batch.observations.get(index).map(|o| Self {
            boot_id: o.observed.process.boot_id,
        }))
    }

    /// The measured boot id.
    pub fn boot_id(&self) -> &[u8; 16] {
        &self.boot_id
    }
}
