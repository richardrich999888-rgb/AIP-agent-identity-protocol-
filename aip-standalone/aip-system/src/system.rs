//! `AutonomousSystem` — the durable descriptor.
//!
//! One system type covers an AI agent, a UAS, a UGV, a robot, an industrial
//! edge node, a spacecraft computer and an enterprise workload. There is no
//! per-vertical variant and no per-vertical field: what differs between them
//! is which profiles apply and whether a platform exists, and both of those
//! are already expressible.
//!
//! # What this type deliberately does not have
//!
//! No `agent_id`. A system that names an intelligence is a system fused to
//! one version of it, and the model's central claim is that the two are
//! separable — the same airframe flies successive autonomy builds, and the
//! same autonomy build flies successive airframes. The agent binding belongs
//! to [`crate::SystemExecution`], where it is true for a bounded interval and
//! can be stated exactly.
//!
//! No key, token, scope or signature. This is a descriptor, not a trust
//! anchor (D17-3). Its integrity comes from its canonical bytes being
//! embedded in something already signed. Adding a signing key here would add
//! a trust anchor, which is a declared STOP condition, and nothing needs one.

use aip_types::canonical::{put_domain, put_opt_str, put_str, put_u16, put_u32, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::SystemError;
use crate::ids::{PlatformId, SystemId};
use crate::lifecycle::LifecycleState;
use crate::profile::ProfileRef;

/// Domain tag leading every `AutonomousSystem` canonical encoding.
pub const AUTONOMOUS_SYSTEM_DOMAIN: &str = "SYNTRIASS/AUTONOMY/SYSTEM/v1";

/// Structure version. Version 1 is the only version this build implements;
/// anything else is refused rather than guessed.
pub const AUTONOMOUS_SYSTEM_VERSION: u16 = 1;

/// What kind of autonomous system this is.
///
/// A coarse deployment category, carried so a reader knows what it is looking
/// at. It is **not** a capability, **not** a permission, and **not** a
/// dispatch key: no code branches on it to decide what a system may do, and
/// the accountability core never sees it at all.
///
/// Closed, with no `Other` escape. A system type this build does not know is
/// a system type whose meaning it does not know, and guessing is worse than
/// refusing (S17-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemType {
    /// Software intelligence with no physical platform.
    SoftwareAgent,
    /// Uncrewed aerial system.
    UncrewedAerial,
    /// Uncrewed ground vehicle.
    UncrewedGround,
    /// Uncrewed surface or subsurface vessel.
    UncrewedMaritime,
    /// Manipulator or mobile robot.
    Robotic,
    /// Industrial control or process automation.
    Industrial,
    /// Critical-infrastructure edge node.
    CriticalEdge,
    /// Orbital or deep-space vehicle or payload.
    Space,
    /// Enterprise workload with organisational, not physical, consequence.
    Enterprise,
}

impl SystemType {
    /// Stable wire code, assigned explicitly. Reordering the variants must
    /// not change what already-encoded bytes mean.
    pub fn code(self) -> u8 {
        match self {
            Self::SoftwareAgent => 0x01,
            Self::UncrewedAerial => 0x02,
            Self::UncrewedGround => 0x03,
            Self::UncrewedMaritime => 0x04,
            Self::Robotic => 0x05,
            Self::Industrial => 0x06,
            Self::CriticalEdge => 0x07,
            Self::Space => 0x08,
            Self::Enterprise => 0x09,
        }
    }
}

/// The durable description of one autonomous system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomousSystem {
    pub version: u16,
    pub system_id: SystemId,
    pub system_type: SystemType,
    /// The platform this system is **registered** as, when it has one.
    ///
    /// `None` for a software agent, and `None` is a fact rather than a gap:
    /// inventing a platform identity for something with no platform would
    /// make a claim out of nothing.
    ///
    /// Deliberately distinct from [`crate::SystemExecution::platform_id`],
    /// which is where an execution actually ran. The two disagreeing is
    /// representable on purpose (D17-2) — noticing it is reconciliation's
    /// job, and this layer must not pre-empt it by having only one field.
    pub platform: Option<PlatformId>,
    /// Free-form operator label. Never an identifier, never compared, never
    /// trusted; it is here so a human reading a record knows what they are
    /// looking at.
    pub display_name: Option<String>,
    /// Commitments to the profiles that apply. Order-independent in meaning,
    /// but sorted before encoding so the bytes are deterministic.
    pub profiles: Vec<ProfileRef>,
    /// Where the system is in its life. A record, never a gate — see
    /// [`crate::LifecycleState`].
    pub lifecycle_state: LifecycleState,
    /// Unix ms this description was written. Context only; not a validity
    /// window. Temporal validity belongs to tokens.
    pub described_at_ms: u64,
}

impl AutonomousSystem {
    /// Build a description at the current structure version.
    ///
    /// Constructing one grants nothing (S17-4). There is no field it could
    /// grant anything through, and no code in this crate reads one to decide
    /// anything.
    pub fn new(
        system_id: SystemId,
        system_type: SystemType,
        lifecycle_state: LifecycleState,
        described_at_ms: u64,
    ) -> Self {
        Self {
            version: AUTONOMOUS_SYSTEM_VERSION,
            system_id,
            system_type,
            platform: None,
            display_name: None,
            profiles: Vec::new(),
            lifecycle_state,
            described_at_ms,
        }
    }

    pub fn with_platform(mut self, platform: PlatformId) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = Some(name.to_owned());
        self
    }

    pub fn with_profile(mut self, profile: ProfileRef) -> Self {
        self.profiles.push(profile);
        self
    }

    /// Refuse a structure whose version this build does not implement.
    ///
    /// Must be called before reading a deserialised value. Serde will happily
    /// parse a version-2 record into version-1 fields; only this check stops
    /// those fields being read as though their meaning were known.
    pub fn check_version(&self) -> Result<(), SystemError> {
        if self.version != AUTONOMOUS_SYSTEM_VERSION {
            return Err(SystemError::UnsupportedVersion {
                found: self.version,
                supported: AUTONOMOUS_SYSTEM_VERSION,
            });
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Injective because every variable-length field is length-prefixed and
    /// every optional field carries a presence byte, so no two distinct
    /// descriptions can produce the same bytes — a system named `"ab"` with no
    /// platform cannot encode as one named `"a"` with platform `"b"`.
    ///
    /// This crate does not sign these bytes. They exist to be embedded in
    /// something that is (D17-3).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, AUTONOMOUS_SYSTEM_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, self.system_id.as_str());
        put_u8(&mut buf, self.system_type.code());
        // Optionals carry a presence byte rather than encoding `None` as an
        // empty string: absent and empty are different claims.
        match &self.platform {
            Some(p) => {
                put_u8(&mut buf, 1);
                put_str(&mut buf, p.as_str());
            }
            None => put_u8(&mut buf, 0),
        }
        put_opt_str(&mut buf, &self.display_name);
        // Sorted so the bytes do not depend on insertion order, and counted
        // so a truncated list is not a valid prefix of a longer one.
        let mut profiles: Vec<&ProfileRef> = self.profiles.iter().collect();
        profiles.sort_by(|a, b| a.kind.code().cmp(&b.kind.code()).then(a.id().cmp(b.id())));
        put_u32(&mut buf, profiles.len() as u32);
        for p in profiles {
            p.encode(&mut buf);
        }
        self.lifecycle_state.encode(&mut buf);
        put_u64(&mut buf, self.described_at_ms);
        buf
    }
}
