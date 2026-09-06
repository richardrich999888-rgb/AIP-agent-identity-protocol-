//! The verifier-supplied deployment registry.
//!
//! # Why this is not a new trust anchor
//!
//! The verifier already decides which decision-point and observer keys it
//! trusts. Deciding *which platform the host a trusted observer covers is* is
//! a statement of the same kind, made by the same party, at the same moment.
//! It introduces no signer, no key, and no artifact — it is verifier-held
//! data, exactly like `ObserverTrustAnchors`.
//!
//! That also bounds what it is worth. A registry entry is a **verifier
//! assertion**, and inherits the verifier's trust model rather than improving
//! on it. It says nothing about serial numbers, and nothing survives a reboot
//! (see `ADR-002`, gap G1).
//!
//! # Why the key is the boot id
//!
//! `boot_id` is the only value in the system that distinguishes one
//! machine-boot from another *and* is produced by something other than the
//! subject: `ProcfsProbe` reads it from `/proc/sys/kernel/random/boot_id` and
//! an anchored collector signs the batch containing it.
//!
//! It identifies a **boot**, not a machine. A reboot produces a new one, so a
//! registration legitimately stops applying — which is correct fail-closed
//! behaviour and is why hardware *replacement* cannot be detected here
//! (ADR-002 G1). Registering a new boot is a deliberate act by the verifier,
//! which is the property that stops old trust silently surviving new hardware.
//!
//! # Offline by construction
//!
//! The registry is portable data. Verification needs no network, which is a
//! hard requirement for the disconnected and space profiles.

use std::collections::HashMap;

use aip_system::{HardwareId, PlatformId};
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;

/// What the verifier asserts about one observed host-boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRegistration {
    /// The platform the host is part of.
    pub platform_id: PlatformId,
    /// The compute element, when the verifier distinguishes one.
    ///
    /// A platform may contain several — a UAS with a mission computer and a
    /// flight controller is two hardware elements under one platform, and
    /// each boots separately. `None` where the deployment does not
    /// distinguish them, which is a fact rather than a gap.
    pub hardware_id: Option<HardwareId>,
    /// When the verifier asserts this registration began, Unix ms.
    pub registered_from_ms: u64,
    /// When it ceased to apply, Unix ms, exclusive. `None` means open-ended.
    ///
    /// Bounded registration is how hardware replacement is handled: the old
    /// entry is closed and a new one opened. Nothing is mutated in place, so
    /// a historical verification still resolves the platform that applied at
    /// the time.
    pub registered_until_ms: Option<u64>,
}

impl HostRegistration {
    /// Whether this registration applies at `t_ms`.
    ///
    /// Half-open `[from, until)`, so two consecutive registrations of the same
    /// host cannot both apply at the instant of handover — an overlap would
    /// make a replacement ambiguous exactly when it matters.
    pub fn applies_at(&self, t_ms: u64) -> bool {
        t_ms >= self.registered_from_ms && self.registered_until_ms.is_none_or(|until| t_ms < until)
    }
}

/// The verifier's map from observed host-boots to platforms.
///
/// Deliberately shaped like `ObserverTrustAnchors`: constructed by the
/// verifier, consulted by lookup, never carried in an artifact. A registry
/// that travelled with the evidence would be the evidence asserting its own
/// context, which is B-4's defect one layer down.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformRegistry {
    /// `boot_id` → the registrations asserted for it, in insertion order.
    ///
    /// A `Vec` rather than a single value because one host is registered,
    /// closed and re-registered over its life, and a historical verification
    /// must resolve the entry that applied *then*.
    hosts: HashMap<[u8; 16], Vec<HostRegistration>>,
}

impl PlatformRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assert that the host with this `boot_id` is part of `platform`.
    ///
    /// Refuses an entry whose window is empty or inverted: a registration that
    /// applies at no instant is not a registration, and silently storing one
    /// would produce a host that is registered and never resolves.
    pub fn register(
        mut self,
        boot_id: [u8; 16],
        registration: HostRegistration,
    ) -> Result<Self, PlatformError> {
        if let Some(until) = registration.registered_until_ms {
            if until <= registration.registered_from_ms {
                return Err(PlatformError::EmptyRegistrationWindow);
            }
        }
        // Overlap with an existing open entry is refused rather than resolved
        // by precedence. Two registrations applying at one instant is an
        // authoring mistake, and guessing which was meant is how a
        // replacement gets attributed to the wrong platform.
        if let Some(existing) = self.hosts.get(&boot_id) {
            for e in existing {
                let overlaps = e.applies_at(registration.registered_from_ms)
                    || registration.applies_at(e.registered_from_ms);
                if overlaps {
                    return Err(PlatformError::OverlappingRegistration);
                }
            }
        }
        self.hosts.entry(boot_id).or_default().push(registration);
        Ok(self)
    }

    /// The registration that applied to this host-boot at `t_ms`.
    ///
    /// `None` for an unregistered host, and for a host registered only outside
    /// this instant. Both are *unknown*, never *wrong*: an unregistered host
    /// is a host the verifier has not spoken about.
    pub fn resolve(&self, boot_id: &[u8; 16], t_ms: u64) -> Option<&HostRegistration> {
        self.hosts.get(boot_id)?.iter().find(|r| r.applies_at(t_ms))
    }

    /// Close an open registration at `at_ms` — the hardware-replacement and
    /// reassignment path.
    ///
    /// Returns whether an open entry was found and closed. Nothing is
    /// mutated destructively: the entry keeps its start, so a verification of
    /// an earlier execution still resolves it.
    pub fn close(&mut self, boot_id: &[u8; 16], at_ms: u64) -> bool {
        let Some(entries) = self.hosts.get_mut(boot_id) else {
            return false;
        };
        for e in entries.iter_mut() {
            if e.registered_until_ms.is_none() && at_ms > e.registered_from_ms {
                e.registered_until_ms = Some(at_ms);
                return true;
            }
        }
        false
    }

    /// Every boot registered to `platform`, at `t_ms`.
    ///
    /// A platform with several compute elements has several — the UAS case in
    /// Skill 19's brief. Sorted so the result is deterministic.
    pub fn boots_of(&self, platform: &PlatformId, t_ms: u64) -> Vec<[u8; 16]> {
        let mut out: Vec<[u8; 16]> = self
            .hosts
            .iter()
            .filter(|(_, rs)| {
                rs.iter()
                    .any(|r| r.applies_at(t_ms) && &r.platform_id == platform)
            })
            .map(|(b, _)| *b)
            .collect();
        out.sort();
        out
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}
