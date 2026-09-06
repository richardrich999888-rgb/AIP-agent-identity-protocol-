//! `PlatformBinding` — what may honestly be said about where an execution ran.
//!
//! # Not a verdict
//!
//! A `PlatformDisposition` is a structural fact about which evidence exists
//! for one execution's location. It is an input to the one reconciliation
//! engine — not a result class, not a severity, not an accusation. This crate
//! produces no verdicts and computes no evidence strength.
//!
//! # The four dispositions, and why the last two are separate
//!
//! `Unregistered` and `NotEvaluated` are distinct for the same reason
//! `CANNOT_PROVE` exists. "The verifier has not spoken about this host" and
//! "no observation reached us" are different states, and summing them turns a
//! blind spot into a clean bill of health.

use aip_system::{HardwareId, PlatformId};
use aip_types::canonical::{put_bytes, put_domain, put_str, put_u16, put_u64, put_u8};
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;
use crate::method::BindingMethod;
use crate::registry::PlatformRegistry;

/// Domain tag leading every `PlatformBinding` canonical encoding.
pub const PLATFORM_BINDING_DOMAIN: &str = "SYNTRIASS/AUTONOMY/PLATFORM_BINDING/v1";

/// Structure version. Unknown versions are refused, never guessed.
pub const PLATFORM_BINDING_VERSION: u16 = 1;

/// What is established about where an execution ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformDisposition {
    /// The verifier's registry resolves the observed host-boot to a platform.
    Bound {
        platform_id: PlatformId,
        hardware_id: Option<HardwareId>,
        method: BindingMethod,
    },
    /// The observed host-boot resolves to a platform **other** than the one
    /// authorized. The strongest statement this crate makes.
    Mismatch {
        authorized: PlatformId,
        observed: PlatformId,
    },
    /// An observation exists, and the verifier's registry does not cover the
    /// host-boot it names. Unknown, not wrong.
    Unregistered,
    /// No observation was available to resolve. The default.
    NotEvaluated,
}

impl PlatformDisposition {
    pub fn code(&self) -> u8 {
        match self {
            Self::Bound { .. } => 0x01,
            Self::Mismatch { .. } => 0x02,
            Self::Unregistered => 0x03,
            Self::NotEvaluated => 0x04,
        }
    }

    /// Whether this asserts the execution ran on a known platform.
    ///
    /// True only for `Bound`. `Unregistered` and `NotEvaluated` are both
    /// false, and neither asserts that it ran somewhere *else*.
    pub fn asserts_platform(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        put_u8(buf, self.code());
        match self {
            Self::Bound {
                platform_id,
                hardware_id,
                method,
            } => {
                put_str(buf, platform_id.as_str());
                match hardware_id {
                    Some(h) => {
                        put_u8(buf, 1);
                        put_str(buf, h.as_str());
                    }
                    None => put_u8(buf, 0),
                }
                method.encode(buf);
            }
            Self::Mismatch {
                authorized,
                observed,
            } => {
                put_str(buf, authorized.as_str());
                put_str(buf, observed.as_str());
            }
            Self::Unregistered | Self::NotEvaluated => {}
        }
    }
}

/// One execution's platform binding, as the verifier resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformBinding {
    pub version: u16,
    /// The execution this is about. Reused verbatim from `aip-airi`; this
    /// crate defines no execution identifier of its own.
    pub execution_id: [u8; 16],
    /// The host-boot an anchored observer measured, when one did.
    ///
    /// `None` means no observation reached the verifier — which is why the
    /// disposition is then `NotEvaluated` rather than anything stronger.
    pub observed_boot_id: Option<[u8; 16]>,
    /// The instant the binding was resolved at, Unix ms.
    ///
    /// Supplied by the verifier, not read from a clock: this crate reads no
    /// clock, for the same reason the reconciler does not — a historical
    /// verification must be able to say what "then" means.
    pub resolved_at_ms: u64,
    disposition: PlatformDisposition,
}

impl PlatformBinding {
    /// Resolve where an execution ran, from what the verifier holds.
    ///
    /// The only constructor. There is no setter for `disposition`, so a
    /// caller cannot choose the answer — it is a consequence of the inputs.
    ///
    /// - No observed boot → `NotEvaluated`. Absence of observation is not
    ///   evidence of location.
    /// - Registry does not cover the boot at this instant → `Unregistered`.
    /// - Registry resolves it, and an authorized platform was supplied that
    ///   differs → `Mismatch`. **This is T13 caught at the platform layer.**
    /// - Registry resolves it and it agrees, or nothing was authorized to
    ///   compare against → `Bound` by `DeploymentRegistry`.
    ///
    /// `authorized_platform` is what the decision point signed (Skill 18's
    /// binding). `None` means the authorization named no platform, in which
    /// case there is nothing to disagree with — and a `Bound` result then says
    /// only where it ran, not that it was permitted to.
    pub fn resolve(
        execution_id: [u8; 16],
        observed_boot_id: Option<[u8; 16]>,
        authorized_platform: Option<&PlatformId>,
        registry: &PlatformRegistry,
        resolved_at_ms: u64,
    ) -> Self {
        let disposition = match observed_boot_id {
            None => PlatformDisposition::NotEvaluated,
            Some(boot) => match registry.resolve(&boot, resolved_at_ms) {
                None => PlatformDisposition::Unregistered,
                Some(reg) => match authorized_platform {
                    Some(auth) if auth != &reg.platform_id => PlatformDisposition::Mismatch {
                        authorized: auth.clone(),
                        observed: reg.platform_id.clone(),
                    },
                    _ => PlatformDisposition::Bound {
                        platform_id: reg.platform_id.clone(),
                        hardware_id: reg.hardware_id.clone(),
                        // The registry is the only method this build can
                        // produce. `HardwareAttested` requires ADR-002 to be
                        // accepted, and nothing here can reach it.
                        method: BindingMethod::DeploymentRegistry,
                    },
                },
            },
        };
        Self {
            version: PLATFORM_BINDING_VERSION,
            execution_id,
            observed_boot_id,
            resolved_at_ms,
            disposition,
        }
    }

    /// Read-only. The disposition follows the evidence; a caller that could
    /// set it would eventually set it wrong.
    pub fn disposition(&self) -> &PlatformDisposition {
        &self.disposition
    }

    /// Refuse a structure whose version this build does not implement.
    ///
    /// Also refuses a binding claiming a method this build cannot produce: a
    /// deserialised `HardwareAttested` binding is either from a future build
    /// or forged, and both are refused rather than read.
    pub fn check_version(&self) -> Result<(), PlatformError> {
        if self.version != PLATFORM_BINDING_VERSION {
            return Err(PlatformError::UnsupportedVersion {
                found: self.version,
                supported: PLATFORM_BINDING_VERSION,
            });
        }
        if let PlatformDisposition::Bound { method, .. } = &self.disposition {
            if !method.is_implemented() {
                return Err(PlatformError::UnsupportedVersion {
                    found: self.version,
                    supported: PLATFORM_BINDING_VERSION,
                });
            }
        }
        Ok(())
    }

    /// Domain-tagged, injective canonical bytes.
    ///
    /// Every identity that distinguishes one binding from another is inside
    /// them: the execution, the observed boot, the resolved platform and
    /// hardware, the method, and the instant. Length-prefixed with presence
    /// bytes on optionals, so no two distinct bindings collide and no field
    /// can shift into another.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_domain(&mut buf, PLATFORM_BINDING_DOMAIN);
        put_u16(&mut buf, self.version);
        put_bytes(&mut buf, &self.execution_id);
        match &self.observed_boot_id {
            Some(b) => {
                put_u8(&mut buf, 1);
                put_bytes(&mut buf, b);
            }
            None => put_u8(&mut buf, 0),
        }
        put_u64(&mut buf, self.resolved_at_ms);
        self.disposition.encode(&mut buf);
        buf
    }

    /// SHA-256 over the canonical bytes, for embedding in a signed artifact.
    ///
    /// This crate signs nothing. As with Skills 17 and 18, integrity comes
    /// from a consumer committing to these bytes inside something already
    /// signed — never from a signer added here.
    pub fn digest(&self) -> [u8; 32] {
        aip_crypto::sha256(&self.canonical_bytes())
    }
}
