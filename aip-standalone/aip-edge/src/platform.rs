//! Resolving where the execution ran, from evidence rather than from a claim.
//!
//! # Two statements that must come from different places
//!
//! A platform binding is the conjunction of exactly two things, and the whole
//! value of Skill 19 is that they have different authors:
//!
//! ```text
//!   the verifier asserts   boot_id B is platform P     ← PlatformRegistry
//!   an observer measured   this execution ran on B     ← ObservedBoot
//! ```
//!
//! The registry is verifier-held data of the same kind as `ObserverTrustAnchors`
//! — no signer, no key, no artifact. The measurement is extracted from an
//! attested batch that verified against the verifier's own anchors, and
//! `ObservedBoot` has **no** `from_bytes`, `new` or `From<[u8; 16]>`. A caller
//! holding a self-reported boot id has nothing to call.
//!
//! That last sentence is the entire mechanism. The reference does not check
//! that self-reported platform data is rejected; it has no expression capable
//! of offering self-reported platform data in the first place, which is why
//! [`self_reported_boot_cannot_bind`] is a compile-time argument written as a
//! test rather than a runtime guard.
//!
//! # Where the verifier's boot id comes from
//!
//! The driver reads `/proc/sys/kernel/random/boot_id` **itself**, as the party
//! that deployed the host, and registers that value. It is not taken from the
//! batch. Registering the boot id the observer reported would make the
//! registry agree with the observation by construction, and the agreement
//! would establish nothing. Registering the verifier's own knowledge and then
//! requiring the measurement to match it is the check that has content.

use aip_observe::{AttestedBatch, ObserverTrustAnchors, VerifyError};
use aip_platform::{HostRegistration, ObservedBoot, PlatformBinding, PlatformRegistry};
use aip_system::{HardwareId, PlatformId};

use crate::error::EdgeError;

/// Assert that a host-boot the verifier knows about belongs to a platform.
///
/// Open-ended from `from_ms`. Closing and re-opening a registration is how
/// hardware replacement is represented; nothing is mutated in place, so a
/// historical verification still resolves the entry that applied then.
pub fn register_measured_host(
    registry: PlatformRegistry,
    boot_id: [u8; 16],
    platform_id: PlatformId,
    hardware_id: Option<HardwareId>,
    from_ms: u64,
) -> Result<PlatformRegistry, EdgeError> {
    registry
        .register(
            boot_id,
            HostRegistration {
                platform_id,
                hardware_id,
                registered_from_ms: from_ms,
                registered_until_ms: None,
            },
        )
        .map_err(|e| EdgeError::Transport(format!("platform registry: {e:?}")))
}

/// Resolve the platform binding for one execution from a live attested batch.
///
/// `index` selects the observation whose measured boot is used — typically the
/// one the correlation matched, so the binding and the observation record are
/// about the same measurement rather than two different ones that happened to
/// arrive together.
///
/// Returns `Ok(None)` when the batch verifies and carries no observation at
/// that index: a verified batch that saw nothing is an absence, not an error,
/// and the two must not be conflated. The caller then resolves with `None`,
/// which yields `NotEvaluated` — absence of observation is not evidence of
/// location.
pub fn observed_boot_from(
    batch: &AttestedBatch,
    anchors: &ObserverTrustAnchors,
    index: usize,
) -> Result<Option<ObservedBoot>, VerifyError> {
    ObservedBoot::from_attested_at(batch, anchors, index)
}

/// Bind an execution to a platform, from measurement and registry alone.
///
/// `authorized_platform` is what the decision point signed. `None` means the
/// authorization named no platform, in which case there is nothing to disagree
/// with — and a `Bound` result then says only where it ran, not that it was
/// permitted to run there.
///
/// This function chooses no disposition. `PlatformBinding::resolve` derives it,
/// there is no setter, and a `Mismatch` is therefore a consequence of the
/// inputs rather than a judgement made here.
pub fn bind_platform(
    execution_id: [u8; 16],
    observed_boot: Option<ObservedBoot>,
    authorized_platform: Option<&PlatformId>,
    registry: &PlatformRegistry,
    resolved_at_ms: u64,
) -> PlatformBinding {
    PlatformBinding::resolve(
        execution_id,
        observed_boot,
        authorized_platform,
        registry,
        resolved_at_ms,
    )
}

/// The argument that a self-reported platform cannot satisfy the observation
/// boundary, stated as executable prose.
///
/// A workload's `ExecutionBinding` contains a `boot_id`. It is 16 bytes and it
/// is the *right* 16 bytes on an honest host. Nothing in this crate, and
/// nothing in `aip-platform`, offers a way to turn those bytes into an
/// `ObservedBoot`: the field is private and both constructors take an
/// `AttestedBatch` plus the verifier's anchors.
///
/// So the strongest thing a caller holding a self-report can do is pass `None`,
/// and `resolve` answers `NotEvaluated`. Returning that binding is what this
/// function does — not as a fallback, but to make the ceiling of the
/// self-reported path visible in the reference's own output.
pub fn self_reported_boot_cannot_bind(
    execution_id: [u8; 16],
    authorized_platform: Option<&PlatformId>,
    registry: &PlatformRegistry,
    resolved_at_ms: u64,
) -> PlatformBinding {
    // There is deliberately no parameter for the self-reported bytes. A
    // signature that accepted them would invite a future caller to find a way
    // to use them.
    PlatformBinding::resolve(
        execution_id,
        None,
        authorized_platform,
        registry,
        resolved_at_ms,
    )
}

/// Read this host's boot id, as the verifier's own knowledge of the host it
/// deployed.
///
/// Deliberately not routed through the observer: see the module documentation
/// for why registering the observer's own report would make the registry agree
/// with the measurement by construction.
pub fn verifier_boot_id() -> Result<[u8; 16], EdgeError> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| EdgeError::Transport(format!("/proc/sys/kernel/random/boot_id: {e}")))?;
    aip_core::execution_binding::parse_boot_id(&text)
        .map_err(|e| EdgeError::Transport(format!("boot id: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_platform::PlatformDisposition;

    fn platform(s: &str) -> PlatformId {
        PlatformId::parse(s).expect("platform id")
    }

    #[test]
    fn no_observation_yields_not_evaluated_never_bound() {
        let registry = PlatformRegistry::new();
        let b = bind_platform([1u8; 16], None, None, &registry, 1_000);
        assert_eq!(b.disposition(), &PlatformDisposition::NotEvaluated);
        assert!(!b.disposition().asserts_platform());
    }

    #[test]
    fn a_self_reported_boot_reaches_not_evaluated_and_no_further() {
        let registry = register_measured_host(
            PlatformRegistry::new(),
            [3u8; 16],
            platform("edge:reference-1"),
            None,
            0,
        )
        .unwrap();
        // Even with the *correct* boot registered, the self-reported path has
        // no way to name it.
        let b = self_reported_boot_cannot_bind([1u8; 16], None, &registry, 1_000);
        assert_eq!(b.disposition(), &PlatformDisposition::NotEvaluated);
    }

    #[test]
    fn an_empty_registration_window_is_refused() {
        let r = PlatformRegistry::new().register(
            [1u8; 16],
            HostRegistration {
                platform_id: platform("edge:x"),
                hardware_id: None,
                registered_from_ms: 10,
                registered_until_ms: Some(10),
            },
        );
        assert!(
            r.is_err(),
            "a registration that applies at no instant is not a registration"
        );
    }
}
