//! Fixtures that go through the real observer trust model.
//!
//! Every `ObservationRecord` here is produced by a real `CollectorSigner`
//! signing a real batch, verified against real anchors. A hand-built record
//! would test this crate against a fiction; the point of the effect boundary
//! is what happens to evidence that actually came from an anchored observer.

use aip_crypto::generate_ed25519_keypair;
use aip_effect::{EffectCorrelation, EffectObservation, EffectWindow, ObservedStance};
use aip_execution::RequestedEffect;
use aip_observation::{ObservationCorrelation, ObservationProfile, ObservationRecord};
use aip_observe::{
    CollectorSigner, ObservedEffect, ObservedProcess, ObserverAttestor, ObserverTrustAnchors,
    ProcfsProbe, SourceMechanism,
};
use aip_system::SystemId;

pub const OBSERVER: &str = "collector.effect.example";
pub const KEY_V: u32 = 1;
pub const BOOT: [u8; 16] = [0xb0; 16];
pub const EXEC: [u8; 16] = [0xe1; 16];
pub const DECISION: [u8; 16] = [0xd1; 16];

/// A collector, its anchors, and a probe — the real chain.
pub struct Observer {
    pub signer: CollectorSigner,
    pub anchors: ObserverTrustAnchors,
    pub probe: ProcfsProbe,
}

pub fn observer(id: &str) -> Observer {
    let kp = generate_ed25519_keypair();
    let signer = CollectorSigner::new(id, KEY_V, &kp.private_key, &kp.public_key).unwrap();
    let anchors = ObserverTrustAnchors::new().trust(id, KEY_V, &kp.public_key);
    Observer {
        signer,
        anchors,
        probe: ProcfsProbe::new("probe-effect"),
    }
}

pub fn system() -> SystemId {
    SystemId::parse("sys:effect-test").expect("a valid system id")
}

/// A verified record for `(system, exec, boot)` at collector time `at_ms`.
pub fn record_at(
    o: &mut Observer,
    system_id: &SystemId,
    exec: [u8; 16],
    boot: [u8; 16],
    decision: Option<[u8; 16]>,
    at_ms: u64,
) -> ObservationRecord {
    let proc = ObservedProcess {
        process: aip_types::ProcessInstance {
            pid: 42,
            pid_start_time_ticks: 1000,
            boot_id: boot,
        },
        exe_content_sha256: [0xe0; 32],
        exe_path: "/opt/agent/bin/agent".into(),
    };
    let obs = o
        .probe
        .observation(proc, ObservedEffect::ProcessPresent, None, at_ms);
    let batch = o.probe.batch([0x11; 16], at_ms, at_ms + 10, vec![obs]);
    let attested = o.signer.attest_at(batch, at_ms).unwrap();

    ObservationRecord::from_attested(
        &attested,
        &o.anchors,
        0,
        ObservationCorrelation {
            system_id: system_id.clone(),
            execution_id: exec,
            boot_id: boot,
            decision_id: decision,
        },
    )
    .expect("a batch this observer signed must yield a record")
}

/// The standard record: correct system, execution, boot and decision.
pub fn good_record(o: &mut Observer) -> ObservationRecord {
    record_at(o, &system(), EXEC, BOOT, Some(DECISION), 1_000)
}

/// A profile that can observe process identity at `Attested` — the class the
/// fixture's `ProcfsPoll` mechanism produces.
pub fn capable_profile() -> ObservationProfile {
    ObservationProfile::new("effect-test")
        .expect("a valid profile name")
        .with_mechanism(SourceMechanism::ProcfsPoll)
}

/// A profile that declares it observes nothing.
pub fn blind_profile() -> ObservationProfile {
    ObservationProfile::new("effect-test-blind").expect("a valid profile name")
}

pub fn correlation() -> EffectCorrelation {
    EffectCorrelation {
        system_id: system(),
        execution_id: EXEC,
        boot_id: BOOT,
        decision_id: Some(DECISION),
        parameter_commitment: [0x9c; 32],
    }
}

pub fn requested() -> RequestedEffect {
    RequestedEffect {
        action_kind: "actuator.open".into(),
        parameter_commitment: [0x9c; 32],
        target: Some("valve-a".into()),
    }
}

pub fn window() -> EffectWindow {
    EffectWindow {
        from_ms: 0,
        to_ms: 10_000,
    }
}

pub fn supports(r: ObservationRecord) -> EffectObservation {
    EffectObservation::new(r, ObservedStance::Supports)
        .expect("an observed record may take a stance")
}

pub fn opposes(r: ObservationRecord) -> EffectObservation {
    EffectObservation::new(r, ObservedStance::Opposes)
        .expect("an observed record may take a stance")
}

pub fn neither(r: ObservationRecord) -> EffectObservation {
    EffectObservation::new(r, ObservedStance::Neither).expect("Neither is always admissible")
}

/// One requested effect in the execution — the exact-binding case.
pub const ONE_EFFECT: u32 = 1;
