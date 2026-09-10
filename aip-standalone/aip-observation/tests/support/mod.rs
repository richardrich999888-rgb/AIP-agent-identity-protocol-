//! Real observers, real signatures, real verification.
//!
//! Every `ObservationRecord` in these tests comes through a `CollectorSigner`,
//! a real Ed25519 signature and a real verification against real anchors.
//! There is no shortcut — the absence of one is the property under test.

#![allow(dead_code)]

use aip_observation::*;
use aip_observe::*;
use aip_system::SystemId;
use aip_types::{KeyPair, ProcessInstance};

pub const OBSERVER_ID: &str = "collector-o";
pub const PROBE_ID: &str = "probe-o";
pub const BOOT_P: [u8; 16] = [0x11; 16];
pub const BOOT_Q: [u8; 16] = [0x22; 16];
pub const EXEC_A: [u8; 16] = [0xA1; 16];
pub const EXEC_B: [u8; 16] = [0xB2; 16];
pub const DECISION_A: [u8; 16] = [0xD1; 16];

pub fn system(v: &str) -> SystemId {
    SystemId::parse(v).expect("valid system id")
}

pub struct Observer {
    pub signer: CollectorSigner,
    pub probe: ProcfsProbe,
    pub anchors: ObserverTrustAnchors,
    pub keys: KeyPair,
}

/// An observer with a fresh key and the anchors that trust it.
pub fn observer() -> Observer {
    observer_named(OBSERVER_ID, 1)
}

pub fn observer_named(id: &str, key_version: u32) -> Observer {
    let keys = aip_crypto::generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new(id, key_version, &keys.private_key, &keys.public_key).unwrap();
    signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let mut probe = ProcfsProbe::new(PROBE_ID);
    for m in SourceMechanism::ALL {
        probe.declare_source(m);
    }
    let anchors = ObserverTrustAnchors::new().trust(id, key_version, &keys.public_key);
    Observer {
        signer,
        probe,
        anchors,
        keys,
    }
}

fn observed_process(boot_id: [u8; 16]) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 777_000,
            boot_id,
        },
        exe_content_sha256: [0x33; 32],
        exe_path: "/opt/agent/bin/autonomy".into(),
    }
}

/// A batch attested by `o`, carrying one observation on `boot_id` obtained by
/// `mechanism`, at collector sequence `seq`.
pub fn batch_on(
    o: &mut Observer,
    boot_id: [u8; 16],
    mechanism: SourceMechanism,
    seq: u8,
) -> AttestedBatch {
    let obs = o.probe.observation_with(
        observed_process(boot_id),
        ObservedEffect::ProcessPresent,
        mechanism,
        None,
        1_000,
    );
    o.signer
        .attest(o.probe.batch([seq; 16], 0, 2_000, vec![obs]))
        .expect("attest")
}

pub fn correlation(boot_id: [u8; 16], execution_id: [u8; 16], sys: &str) -> ObservationCorrelation {
    ObservationCorrelation {
        system_id: system(sys),
        execution_id,
        boot_id,
        decision_id: Some(DECISION_A),
    }
}

/// A verified record: the only way one can be made.
pub fn record_on(boot_id: [u8; 16], mechanism: SourceMechanism) -> ObservationRecord {
    let mut o = observer();
    let batch = batch_on(&mut o, boot_id, mechanism, 1);
    ObservationRecord::from_attested(
        &batch,
        &o.anchors,
        0,
        correlation(boot_id, EXEC_A, "sys:fleet-1"),
    )
    .expect("an anchored observer's batch must verify")
}
