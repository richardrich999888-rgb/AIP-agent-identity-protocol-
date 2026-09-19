//! The access ledger built from a real probe and a real collector, resolved
//! against a real signed registry — then attacked.
//!
//! The observation side is genuine: `ProcfsProbe` measures this test's own
//! process, records socket effects for it under an agent claim, and a
//! `CollectorSigner` attests the batch. What is synthetic is only the socket
//! table content (the effects name endpoints chosen by the test), so the
//! registry resolution can be checked against known addresses.

use aip_crypto::generate_ed25519_keypair;
use aip_ledger::{
    AccessLedger, AccessLedgerBuilder, LedgerError, LedgerSigner, LedgerTrustAnchors, ResourceRef,
    Standing, TimeBasis, PROTO_TCP,
};
use aip_observe::{
    AgentClaim, CollectorSigner, ObservedEffect, ObserverAttestor, ObserverTrustAnchors,
    ProcfsProbe, SocketEndpoint, SocketProtocol, SourceMechanism,
};
use aip_registry::{
    AddressRange, Criticality, PortRange, Protocol, RegistryTrustAnchors, ResourceEntry,
    ResourceRegistry,
};
use aip_types::CoverageWindow;

const AGENT: &str = "aip1LoanAgentXYZ";
const OTHER_AGENT: &str = "aip1SomeoneElse";
const OBSERVER: &str = "collector-t";
const PROBE: &str = "probe-t";
const CORE: [u8; 4] = [10, 0, 5, 20];
const CORE_PORT: u16 = 8443;
const UNNAMED: [u8; 4] = [203, 0, 113, 9];
const T0: u64 = 1_700_000_000_000;

/// The observer's layout: IPv4 in the first four bytes.
fn ep(addr: [u8; 4], port: u16) -> SocketEndpoint {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&addr);
    SocketEndpoint {
        addr: a,
        is_v6: false,
        port,
    }
}

fn registry() -> (ResourceRegistry, RegistryTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let reg = ResourceRegistry::sign(
        "bank/dc1",
        "bank.example",
        &kp.private_key,
        5,
        T0 - 1_000_000,
        vec![ResourceEntry {
            id: "core-banking-api".into(),
            display_name: "Core banking API".into(),
            criticality: Criticality::TransactionCritical,
            protocol: Protocol::Tcp,
            addresses: vec![AddressRange::v4_host(CORE)],
            ports: vec![PortRange::single(CORE_PORT)],
        }],
    )
    .unwrap();
    (
        reg,
        RegistryTrustAnchors::new().trust("bank.example", &kp.public_key),
    )
}

struct Collector {
    signer: CollectorSigner,
    anchors: ObserverTrustAnchors,
}

fn collector() -> Collector {
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE, &SourceMechanism::ALL);
    Collector {
        signer,
        anchors: ObserverTrustAnchors::new().trust(OBSERVER, 1, &kp.public_key),
    }
}

/// One attested batch: this process, claimed as `agent`, with socket effects
/// to the given remotes at the given host times.
fn batch_for(
    c: &mut Collector,
    agent: &str,
    remotes: &[([u8; 4], u16, u64)],
    seq_tag: u8,
) -> aip_observe::AttestedBatch {
    let mut probe = ProcfsProbe::new(PROBE);
    let claim = AgentClaim {
        agent_id: agent.into(),
        claim_source: "orchestrator".into(),
        decision_id: Some([seq_tag; 16]),
    };
    let me = probe.measure(std::process::id()).unwrap();
    let mut obs = Vec::new();
    for (i, (addr, port, t)) in remotes.iter().enumerate() {
        obs.push(probe.observation(
            me.clone(),
            ObservedEffect::SocketObserved {
                protocol: SocketProtocol::Tcp,
                local: ep([127, 0, 0, 1], 40_000 + i as u16),
                remote: ep(*addr, *port),
                state: 0x01,
                inode: 9_000 + i as u64,
            },
            Some(&claim),
            *t,
        ));
    }
    let b = probe.batch([seq_tag; 16], T0, T0 + 60_000, obs);
    c.signer.attest_at(b, T0 + 61_000).unwrap()
}

fn window() -> CoverageWindow {
    CoverageWindow {
        from_ms: T0,
        to_ms: T0 + 60_000,
    }
}

fn ledger_signer() -> (LedgerSigner, LedgerTrustAnchors) {
    let kp = generate_ed25519_keypair();
    (
        LedgerSigner::new("ledger-1", 1, &kp.private_key, &kp.public_key),
        LedgerTrustAnchors::new().trust("ledger-1", 1, &kp.public_key),
    )
}

fn build() -> (AccessLedger, LedgerTrustAnchors) {
    let (reg, reg_anchors) = registry();
    let mut c = collector();
    let b1 = batch_for(
        &mut c,
        AGENT,
        &[(CORE, CORE_PORT, T0 + 1_000), (UNNAMED, 443, T0 + 2_000)],
        1,
    );
    let b2 = batch_for(&mut c, AGENT, &[(CORE, CORE_PORT, T0 + 30_000)], 2);
    // Someone else's connections in the same window: not this agent's rows.
    let b3 = batch_for(&mut c, OTHER_AGENT, &[([10, 0, 9, 3], 9001, T0 + 5_000)], 3);
    // This agent, but outside the window.
    let b4 = batch_for(&mut c, AGENT, &[([10, 0, 9, 3], 9001, T0 + 59_999)], 4);
    // A window that ends before b4's observation: the late row is examined
    // and excluded.
    let mut narrow = AccessLedgerBuilder::new(
        AGENT,
        CoverageWindow {
            from_ms: T0,
            to_ms: T0 + 40_000,
        },
        &reg,
        &reg_anchors,
    )
    .unwrap();
    for b in [&b1, &b2, &b3, &b4] {
        narrow.observe(b, &c.anchors).unwrap();
    }
    let (signer, anchors) = ledger_signer();
    let ledger = narrow.build_and_sign(&signer, T0 + 70_000).unwrap();
    (ledger, anchors)
}

// ─── Composition ───

#[test]
fn rows_are_named_by_the_registry_and_the_unnamed_are_said_to_be_unnamed() {
    let (ledger, anchors) = build();
    assert_eq!(ledger.verify(&anchors), Ok(()));
    assert_eq!(ledger.registry_id, "bank/dc1");
    assert_eq!(ledger.registry_revision, 5);
    assert_eq!(ledger.entries.len(), 2, "{:#?}", ledger.entries);

    let core = ledger
        .entries
        .iter()
        .find(|e| e.endpoint.port == CORE_PORT)
        .expect("core banking row");
    assert_eq!(
        core.resource,
        ResourceRef::Named {
            id: "core-banking-api".into(),
            criticality: Criticality::TransactionCritical.code(),
        }
    );
    assert_eq!(core.endpoint.protocol, PROTO_TCP);
    assert_eq!(core.occurrences, 2, "two batches saw the same endpoint");
    assert_eq!(core.first_seen_ms, T0 + 1_000);
    assert_eq!(core.last_seen_ms, T0 + 30_000);
    assert_eq!(core.time_basis, TimeBasis::HostWallClock);
    assert_eq!(core.standing, Standing::NoVerdict);
    assert!(core.verdicts.is_empty());

    let unnamed = ledger
        .entries
        .iter()
        .find(|e| e.endpoint.port == 443)
        .expect("unnamed row");
    assert_eq!(unnamed.resource, ResourceRef::Unregistered);
    assert_eq!(ledger.unregistered().count(), 1);
    assert_eq!(ledger.adverse().count(), 0);
}

#[test]
fn other_agents_and_out_of_window_observations_are_counted_but_not_kept() {
    let (ledger, _) = build();
    // 2 + 1 + 1 + 1 observations examined across four batches.
    assert_eq!(ledger.considered, 5);
    assert_eq!(ledger.batches.len(), 4);
    assert!(
        ledger.entries.iter().all(|e| e.endpoint.port != 9001),
        "neither the other agent's row nor the late one"
    );
}

#[test]
fn an_unverifiable_batch_is_refused_and_leaves_the_ledger_unchanged() {
    let (reg, reg_anchors) = registry();
    let mut c = collector();
    let b = batch_for(&mut c, AGENT, &[(CORE, CORE_PORT, T0 + 1_000)], 1);
    let stranger = ObserverTrustAnchors::new();
    let mut builder = AccessLedgerBuilder::new(AGENT, window(), &reg, &reg_anchors).unwrap();
    assert!(matches!(
        builder.observe(&b, &stranger),
        Err(LedgerError::BatchInvalid(_))
    ));
    let (signer, _) = ledger_signer();
    let ledger = builder.build_and_sign(&signer, T0 + 70_000).unwrap();
    assert!(ledger.entries.is_empty());
    assert!(ledger.batches.is_empty());
}

#[test]
fn a_registry_the_verifier_does_not_anchor_cannot_start_a_ledger() {
    let (reg, _) = registry();
    let nobody = RegistryTrustAnchors::new();
    assert!(matches!(
        AccessLedgerBuilder::new(AGENT, window(), &reg, &nobody),
        Err(LedgerError::Registry(_))
    ));
}

// ─── The ledger under attack ───

#[test]
fn renaming_a_row_after_signing_is_detected() {
    let (mut ledger, anchors) = build();
    let i = ledger
        .entries
        .iter()
        .position(|e| e.resource == ResourceRef::Unregistered)
        .unwrap();
    ledger.entries[i].resource = ResourceRef::Named {
        id: "core-banking-api".into(),
        criticality: 1,
    };
    assert_eq!(
        ledger.verify(&anchors),
        Err(LedgerError::PayloadHashMismatch)
    );
}

#[test]
fn dropping_a_row_after_signing_is_detected() {
    let (mut ledger, anchors) = build();
    ledger.entries.pop();
    assert_eq!(
        ledger.verify(&anchors),
        Err(LedgerError::PayloadHashMismatch)
    );
}

#[test]
fn re_pointing_the_registry_revision_after_signing_is_detected() {
    let (mut ledger, anchors) = build();
    ledger.registry_revision += 1;
    assert_eq!(
        ledger.verify(&anchors),
        Err(LedgerError::PayloadHashMismatch)
    );
}

#[test]
fn a_ledger_from_an_unanchored_signer_establishes_nothing() {
    let (ledger, _) = build();
    let impostor = generate_ed25519_keypair();
    let wrong = LedgerTrustAnchors::new().trust("ledger-1", 1, &impostor.public_key);
    assert_eq!(ledger.verify(&wrong), Err(LedgerError::SignatureInvalid));
    assert!(matches!(
        ledger.verify(&LedgerTrustAnchors::new()),
        Err(LedgerError::UntrustedSigner { .. })
    ));
}

#[test]
fn a_reordered_or_restated_ledger_is_not_canonical() {
    let (mut ledger, anchors) = build();
    ledger.entries.reverse();
    assert_eq!(
        ledger.verify(&anchors),
        Err(LedgerError::EntriesNotCanonical)
    );
    let (mut ledger, anchors) = build();
    // Restating a row's standing above what its (absent) verdicts support.
    ledger.entries[0].standing = Standing::Verified;
    assert_eq!(
        ledger.verify(&anchors),
        Err(LedgerError::EntriesNotCanonical)
    );
}

#[test]
fn the_ledger_round_trips_through_json_and_still_verifies() {
    let (ledger, anchors) = build();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: AccessLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ledger);
    assert_eq!(back.verify(&anchors), Ok(()));
    assert_eq!(back.digest(), ledger.digest());
}
