//! R17 — the AI-inventory attachment, derived from a real signed ledger.
//!
//! The ledger is built the same way `tests/ledger.rs` builds one: a real
//! `ProcfsProbe` measuring this process, a real `CollectorSigner` attesting
//! the batch, and a real signed registry naming one institutional system.
//! What the tests check is that the attachment says exactly what the ledger
//! says, and refuses to say anything the ledger does not.

use aip_crypto::generate_ed25519_keypair;
use aip_ledger::{
    AccessLedger, AccessLedgerBuilder, InventoryEntry, LedgerError, LedgerSigner,
    LedgerTrustAnchors,
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
const OBSERVER: &str = "collector-t";
const PROBE: &str = "probe-t";
const CORE: [u8; 4] = [10, 0, 5, 20];
const CORE_PORT: u16 = 8443;
const UNNAMED: [u8; 4] = [203, 0, 113, 9];
const T0: u64 = 1_700_000_000_000;

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

/// A ledger over two endpoints: the named core banking system and one the
/// registry never named.
fn built() -> (AccessLedger, LedgerTrustAnchors) {
    let (reg, reg_anchors) = registry();
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE, &SourceMechanism::ALL);
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER, 1, &kp.public_key);

    let mut probe = ProcfsProbe::new(PROBE);
    let claim = AgentClaim {
        agent_id: AGENT.into(),
        claim_source: "orchestrator".into(),
        decision_id: Some([1u8; 16]),
    };
    let me = probe.measure(std::process::id()).unwrap();
    let mut obs = Vec::new();
    for (i, (addr, port)) in [(CORE, CORE_PORT), (UNNAMED, 443)].iter().enumerate() {
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
            T0 + 1_000,
        ));
    }
    let batch = signer
        .attest_at(probe.batch([1u8; 16], T0, T0 + 60_000, obs), T0 + 61_000)
        .unwrap();

    let window = CoverageWindow {
        from_ms: T0,
        to_ms: T0 + 60_000,
    };
    let mut b = AccessLedgerBuilder::new(AGENT, window, &reg, &reg_anchors).unwrap();
    b.observe(&batch, &anchors).unwrap();

    let lkp = generate_ed25519_keypair();
    let lsigner = LedgerSigner::new("ledger-1", 1, &lkp.private_key, &lkp.public_key);
    (
        b.build_and_sign(&lsigner, T0 + 70_000).unwrap(),
        LedgerTrustAnchors::new().trust("ledger-1", 1, &lkp.public_key),
    )
}

#[test]
fn the_entry_reports_what_the_ledger_says_and_cites_it() {
    let (ledger, anchors) = built();
    let e = InventoryEntry::from_ledger(&ledger, &anchors).unwrap();

    assert_eq!(e.agent_id, AGENT);
    assert_eq!(e.window_from_ms, T0);
    assert_eq!(e.window_to_ms, T0 + 60_000);
    // The registry revision is cited, because two entries from different
    // revisions are not directly comparable.
    assert_eq!(e.registry_id, "bank/dc1");
    assert_eq!(e.registry_revision, 5);
    // The ledger is cited by digest, so a reviewer can ask for the document.
    assert_eq!(e.ledger_digest, hex::encode(ledger.digest()));
    assert_eq!(e.ledger_signer_id, "ledger-1");

    // One named resource and one unregistered group.
    assert_eq!(e.resources.len(), 2, "{:#?}", e.resources);
    let named = &e.resources[0];
    assert_eq!(named.resource_id.as_deref(), Some("core-banking-api"));
    assert_eq!(
        named.criticality,
        Some(Criticality::TransactionCritical.code())
    );
    assert_eq!(named.rows, 1);
    let unregistered = e.resources.last().unwrap();
    assert_eq!(unregistered.resource_id, None);
    assert_eq!(e.unregistered_endpoints, 1);
}

/// No verdicts were cited, so every row is `NoVerdict` — and the entry must
/// report that separately from `verified` rather than letting a reviewer
/// read an unobserved window as a clean one.
#[test]
fn a_window_with_no_verdicts_is_not_reported_as_verified() {
    let (ledger, anchors) = built();
    let e = InventoryEntry::from_ledger(&ledger, &anchors).unwrap();
    assert_eq!(e.verified_rows, 0);
    assert_eq!(e.adverse_rows, 0);
    assert_eq!(e.no_verdict_rows, ledger.entries.len());
    assert_eq!(e.unproven_rows, 0);
    // And the review flag is not a clean bill of health either way: it is
    // narrow on purpose.
    assert!(!e.needs_review());
    assert_eq!(
        e.verified_rows + e.adverse_rows + e.unproven_rows + e.no_verdict_rows,
        ledger.entries.len(),
        "every row is accounted for in exactly one standing"
    );
}

/// The entry is derived from a **verified** ledger. An unverified one would
/// launder an unsigned document into a regulatory record.
#[test]
fn an_unverifiable_ledger_yields_no_inventory_entry() {
    let (ledger, _) = built();

    assert!(matches!(
        InventoryEntry::from_ledger(&ledger, &LedgerTrustAnchors::new()),
        Err(LedgerError::UntrustedSigner { .. })
    ));

    let impostor = generate_ed25519_keypair();
    assert_eq!(
        InventoryEntry::from_ledger(
            &ledger,
            &LedgerTrustAnchors::new().trust("ledger-1", 1, &impostor.public_key)
        ),
        Err(LedgerError::SignatureInvalid)
    );
}

/// A ledger altered after signing produces no entry, so the attachment can
/// never be more favourable than the document it rests on.
#[test]
fn a_tampered_ledger_yields_no_inventory_entry() {
    let (mut ledger, anchors) = built();
    ledger.entries.pop();
    assert_eq!(
        InventoryEntry::from_ledger(&ledger, &anchors),
        Err(LedgerError::PayloadHashMismatch)
    );
}

#[test]
fn the_entry_round_trips_through_json() {
    let (ledger, anchors) = built();
    let e = InventoryEntry::from_ledger(&ledger, &anchors).unwrap();
    let back: InventoryEntry = serde_json::from_str(&e.to_json()).unwrap();
    assert_eq!(back, e);
}
