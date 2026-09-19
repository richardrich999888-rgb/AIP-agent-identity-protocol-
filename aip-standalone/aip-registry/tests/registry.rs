//! The resource registry under attack and under use.
//!
//! Every test below is one of two kinds: an attacker or a careless operator
//! presents a registry that could name an endpoint two ways, or that the
//! institution did not sign, and the registry is refused; or a legitimate
//! registry resolves endpoints deterministically, with "unregistered" as an
//! explicit answer.

use aip_crypto::generate_ed25519_keypair as generate_keypair;
use aip_registry::{
    AddressRange, Criticality, ObservedProtocol, PortRange, Protocol, RegistryError,
    RegistryTrustAnchors, Resolution, ResourceEntry, ResourceRegistry, RESOURCE_REGISTRY_VERSION,
};

const BANK: &str = "bank.example";
const REGISTRY: &str = "bank.example/dc1";

fn entry(
    id: &str,
    crit: Criticality,
    proto: Protocol,
    addrs: &[AddressRange],
    ports: &[PortRange],
) -> ResourceEntry {
    ResourceEntry {
        id: id.to_owned(),
        display_name: format!("{id} (display)"),
        criticality: crit,
        protocol: proto,
        addresses: addrs.to_vec(),
        ports: ports.to_vec(),
    }
}

/// A small but realistic estate: core banking API on one host, a payments
/// switch on a /28, a read-only reporting store on UDP+TCP, and a v6-only
/// admin plane.
fn estate() -> Vec<ResourceEntry> {
    vec![
        entry(
            "core-banking-api",
            Criticality::TransactionCritical,
            Protocol::Tcp,
            &[AddressRange::v4_host([10, 0, 5, 20])],
            &[PortRange::single(8443)],
        ),
        entry(
            "payments-switch",
            Criticality::TransactionCritical,
            Protocol::Tcp,
            &[AddressRange::v4([10, 0, 9, 0], 28)],
            &[PortRange {
                from: 9000,
                to: 9010,
            }],
        ),
        entry(
            "reporting-store",
            Criticality::Informational,
            Protocol::Any,
            &[AddressRange::v4([10, 0, 20, 0], 24)],
            &[PortRange::single(5432)],
        ),
        entry(
            "admin-plane-v6",
            Criticality::Operational,
            Protocol::Tcp,
            &[AddressRange::v6(
                [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                64,
            )],
            &[PortRange::single(22)],
        ),
    ]
}

fn v4(octets: [u8; 4]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[12..].copy_from_slice(&octets);
    a
}

fn signed_estate() -> (ResourceRegistry, RegistryTrustAnchors, Vec<u8>) {
    let kp = generate_keypair();
    let reg = ResourceRegistry::sign(
        REGISTRY,
        BANK,
        &kp.private_key,
        7,
        1_700_000_000_000,
        estate(),
    )
    .expect("a well-formed estate signs");
    let anchors = RegistryTrustAnchors::new().trust(BANK, &kp.public_key);
    (reg, anchors, kp.private_key.clone())
}

// ─── Signing and verification ───

#[test]
fn a_signed_registry_verifies_against_the_institutions_anchor() {
    let (reg, anchors, _) = signed_estate();
    assert_eq!(reg.verify(&anchors), Ok(()));
    assert_eq!(reg.version, RESOURCE_REGISTRY_VERSION);
    assert_eq!(reg.citation(), (REGISTRY, 7));
}

#[test]
fn entries_are_sorted_by_id_regardless_of_the_callers_order() {
    let kp = generate_keypair();
    let mut reversed = estate();
    reversed.reverse();
    let a = ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, estate()).unwrap();
    let b = ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, reversed).unwrap();
    assert_eq!(
        a.signing_preimage(),
        b.signing_preimage(),
        "one estate, one encoding"
    );
    let ids: Vec<&str> = a.entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "admin-plane-v6",
            "core-banking-api",
            "payments-switch",
            "reporting-store"
        ]
    );
}

#[test]
fn an_unanchored_issuer_is_refused_before_the_signature_is_examined() {
    let (reg, _, _) = signed_estate();
    let nobody = RegistryTrustAnchors::new();
    assert_eq!(
        reg.verify(&nobody),
        Err(RegistryError::UntrustedIssuer(BANK.to_owned()))
    );
}

#[test]
fn renaming_the_payments_switch_after_signing_is_detected() {
    let (mut reg, anchors, _) = signed_estate();
    let idx = reg
        .entries
        .iter()
        .position(|e| e.id == "payments-switch")
        .unwrap();
    reg.entries[idx].display_name = "test system".to_owned();
    assert_eq!(
        reg.verify(&anchors),
        Err(RegistryError::PayloadHashMismatch)
    );
}

#[test]
fn downgrading_criticality_after_signing_is_detected() {
    let (mut reg, anchors, _) = signed_estate();
    let idx = reg
        .entries
        .iter()
        .position(|e| e.id == "core-banking-api")
        .unwrap();
    reg.entries[idx].criticality = Criticality::Informational;
    assert_eq!(
        reg.verify(&anchors),
        Err(RegistryError::PayloadHashMismatch)
    );
}

#[test]
fn widening_an_address_range_after_signing_is_detected() {
    let (mut reg, anchors, _) = signed_estate();
    let idx = reg
        .entries
        .iter()
        .position(|e| e.id == "core-banking-api")
        .unwrap();
    reg.entries[idx].addresses = vec![AddressRange::v4([10, 0, 0, 0], 8)];
    assert_eq!(
        reg.verify(&anchors),
        Err(RegistryError::PayloadHashMismatch)
    );
}

#[test]
fn a_registry_signed_by_another_key_under_the_institutions_name_is_refused() {
    let (reg, _, _) = signed_estate();
    let impostor = generate_keypair();
    let anchors = RegistryTrustAnchors::new().trust(BANK, &impostor.public_key);
    assert_eq!(reg.verify(&anchors), Err(RegistryError::SignatureInvalid));
}

#[test]
fn a_signature_naming_a_different_signer_is_refused() {
    let (mut reg, anchors, _) = signed_estate();
    reg.signature.signer_id = "someone-else".to_owned();
    assert_eq!(reg.verify(&anchors), Err(RegistryError::SignerMismatch));
}

#[test]
fn the_registry_round_trips_through_json_and_still_verifies() {
    let (reg, anchors, _) = signed_estate();
    let json = serde_json::to_string(&reg).unwrap();
    let back: ResourceRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reg);
    assert_eq!(back.verify(&anchors), Ok(()));
}

// ─── Well-formedness: the institution cannot sign an ambiguous estate ───

#[test]
fn two_entries_that_could_name_one_endpoint_are_refused_at_signing() {
    let kp = generate_keypair();
    let mut e = estate();
    // A "monitoring" entry whose /24 swallows the payments switch's /28 on
    // an overlapping port range.
    e.push(entry(
        "monitoring",
        Criticality::Informational,
        Protocol::Any,
        &[AddressRange::v4([10, 0, 9, 0], 24)],
        &[PortRange {
            from: 9005,
            to: 9100,
        }],
    ));
    let err = ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, e).unwrap_err();
    assert_eq!(
        err,
        RegistryError::Overlap {
            a: "monitoring".into(),
            b: "payments-switch".into()
        }
    );
}

#[test]
fn overlapping_addresses_on_disjoint_ports_or_protocols_are_not_an_overlap() {
    let kp = generate_keypair();
    let mut e = estate();
    // Same host as core banking, different port: a legitimate second service.
    e.push(entry(
        "core-banking-metrics",
        Criticality::Operational,
        Protocol::Tcp,
        &[AddressRange::v4_host([10, 0, 5, 20])],
        &[PortRange::single(9100)],
    ));
    // Same host and port as core banking but UDP only: distinct too.
    e.push(entry(
        "core-banking-udp-thing",
        Criticality::Operational,
        Protocol::Udp,
        &[AddressRange::v4_host([10, 0, 5, 20])],
        &[PortRange::single(8443)],
    ));
    assert!(ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, e).is_ok());
}

#[test]
fn duplicate_ids_are_refused() {
    let kp = generate_keypair();
    let mut e = estate();
    e.push(entry(
        "core-banking-api",
        Criticality::Informational,
        Protocol::Tcp,
        &[AddressRange::v4_host([10, 0, 5, 99])],
        &[PortRange::single(1)],
    ));
    assert_eq!(
        ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, e).unwrap_err(),
        RegistryError::DuplicateId("core-banking-api".into())
    );
}

#[test]
fn malformed_entries_are_refused_with_the_offending_field_named() {
    let kp = generate_keypair();
    let bad_id = vec![entry(
        "core banking",
        Criticality::Informational,
        Protocol::Tcp,
        &[AddressRange::v4_host([10, 0, 0, 1])],
        &[PortRange::single(1)],
    )];
    assert_eq!(
        ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, bad_id).unwrap_err(),
        RegistryError::BadId("core banking".into())
    );
    let inverted = vec![entry(
        "x",
        Criticality::Informational,
        Protocol::Tcp,
        &[AddressRange::v4_host([10, 0, 0, 1])],
        &[PortRange { from: 10, to: 5 }],
    )];
    assert_eq!(
        ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, inverted).unwrap_err(),
        RegistryError::PortRangeInverted { from: 10, to: 5 }
    );
    let host_bits = vec![entry(
        "y",
        Criticality::Informational,
        Protocol::Tcp,
        &[AddressRange::v4([10, 0, 0, 1], 24)],
        &[PortRange::single(1)],
    )];
    assert_eq!(
        ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, host_bits).unwrap_err(),
        RegistryError::HostBitsSet
    );
    let no_addr = vec![entry(
        "z",
        Criticality::Informational,
        Protocol::Tcp,
        &[],
        &[PortRange::single(1)],
    )];
    assert_eq!(
        ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 1, 0, no_addr).unwrap_err(),
        RegistryError::NoAddresses("z".into())
    );
}

#[test]
fn a_registry_edited_out_of_order_after_signing_fails_well_formedness_first() {
    let (mut reg, anchors, _) = signed_estate();
    reg.entries.reverse();
    assert_eq!(reg.verify(&anchors), Err(RegistryError::EntriesNotSorted));
}

// ─── Resolution: total, deterministic, and honest about the unnamed ───

#[test]
fn endpoints_resolve_to_exactly_one_named_resource() {
    let (reg, anchors, _) = signed_estate();
    reg.verify(&anchors).unwrap();

    match reg.resolve(ObservedProtocol::Tcp, false, &v4([10, 0, 5, 20]), 8443) {
        Resolution::Resource(e) => assert_eq!(e.id, "core-banking-api"),
        other => panic!("{other:?}"),
    }
    // Inside the /28 and the port range.
    match reg.resolve(ObservedProtocol::Tcp, false, &v4([10, 0, 9, 13]), 9007) {
        Resolution::Resource(e) => {
            assert_eq!(e.id, "payments-switch");
            assert_eq!(e.criticality, Criticality::TransactionCritical);
        }
        other => panic!("{other:?}"),
    }
    // Protocol::Any admits both.
    for p in [ObservedProtocol::Tcp, ObservedProtocol::Udp] {
        match reg.resolve(p, false, &v4([10, 0, 20, 200]), 5432) {
            Resolution::Resource(e) => assert_eq!(e.id, "reporting-store"),
            other => panic!("{other:?}"),
        }
    }
    // v6 admin plane.
    let mut v6 = [0u8; 16];
    v6[0] = 0xfd;
    v6[15] = 0x42;
    match reg.resolve(ObservedProtocol::Tcp, true, &v6, 22) {
        Resolution::Resource(e) => assert_eq!(e.id, "admin-plane-v6"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn everything_the_institution_did_not_name_is_unregistered_not_guessed() {
    let (reg, _, _) = signed_estate();
    // Right host, wrong port.
    assert_eq!(
        reg.resolve(ObservedProtocol::Tcp, false, &v4([10, 0, 5, 20]), 443),
        Resolution::Unregistered
    );
    // Right host and port, wrong protocol.
    assert_eq!(
        reg.resolve(ObservedProtocol::Udp, false, &v4([10, 0, 5, 20]), 8443),
        Resolution::Unregistered
    );
    // Just outside the /28.
    assert_eq!(
        reg.resolve(ObservedProtocol::Tcp, false, &v4([10, 0, 9, 16]), 9000),
        Resolution::Unregistered
    );
    // Just outside the port range.
    assert_eq!(
        reg.resolve(ObservedProtocol::Tcp, false, &v4([10, 0, 9, 1]), 9011),
        Resolution::Unregistered
    );
    // A v4 address that happens to equal the low bytes of a v6 entry's
    // network is not a v6 address.
    let mut looks_like = [0u8; 16];
    looks_like[12] = 0xfd;
    assert_eq!(
        reg.resolve(ObservedProtocol::Tcp, false, &looks_like, 22),
        Resolution::Unregistered
    );
    // A v6 address equal to a v4 entry's host bytes is not that v4 host.
    assert_eq!(
        reg.resolve(ObservedProtocol::Tcp, true, &v4([10, 0, 5, 20]), 8443),
        Resolution::Unregistered
    );
    // The public internet.
    assert_eq!(
        reg.resolve(ObservedProtocol::Tcp, false, &v4([203, 0, 113, 9]), 443),
        Resolution::Unregistered
    );
}

#[test]
fn resolution_is_deterministic_across_registry_instances() {
    let (a, _, _) = signed_estate();
    let (b, _, _) = signed_estate();
    for (addr, port) in [
        ([10, 0, 5, 20], 8443),
        ([10, 0, 9, 13], 9007),
        ([1, 1, 1, 1], 53),
    ] {
        let ra = a.resolve(ObservedProtocol::Tcp, false, &v4(addr), port);
        let rb = b.resolve(ObservedProtocol::Tcp, false, &v4(addr), port);
        match (ra, rb) {
            (Resolution::Resource(x), Resolution::Resource(y)) => assert_eq!(x.id, y.id),
            (Resolution::Unregistered, Resolution::Unregistered) => {}
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn the_citation_pins_the_revision_that_resolved_an_endpoint() {
    let kp = generate_keypair();
    let r7 = ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 7, 1_000, estate()).unwrap();
    let mut later = estate();
    let idx = later
        .iter()
        .position(|e| e.id == "core-banking-api")
        .unwrap();
    later[idx].display_name = "core banking (decommissioned)".into();
    let r8 = ResourceRegistry::sign(REGISTRY, BANK, &kp.private_key, 8, 2_000, later).unwrap();
    assert_eq!(r7.citation(), (REGISTRY, 7));
    assert_eq!(r8.citation(), (REGISTRY, 8));
    assert_ne!(r7.signing_preimage(), r8.signing_preimage());
}
