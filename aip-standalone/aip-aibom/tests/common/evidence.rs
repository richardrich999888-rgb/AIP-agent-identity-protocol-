//! Real artifacts from the newer verifiers: a signed access ledger over
//! attested observation and a signed registry, gateway-countersigned tool
//! receipts, and approval-surface artifacts. Each mirrors the producing
//! crate's own test fixture.

#![allow(dead_code)]

use aip_airi::{
    GatewayDisposition, GatewaySigner, GatewayTrustAnchors, SignedToolReceipt, ToolReceipt,
};
use aip_approval::{
    ApprovalArtifact, ApprovalSurfaceAnchors, RenderedForm, SignedApprovalArtifact,
    APPROVAL_ARTIFACT_VERSION,
};
use aip_authorize::ExpectedExecution;
use aip_crypto::{generate_ed25519_keypair, sha256, sign_ed25519};
use aip_ledger::{
    AccessLedger, AccessLedgerBuilder, LedgerSigner, LedgerTrustAnchors, Standing as RowStanding,
    VerdictCitation,
};
use aip_observe::{
    AgentClaim, CollectorSigner, ObservedEffect, ObserverAttestor, ObserverTrustAnchors,
    ProcfsProbe, SocketEndpoint, SocketProtocol, SourceMechanism,
};
use aip_registry::{
    AddressRange, Criticality, PortRange, Protocol, RegistryTrustAnchors, ResourceEntry,
    ResourceRegistry,
};
use aip_types::{CoverageWindow, KeyPair, ScopeAction};

pub const CORE: [u8; 4] = [10, 0, 5, 20];
pub const CORE_PORT: u16 = 8443;
pub const LEDGER_DB: [u8; 4] = [10, 0, 7, 3];
pub const LEDGER_DB_PORT: u16 = 5432;
pub const UNNAMED: [u8; 4] = [203, 0, 113, 9];
pub const T0: u64 = 1_700_000_000_000;
pub const LEDGER_SIGNER: &str = "ledger-1";
pub const GATEWAY: &str = "mcp-gateway-1";
pub const SURFACE: &str = "approvals-ui";
const OBSERVER: &str = "collector-aibom";
const PROBE: &str = "probe-aibom";

fn ep(addr: [u8; 4], port: u16) -> SocketEndpoint {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&addr);
    SocketEndpoint {
        addr: a,
        is_v6: false,
        port,
    }
}

fn entry(id: &str, addr: [u8; 4], port: u16) -> ResourceEntry {
    ResourceEntry {
        id: id.into(),
        display_name: id.into(),
        criticality: Criticality::TransactionCritical,
        protocol: Protocol::Tcp,
        addresses: vec![AddressRange::v4_host(addr)],
        ports: vec![PortRange::single(port)],
    }
}

/// The institution's signed registry: two named resources.
fn registry() -> (ResourceRegistry, RegistryTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let reg = ResourceRegistry::sign(
        "bank/dc1",
        "bank.example",
        &kp.private_key,
        5,
        T0 - 1_000_000,
        vec![
            entry("core-banking-api", CORE, CORE_PORT),
            entry("ledger-db", LEDGER_DB, LEDGER_DB_PORT),
        ],
    )
    .unwrap();
    (
        reg,
        RegistryTrustAnchors::new().trust("bank.example", &kp.public_key),
    )
}

/// A ledger and the key that signed it, so a test can play the ledger signer.
pub struct Ledger {
    pub ledger: AccessLedger,
    pub anchors: LedgerTrustAnchors,
    pub key: KeyPair,
}

/// A signed access ledger for `agent`: socket effects from this test's own
/// process to `remotes`, attested by a real collector, resolved against the
/// signed registry.
pub fn ledger(agent: &str, remotes: &[([u8; 4], u16)]) -> Ledger {
    let (reg, reg_anchors) = registry();
    let kp = generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE, &SourceMechanism::ALL);
    let observer = ObserverTrustAnchors::new().trust(OBSERVER, 1, &kp.public_key);

    let mut probe = ProcfsProbe::new(PROBE);
    let claim = AgentClaim {
        agent_id: agent.into(),
        claim_source: "orchestrator".into(),
        decision_id: Some([7; 16]),
    };
    let me = probe.measure(std::process::id()).unwrap();
    let obs = remotes
        .iter()
        .enumerate()
        .map(|(i, (addr, port))| {
            probe.observation(
                me.clone(),
                ObservedEffect::SocketObserved {
                    protocol: SocketProtocol::Tcp,
                    local: ep([127, 0, 0, 1], 41_000 + i as u16),
                    remote: ep(*addr, *port),
                    state: 0x01,
                    inode: 7_000 + i as u64,
                },
                Some(&claim),
                T0 + 1_000 + i as u64,
            )
        })
        .collect();
    let batch = signer
        .attest_at(probe.batch([1; 16], T0, T0 + 60_000, obs), T0 + 61_000)
        .unwrap();

    let window = CoverageWindow {
        from_ms: T0,
        to_ms: T0 + 60_000,
    };
    let mut b = AccessLedgerBuilder::new(agent, window, &reg, &reg_anchors).unwrap();
    b.observe(&batch, &observer).unwrap();
    let lkp = generate_ed25519_keypair();
    let ls = LedgerSigner::new(LEDGER_SIGNER, 1, &lkp.private_key, &lkp.public_key);
    let ledger = b.build_and_sign(&ls, T0 + 70_000).unwrap();
    Ledger {
        ledger,
        anchors: LedgerTrustAnchors::new().trust(LEDGER_SIGNER, 1, &lkp.public_key),
        key: lkp,
    }
}

impl Ledger {
    /// Mark the row for `port` adverse, as the ledger signer would after
    /// citing an adverse verdict, and re-sign. `AccessLedger::verify`
    /// recomputes each row's standing from its citations, so this cannot be
    /// done by editing the standing alone.
    pub fn with_adverse_row(mut self, port: u16) -> Self {
        let e = self
            .ledger
            .entries
            .iter_mut()
            .find(|e| e.endpoint.port == port)
            .unwrap();
        e.verdicts.push(VerdictCitation {
            decision_id: Some([7; 16]),
            result: 0x02,
            strength: 0x03,
            reason: 0x01,
            reconciler_id: "reconciler-1".into(),
            key_version: 1,
        });
        e.standing = RowStanding::Adverse;
        self.ledger.attestation = sign_ed25519(
            &self.key.private_key,
            LEDGER_SIGNER,
            &self.ledger.signing_preimage(),
        )
        .unwrap();
        self
    }
}

pub struct Gateway {
    pub signer: GatewaySigner,
    pub anchors: GatewayTrustAnchors,
}

pub fn gateway() -> Gateway {
    let kp = generate_ed25519_keypair();
    Gateway {
        signer: GatewaySigner::new(GATEWAY, 1, &kp.private_key).unwrap(),
        anchors: GatewayTrustAnchors::new().trust(GATEWAY, 1, &kp.public_key),
    }
}

impl Gateway {
    pub fn receipt(
        &self,
        agent: &str,
        tool_id: &str,
        disposition: GatewayDisposition,
    ) -> SignedToolReceipt {
        self.signer
            .sign(ToolReceipt {
                version: 0,
                gateway_id: String::new(),
                key_version: 0,
                decision_id: [9; 16],
                agent_id: agent.into(),
                tool_id: tool_id.into(),
                parameter_commitment: aip_airi::parameter_commitment(b"amount=50000"),
                tool_call_id: None,
                disposition,
                response_commitment: None,
                received_at_ms: T0,
            })
            .unwrap()
    }
}

pub struct Surface {
    pub key: KeyPair,
    pub anchors: ApprovalSurfaceAnchors,
}

pub fn surface() -> Surface {
    let key = generate_ed25519_keypair();
    let anchors = ApprovalSurfaceAnchors::new().trust(SURFACE, &key.public_key);
    Surface { key, anchors }
}

impl Surface {
    /// What the surface showed for `ee`: the sealed action and parameters, or
    /// whatever `shown_parameters` substitutes for them.
    pub fn approval(
        &self,
        ee: &ExpectedExecution,
        shown_action: ScopeAction,
        shown_parameters: [u8; 32],
    ) -> SignedApprovalArtifact {
        SignedApprovalArtifact::sign(
            ApprovalArtifact {
                version: APPROVAL_ARTIFACT_VERSION,
                surface_id: SURFACE.into(),
                decision_id: ee.decision_id,
                expectation_digest: sha256(&ee.signing_preimage()),
                shown_digest: sha256(b"Pay INV-2026-0900 for $500.00? [approve]"),
                shown_form: RenderedForm::PlainText,
                shown_action,
                shown_parameter_digest: shown_parameters,
                approver_ref: "cfo-delegate".into(),
                approved_at_ms: T0,
            },
            &self.key.private_key,
        )
        .unwrap()
    }
}
