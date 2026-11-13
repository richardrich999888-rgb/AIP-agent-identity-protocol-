#![cfg(all(feature = "live-distribution-e2e", unix))]

use aip_aibom::{
    canonical::manifest_digest_hex,
    model::{
        AgentIdentity, CryptoPosture, Environment, Governance, Manifest, NetworkPosture,
        Permissions, Relationships, RuntimeKind, Validity, AIBOM_SCHEMA_VERSION,
    },
    seal::{verify_seal, Publisher as AibomPublisher},
};
use aip_core::{capability::issue_scoped_token, create_identity, identity_signing_payload};
use aip_crypto::{
    custody::{Custodian, InMemoryCustodian},
    generate_ed25519_keypair, sha256, sign_ed25519,
};
use aip_distribution::{
    authorization::{
        authorize_package_operation, package_resource_action, PackageOperation, PackageResource,
    },
    create_manifest,
    evidence::{
        correlation_id_for_transfer, DistributionEvidencePayload, DistributionEvidenceRecord,
        EvidenceOperation, EvidenceTimestampKind, StagingOutcome, TransferOutcome,
    },
    manifest_signing_bytes,
    network_protocol::{
        build_swarm, dial_static_peer, AdmittedRequestHandler, DistributionEvent,
        ManagedPeerClient, ManagedPeerServer, ManagedPeerTrust, Request, RequestAuthorization,
        RequestEnvelope, Response, StaticPeer,
    },
    parse_manifest,
    peer_binding::{
        verify_authenticated_peer, PeerBindingIssuerAnchor, PeerBindingStatement,
        PeerBindingTrustAnchors, PeerIdentityStatus, PeerStatusAuthorityAnchor, PeerStatusSnapshot,
    },
    persistent_replay::PersistentReplayGuard,
    revocation_snapshot::{
        verify_revocation_snapshot, RevocationAuthorityAnchor, RevocationSnapshot,
        RevokedCapability,
    },
    verify_manifest, DiskTransferReceiver,
};
use aip_package::{build_package, export_package, sign_package, PackageFile};
use aip_package_cli::offline_verify::{
    verify_offline_distribution_bundle, OfflinePackageEvidence, OfflinePackageTrust,
    OfflineSenderAuthorization, OfflineTransferEvidence,
};
use aip_types::{CapabilityScope, IdentityStatus, ProvenanceTriple, RevocationReason, ScopeAction};
use futures::StreamExt;
use libp2p::{identity, request_response, swarm::SwarmEvent, Multiaddr};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    time::Duration,
};

struct PeerFixture {
    aid: aip_types::AgentIdentityDocument,
    binding: PeerBindingStatement,
    custodian: InMemoryCustodian,
}

fn valid_aibom() -> Manifest {
    Manifest {
        schema_version: AIBOM_SCHEMA_VERSION,
        validity: Validity {
            issued_at_ms: 1,
            valid_until_ms: Some(u64::MAX - 1),
        },
        agent: AgentIdentity {
            id: "aip:network-fixture-receiver".into(),
            name: "Network fixture receiver".into(),
            owner: "test-security".into(),
            version: "1.0.0".into(),
            deployment: "test".into(),
        },
        models: vec![],
        frameworks: vec![],
        tools: vec![],
        permissions: Permissions::default(),
        data_access: vec![],
        environment: Environment {
            runtime: RuntimeKind::Container,
            network: NetworkPosture::Restricted,
            binary: None,
        },
        relationships: Relationships::default(),
        security_controls: vec![],
        crypto: CryptoPosture::default(),
        supply_chain: vec![],
        governance: Governance::default(),
    }
}

struct FixtureTransferHandler {
    manifest_json: Vec<u8>,
    manifest: aip_distribution::TransferManifest,
    chunks: Vec<aip_distribution::TransferChunk>,
    active: bool,
}

impl AdmittedRequestHandler for FixtureTransferHandler {
    fn handle(
        &mut self,
        _peer: &libp2p::PeerId,
        request: &RequestEnvelope,
    ) -> Result<Response, aip_distribution::network_protocol::RejectCode> {
        use aip_distribution::network_protocol::RejectCode;
        Ok(match &request.message {
            Request::Manifest { package_id }
                if package_id
                    == &format!(
                        "{}/{}",
                        self.manifest.publisher_id, self.manifest.package_name
                    )
                    && !self.active =>
            {
                self.active = true;
                Response::Manifest {
                    manifest_json: self.manifest_json.clone(),
                }
            }
            Request::Chunk { transfer_id, index }
                if transfer_id == &self.manifest.transfer_id && self.active =>
            {
                match self.chunks.get(*index as usize) {
                    Some(chunk) if chunk.index == *index => Response::Chunk {
                        transfer_id: transfer_id.clone(),
                        chunk: chunk.clone(),
                    },
                    _ => return Err(RejectCode::NotFound),
                }
            }
            Request::Resume {
                transfer_id,
                manifest_digest,
            } if transfer_id == &self.manifest.transfer_id
                && manifest_digest
                    == &sha256(
                        &manifest_signing_bytes(&self.manifest).expect("manifest bytes"),
                    ) =>
            {
                self.active = true;
                Response::Resumed {
                    transfer_id: transfer_id.clone(),
                    accepted: true,
                }
            }
            Request::TransferStatus { transfer_id }
                if transfer_id == &self.manifest.transfer_id =>
            {
                Response::TransferStatus {
                    transfer_id: transfer_id.clone(),
                    verified_chunks: 0,
                    total_chunks: self.manifest.chunk_count,
                }
            }
            Request::Cancel { transfer_id } if transfer_id == &self.manifest.transfer_id => {
                self.active = false;
                Response::Cancelled {
                    transfer_id: transfer_id.clone(),
                }
            }
            _ => return Err(RejectCode::InvalidRequest),
        })
    }

    fn disconnected(&mut self, _peer: &libp2p::PeerId) {
        self.active = false;
    }
}

fn active_peer(key: &identity::Keypair, issuer: &InMemoryCustodian, now: u64) -> PeerFixture {
    let provenance = ProvenanceTriple {
        model_commitment: sha256(b"model"),
        environment_commitment: sha256(b"environment"),
        toolchain_commitment: sha256(b"toolchain"),
    };
    let (mut aid, aip_key) = create_identity(provenance, None).unwrap();
    aid.status = IdentityStatus::Active;
    aid.sequence = 1;
    aid.self_signature = Some(
        sign_ed25519(
            &aip_key.private_key,
            &aid.id,
            &identity_signing_payload(&aid),
        )
        .unwrap(),
    );
    let binding = PeerBindingStatement::sign(
        &aid,
        key.public().encode_protobuf(),
        "aip:binding-authority",
        now - 100,
        now + 60_000,
        1,
        1,
        "/aip/distribution/1.0.0",
        issuer,
    )
    .unwrap();
    let custodian = InMemoryCustodian::new(&aip_key.private_key, &aip_key.public_key).unwrap();
    PeerFixture {
        aid,
        binding,
        custodian,
    }
}

#[tokio::test]
async fn two_local_peers_transfer_and_independently_verify_signed_package() {
    let publisher = InMemoryCustodian::generate();
    let aibom = valid_aibom();
    let aibom_key = generate_ed25519_keypair();
    let aibom_publisher = AibomPublisher::new(
        "aip:network-aibom-authority",
        &aibom_key.private_key,
        &aibom_key.public_key,
    )
    .unwrap();
    let aibom_seal = aibom_publisher
        .seal(
            &aibom,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        )
        .unwrap();
    let aibom_digest = manifest_digest_hex(&aibom);
    let aibom_trust = BTreeMap::from([(
        "aip:network-aibom-authority".to_string(),
        aibom_key.public_key.clone(),
    )]);
    let package = build_package(
        "network-fixture",
        "1.0.0",
        "aip:network-publisher",
        &aibom_digest,
        vec![PackageFile {
            path: "payload.bin".into(),
            contents: vec![0x5a; aip_distribution::CHUNK_SIZE + 1024],
        }],
    )
    .unwrap();
    let package_sig = sign_package(&package, &publisher).unwrap();
    let export = serde_json::to_vec(&export_package(&package, &package_sig).unwrap()).unwrap();
    let (manifest, chunks) = create_manifest(&export, &publisher).unwrap();
    let manifest_json = serde_json::to_vec(&manifest).unwrap();

    let server_key = identity::Keypair::generate_ed25519();
    let expected_server_peer = server_key.public().to_peer_id();
    let client_key = identity::Keypair::generate_ed25519();
    let expected_client_peer = client_key.public().to_peer_id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let binding_issuer = InMemoryCustodian::generate();
    let status_signer = InMemoryCustodian::generate();
    let client_identity = active_peer(&client_key, &binding_issuer, now);
    let server_identity = active_peer(&server_key, &binding_issuer, now);
    let status = PeerStatusSnapshot::sign(
        "aip:status-authority",
        1,
        now - 100,
        now + 30_000,
        "/aip/distribution/1.0.0",
        BTreeMap::from([
            (
                client_identity.aid.id.clone(),
                PeerIdentityStatus {
                    status: IdentityStatus::Active,
                    aid_sequence: client_identity.aid.sequence,
                    binding_sequence: client_identity.binding.sequence,
                    binding_digest: client_identity.binding.statement_digest().unwrap(),
                },
            ),
            (
                server_identity.aid.id.clone(),
                PeerIdentityStatus {
                    status: IdentityStatus::Active,
                    aid_sequence: server_identity.aid.sequence,
                    binding_sequence: server_identity.binding.sequence,
                    binding_digest: server_identity.binding.statement_digest().unwrap(),
                },
            ),
        ]),
        &status_signer,
    )
    .unwrap();
    let status_anchor =
        PeerStatusAuthorityAnchor::new(status_signer.public_key().to_vec(), 1).unwrap();
    let status_checkpoint = aip_distribution::peer_binding::verify_peer_status_snapshot(
        &status,
        &status_anchor,
        60_000,
        "/aip/distribution/1.0.0",
        now,
    )
    .unwrap();
    let peer_anchors = PeerBindingTrustAnchors::new(
        BTreeMap::from([(
            "aip:binding-authority".into(),
            PeerBindingIssuerAnchor::new(
                binding_issuer.public_key().to_vec(),
                BTreeSet::from([
                    client_identity.aid.id.clone(),
                    server_identity.aid.id.clone(),
                ]),
            )
            .unwrap(),
        )]),
        BTreeMap::from([(
            "aip:status-authority".into(),
            PeerStatusAuthorityAnchor::with_checkpoint(
                status_signer.public_key().to_vec(),
                status_checkpoint,
            )
            .unwrap(),
        )]),
        120_000,
        60_000,
    )
    .unwrap();

    let resource = PackageResource {
        package_id: "aip:network-publisher/network-fixture".into(),
        publisher_id: "aip:network-publisher".into(),
        release_digest: package.archive_sha256,
        recipient_id: client_identity.aid.id.clone(),
    };
    let capability_issuer = generate_ed25519_keypair();
    let capability_issuer_id = "aip:distribution-capability-authority";
    let issue_grant = |subject: &str, operation| {
        issue_scoped_token(
            capability_issuer_id,
            &capability_issuer.private_key,
            subject,
            CapabilityScope {
                allowed: vec![ScopeAction::Custom(package_resource_action(
                    operation, &resource,
                ))],
                denied: vec![],
            },
            Some(60_000),
        )
        .unwrap()
    };
    let receive_grant = issue_grant(&client_identity.aid.id, PackageOperation::Receive);
    let receive_resume_grant = issue_grant(&client_identity.aid.id, PackageOperation::Resume);
    let serve_grant = issue_grant(&server_identity.aid.id, PackageOperation::Serve);
    let serve_resume_grant = issue_grant(&server_identity.aid.id, PackageOperation::ServeResume);
    let install_grant = issue_grant(&client_identity.aid.id, PackageOperation::Stage);
    let authorization_now = now + 1_000;
    let capability_keys =
        HashMap::from([(capability_issuer_id.into(), capability_issuer.public_key)]);

    let revocation_signer = InMemoryCustodian::generate();
    let revocation_snapshot = RevocationSnapshot::sign(
        "aip:revocation-authority",
        1,
        now - 100,
        now + 30_000,
        "/aip/distribution/1.0.0",
        vec![],
        &revocation_signer,
    )
    .unwrap();
    let revocation_anchor = RevocationAuthorityAnchor::new(
        "aip:revocation-authority".into(),
        revocation_signer.public_key().to_vec(),
        1,
        "/aip/distribution/1.0.0".into(),
        60_000,
        60_000,
    )
    .unwrap();
    let revocations = verify_revocation_snapshot(
        &revocation_snapshot,
        Some(&revocation_anchor),
        None,
        "/aip/distribution/1.0.0",
        now,
    )
    .unwrap();

    let reauthorize_receiver = || {
        verify_authenticated_peer(
            &expected_server_peer,
            &server_identity.binding,
            &server_identity.aid,
            &status,
            &peer_anchors,
            "/aip/distribution/1.0.0",
            authorization_now,
            None,
        )
        .map_err(aip_distribution::authorization::AdmissionError::PeerBinding)?;
        authorize_package_operation(
            PackageOperation::Receive,
            &resource,
            &client_identity.aid.id,
            &receive_grant,
            &[],
            &capability_keys,
            &revocations,
            authorization_now,
        )
        .map_err(|e| aip_distribution::authorization::AdmissionError::Operation(e))?;
        Ok::<(), aip_distribution::authorization::AdmissionError>(())
    };
    reauthorize_receiver().unwrap();
    let server = build_swarm(server_key, 1024 * 1024 * 1024).unwrap();
    let mut client = build_swarm(client_key.clone(), 1024 * 1024 * 1024).unwrap();
    let publisher_key = publisher.public_key().to_vec();
    let replay_dir = std::env::temp_dir().join(format!(
        "aip-p2p-replay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&replay_dir).unwrap();
    let replay_path = replay_dir.join("requests.json");
    let mut local_operations = HashMap::new();
    local_operations.insert(PackageOperation::Serve, (serve_grant.clone(), vec![]));
    local_operations.insert(
        PackageOperation::ServeResume,
        (serve_resume_grant.clone(), vec![]),
    );
    let managed_server = ManagedPeerServer::new(
        server,
        HashMap::from([(
            expected_client_peer,
            ManagedPeerTrust {
                aid: client_identity.aid.clone(),
                binding: client_identity.binding.clone(),
                status: status.clone(),
                anchors: peer_anchors.clone(),
            },
        )]),
        "/aip/distribution/1.0.0".into(),
        server_identity.aid.id.clone(),
        local_operations,
        capability_keys.clone(),
        revocations.clone(),
        PersistentReplayGuard::open(&replay_path).unwrap(),
        FixtureTransferHandler {
            manifest_json: manifest_json.clone(),
            manifest: manifest.clone(),
            chunks: chunks.clone(),
            active: false,
        },
    )
    .unwrap();
    let policy_handle = managed_server.policy_handle();
    let mut managed_server = managed_server;
    managed_server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())
        .unwrap();
    let address =
        tokio::time::timeout(Duration::from_secs(5), managed_server.next_listen_address())
            .await
            .expect("server listens")
            .unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(managed_server.run(stop_rx));

    // The managed client refuses an Install-only grant before it can send a
    // request on the wire, even though the peer binding is valid.
    let mut misconfigured_client = ManagedPeerClient::new(
        build_swarm(client_key.clone(), 1024 * 1024 * 1024).unwrap(),
        StaticPeer {
            peer_id: expected_server_peer,
            address: address.clone(),
        },
        ManagedPeerTrust {
            aid: server_identity.aid.clone(),
            binding: server_identity.binding.clone(),
            status: status.clone(),
            anchors: peer_anchors.clone(),
        },
        "/aip/distribution/1.0.0".into(),
        client_identity.aid.id.clone(),
        resource.clone(),
        HashMap::from([
            (PackageOperation::Receive, (install_grant.clone(), vec![])),
            (
                PackageOperation::Resume,
                (receive_resume_grant.clone(), vec![]),
            ),
        ]),
        capability_keys.clone(),
        revocations.clone(),
    )
    .unwrap();
    assert!(misconfigured_client
        .request(
            [0xf0; 16],
            Request::Manifest {
                package_id: "aip:network-publisher/network-fixture".into(),
            },
        )
        .await
        .unwrap_err()
        .contains("local package operation denied"));

    let mut managed_client = ManagedPeerClient::new(
        build_swarm(client_key.clone(), 1024 * 1024 * 1024).unwrap(),
        StaticPeer {
            peer_id: expected_server_peer,
            address: address.clone(),
        },
        ManagedPeerTrust {
            aid: server_identity.aid.clone(),
            binding: server_identity.binding.clone(),
            status: status.clone(),
            anchors: peer_anchors.clone(),
        },
        "/aip/distribution/1.0.0".into(),
        client_identity.aid.id.clone(),
        resource.clone(),
        HashMap::from([
            (PackageOperation::Receive, (receive_grant.clone(), vec![])),
            (
                PackageOperation::Resume,
                (receive_resume_grant.clone(), vec![]),
            ),
        ]),
        capability_keys.clone(),
        revocations.clone(),
    )
    .unwrap();
    managed_client.dial().unwrap();
    let managed_manifest = managed_client
        .request(
            [0xe0; 16],
            Request::Manifest {
                package_id: "aip:network-publisher/network-fixture".into(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        managed_manifest.message,
        Response::Manifest { .. }
    ));
    let managed_cancel = managed_client
        .request(
            [0xe1; 16],
            Request::Cancel {
                transfer_id: manifest.transfer_id.clone(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(managed_cancel.message, Response::Cancelled { .. }));
    managed_client.disconnect();
    drop(managed_client);
    tokio::time::sleep(Duration::from_millis(100)).await;

    dial_static_peer(
        &mut client,
        &StaticPeer {
            peer_id: expected_server_peer,
            address: address.clone(),
        },
    )
    .unwrap();
    let attacker_key = identity::Keypair::generate_ed25519();
    let mut attacker = build_swarm(attacker_key, 1024 * 1024 * 1024).unwrap();
    dial_static_peer(
        &mut attacker,
        &StaticPeer {
            peer_id: expected_server_peer,
            address: address.clone(),
        },
    )
    .unwrap();
    let attacker_request = RequestEnvelope {
        request_id: [0xa1; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: receive_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Manifest {
            package_id: "aip:network-publisher/network-fixture".into(),
        },
    };
    let attacker_outbound_id = attacker
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, attacker_request);
    let attacker_response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = attacker.select_next_some().await
            {
                if peer == expected_server_peer && request_id == attacker_outbound_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("untrusted transport peer rejected");
    assert!(matches!(
        attacker_response.message,
        Response::Reject {
            code: aip_distribution::network_protocol::RejectCode::Unauthorized
        }
    ));
    let attacker_resume = RequestEnvelope {
        request_id: [0xa2; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: receive_resume_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Resume {
            transfer_id: manifest.transfer_id.clone(),
            manifest_digest: sha256(&manifest_signing_bytes(&manifest).unwrap()),
        },
    };
    let attacker_resume_id = attacker
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, attacker_resume);
    let attacker_resume_response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = attacker.select_next_some().await
            {
                if peer == expected_server_peer && request_id == attacker_resume_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("resume from another peer rejected");
    assert!(matches!(
        attacker_resume_response.message,
        Response::Reject {
            code: aip_distribution::network_protocol::RejectCode::Unauthorized
        }
    ));

    let wrong_operation_request = RequestEnvelope {
        request_id: [1; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: install_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Manifest {
            package_id: "aip:network-publisher/network-fixture".into(),
        },
    };
    let denied_id = client
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, wrong_operation_request);
    let denied = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                if peer == expected_server_peer && request_id == denied_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("unauthorized request rejected");
    assert!(matches!(
        denied.message,
        Response::Reject {
            code: aip_distribution::network_protocol::RejectCode::Unauthorized
        }
    ));

    // Reuse the denied request ID: failed authorization must not consume the
    // durable replay slot, while this correctly scoped request is accepted.
    let manifest_request = RequestEnvelope {
        request_id: [1; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: receive_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Manifest {
            package_id: "aip:network-publisher/network-fixture".into(),
        },
    };
    reauthorize_receiver().unwrap();
    let manifest_outbound_id = client
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, manifest_request.clone());
    let received_manifest = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                if peer == expected_server_peer && request_id == manifest_outbound_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("manifest response");
    received_manifest.validate().unwrap();
    assert_eq!(received_manifest.request_id, manifest_request.request_id);
    let received_manifest = match received_manifest.message {
        Response::Manifest { manifest_json } => parse_manifest(&manifest_json).unwrap(),
        other => panic!("unexpected response: {other:?}"),
    };
    verify_manifest(&received_manifest, "aip:network-publisher", &publisher_key).unwrap();

    let cancel = RequestEnvelope {
        request_id: [0x63; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: receive_resume_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Cancel {
            transfer_id: received_manifest.transfer_id.clone(),
        },
    };
    let cancel_id = client
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, cancel);
    let cancel_response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                if peer == expected_server_peer && request_id == cancel_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("cancel response");
    assert!(
        matches!(cancel_response.message, Response::Cancelled { .. }),
        "unexpected cancel result: {:?}",
        cancel_response.message
    );

    // A cancelled transfer can be requested again with a fresh request ID.
    let restart = RequestEnvelope {
        request_id: [0x64; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: receive_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Manifest {
            package_id: "aip:network-publisher/network-fixture".into(),
        },
    };
    let restart_id = client
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, restart);
    let restarted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                if peer == expected_server_peer && request_id == restart_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("new manifest after cancel");
    assert!(matches!(restarted.message, Response::Manifest { .. }));

    // A newer externally verified revocation snapshot is applied while the
    // transfer is active; the next chunk request must be denied immediately.
    let policy_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut revoked_credentials = vec![
        RevokedCapability {
            jti: receive_grant.jti,
            revoked_at_ms: policy_now,
            reason: RevocationReason::AdminRevocation,
            revoked_by: "aip:revocation-authority".into(),
        },
        RevokedCapability {
            jti: receive_resume_grant.jti,
            revoked_at_ms: policy_now,
            reason: RevocationReason::AdminRevocation,
            revoked_by: "aip:revocation-authority".into(),
        },
    ];
    revoked_credentials.sort_by_key(|entry| entry.jti);
    let revoked_snapshot = RevocationSnapshot::sign(
        "aip:revocation-authority",
        2,
        policy_now,
        policy_now + 20_000,
        "/aip/distribution/1.0.0",
        revoked_credentials,
        &revocation_signer,
    )
    .unwrap();
    let verified_revoked = verify_revocation_snapshot(
        &revoked_snapshot,
        Some(&revocation_anchor),
        Some(revocations.checkpoint()),
        "/aip/distribution/1.0.0",
        policy_now,
    )
    .unwrap();
    policy_handle
        .replace_revocations(verified_revoked.clone())
        .unwrap();
    let revoked_chunk = RequestEnvelope {
        request_id: [0x65; 16],
        resource: resource.clone(),
        authorization: RequestAuthorization {
            capability: receive_grant.clone(),
            delegation_chain: vec![],
        },
        message: Request::Chunk {
            transfer_id: received_manifest.transfer_id.clone(),
            index: 0,
        },
    };
    let revoked_chunk_id = client
        .behaviour_mut()
        .requests
        .send_request(&expected_server_peer, revoked_chunk);
    let revoked_response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) = client.select_next_some().await
            {
                if peer == expected_server_peer && request_id == revoked_chunk_id {
                    break response;
                }
            }
        }
    })
    .await
    .expect("revoked transfer request response");
    assert!(matches!(
        revoked_response.message,
        Response::Reject {
            code: aip_distribution::network_protocol::RejectCode::Unauthorized
        }
    ));

    // Verify and publish a later snapshot that removes the transient fixture
    // revocation so the successful transfer path can continue.
    let clear_snapshot = RevocationSnapshot::sign(
        "aip:revocation-authority",
        3,
        policy_now,
        policy_now + 20_000,
        "/aip/distribution/1.0.0",
        vec![],
        &revocation_signer,
    )
    .unwrap();
    let verified_clear = verify_revocation_snapshot(
        &clear_snapshot,
        Some(&revocation_anchor),
        Some(verified_revoked.checkpoint()),
        "/aip/distribution/1.0.0",
        policy_now,
    )
    .unwrap();
    policy_handle.replace_revocations(verified_clear).unwrap();

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "aip-p2p-recv-{}-{nonce}-{}",
        std::process::id(),
        received_manifest.transfer_id
    ));
    let mut receiver = DiskTransferReceiver::create(
        &root,
        received_manifest.clone(),
        "aip:network-publisher",
        &publisher_key,
    )
    .unwrap();
    for index in 0..received_manifest.chunk_count {
        reauthorize_receiver().unwrap();
        let envelope = RequestEnvelope {
            request_id: [(index as u8).wrapping_add(2); 16],
            resource: resource.clone(),
            authorization: RequestAuthorization {
                capability: receive_grant.clone(),
                delegation_chain: vec![],
            },
            message: Request::Chunk {
                transfer_id: received_manifest.transfer_id.clone(),
                index,
            },
        };
        envelope.validate().unwrap();
        let outbound_id = client
            .behaviour_mut()
            .requests
            .send_request(&expected_server_peer, envelope.clone());
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    },
                )) = client.select_next_some().await
                {
                    if peer == expected_server_peer && request_id == outbound_id {
                        break response;
                    }
                }
            }
        })
        .await
        .expect("chunk response");
        response.validate().unwrap();
        assert_eq!(response.request_id, envelope.request_id);
        match response.message {
            Response::Chunk { transfer_id, chunk }
                if transfer_id == received_manifest.transfer_id =>
            {
                receiver.accept(chunk).unwrap()
            }
            other => panic!("unexpected response: {other:?}"),
        }
        if index == 0 && received_manifest.chunk_count > 1 {
            // Persist one verified chunk, drop the receiver and connection,
            // then reopen the disk journal as a restarted receiver.
            drop(receiver);
            client.disconnect_peer_id(expected_server_peer).ok();
            drop(client);
            let resumed =
                DiskTransferReceiver::resume(&root, "aip:network-publisher", &publisher_key)
                    .unwrap();
            assert_eq!(resumed.completed_chunks(), 1);

            client = build_swarm(client_key.clone(), 1024 * 1024 * 1024).unwrap();
            dial_static_peer(
                &mut client,
                &StaticPeer {
                    peer_id: expected_server_peer,
                    address: address.clone(),
                },
            )
            .unwrap();
            reauthorize_receiver().unwrap();
            let resume = RequestEnvelope {
                request_id: [0x71; 16],
                resource: resource.clone(),
                authorization: RequestAuthorization {
                    capability: receive_resume_grant.clone(),
                    delegation_chain: vec![],
                },
                message: Request::Resume {
                    transfer_id: received_manifest.transfer_id.clone(),
                    manifest_digest: sha256(&manifest_signing_bytes(&received_manifest).unwrap()),
                },
            };
            let outbound_id = client
                .behaviour_mut()
                .requests
                .send_request(&expected_server_peer, resume.clone());
            let resume_response = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                        request_response::Event::Message {
                            peer,
                            message:
                                request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                            ..
                        },
                    )) = client.select_next_some().await
                    {
                        if peer == expected_server_peer && request_id == outbound_id {
                            break response;
                        }
                    }
                }
            })
            .await
            .expect("resume response");
            resume_response.validate().unwrap();
            assert_eq!(resume_response.request_id, resume.request_id);
            assert!(matches!(
                resume_response.message,
                Response::Resumed { accepted: true, .. }
            ));
            receiver = resumed;
        }
    }
    let verified = receiver
        .finalize("aip:network-publisher", &publisher_key, &aibom_digest)
        .unwrap();
    assert_eq!(verified.manifest().name, "network-fixture");
    assert_eq!(verified.files().len(), 1);
    authorize_package_operation(
        PackageOperation::Stage,
        &resource,
        &client_identity.aid.id,
        &install_grant,
        &[],
        &capability_keys,
        &revocations,
        authorization_now,
    )
    .unwrap();
    let install_root = root.with_extension("install");
    std::fs::create_dir(&install_root).unwrap();
    let staged = aip_install::stage_verified_package(&install_root, &verified).unwrap();
    let staged_file = install_root.join(staged.stage_name()).join("payload.bin");
    assert_eq!(
        std::fs::read(staged_file).unwrap(),
        vec![0x5a; aip_distribution::CHUNK_SIZE + 1024]
    );
    verify_seal(&aibom_seal, &aibom, &aibom_trust).unwrap();
    let receiver_staged_digest = staged.staged_artifact_digest();
    assert_eq!(
        receiver_staged_digest,
        aip_install::expected_staged_artifact_digest(&verified)
    );
    let transfer_manifest_digest = sha256(&manifest_signing_bytes(&manifest).unwrap());
    let aibom_manifest_digest: [u8; 32] = hex::decode(&aibom_digest).unwrap().try_into().unwrap();
    let aibom_seal_digest = sha256(&serde_json::to_vec(&aibom_seal).unwrap());
    let evidence = DistributionEvidenceRecord::sign(
        DistributionEvidencePayload {
            version: 1,
            correlation_id: correlation_id_for_transfer(&manifest.transfer_id).unwrap(),
            sender_aid_id: server_identity.aid.id.clone(),
            receiver_aid_id: client_identity.aid.id.clone(),
            sender_peer_id: expected_server_peer.to_string(),
            receiver_peer_id: expected_client_peer.to_string(),
            sender_binding_digest: server_identity.binding.statement_digest().unwrap(),
            receiver_binding_digest: client_identity.binding.statement_digest().unwrap(),
            package_export_digest: sha256(&export),
            package_archive_digest: *verified.archive_sha256(),
            package_manifest_digest: *verified.manifest_sha256(),
            transfer_manifest_digest,
            aibom_manifest_digest,
            aibom_seal_digest,
            aibom_seal_verified: true,
            authorization_operations: vec![
                EvidenceOperation::Serve,
                EvidenceOperation::Receive,
                EvidenceOperation::Resume,
                EvidenceOperation::ServeResume,
                EvidenceOperation::Stage,
            ],
            transfer_outcome: TransferOutcome::Completed,
            resume_count: 1,
            cancellation_count: 1,
            staging_outcome: StagingOutcome::Staged,
            staged_artifact_digest: Some(receiver_staged_digest),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            timestamp_kind: EvidenceTimestampKind::LocalSystemClock,
            signer_aid_id: client_identity.aid.id.clone(),
        },
        &client_identity.custodian,
    )
    .unwrap();
    let exported_evidence_bundle = evidence.to_json().unwrap();
    let imported_evidence =
        DistributionEvidenceRecord::from_json(&exported_evidence_bundle).unwrap();
    imported_evidence
        .verify(&client_identity.aid.primary_key.key_bytes)
        .unwrap();

    // Feed the exact exported receiver record and actual transferred chunks
    // through the independent offline verifier, using external anchors.
    let offline_package_evidence = OfflinePackageEvidence {
        export_bytes: &export,
        aibom_manifest: &aibom,
        aibom_seal: &aibom_seal,
        aid: &client_identity.aid,
        peer_binding: &client_identity.binding,
        peer_status: &status,
        capability: &receive_grant,
        delegation_chain: &[],
        revocation_snapshot: &revocation_snapshot,
        transfer: Some(OfflineTransferEvidence {
            manifest: &manifest,
            chunks: &chunks,
        }),
    };
    let offline_package_trust = OfflinePackageTrust {
        publisher_id: "aip:network-publisher",
        publisher_public_key: &publisher_key,
        aibom_publishers: &aibom_trust,
        peer_binding_anchors: &peer_anchors,
        capability_issuer_keys: &capability_keys,
        revocation_authority: Some(&revocation_anchor),
        revocation_checkpoint: revocations.checkpoint(),
        expected_audience: "/aip/distribution/1.0.0",
        recipient_id: &client_identity.aid.id,
        operation: PackageOperation::Receive,
        now_ms: authorization_now,
    };
    let offline_sender = OfflineSenderAuthorization {
        aid: &server_identity.aid,
        peer_binding: &server_identity.binding,
        peer_status: &status,
        serve_capability: &serve_grant,
        serve_delegation_chain: &[],
        serve_resume_capability: Some(&serve_resume_grant),
        serve_resume_delegation_chain: &[],
    };
    let offline_report = verify_offline_distribution_bundle(
        &offline_package_evidence,
        &offline_package_trust,
        &offline_sender,
        &install_grant,
        &[],
        Some(&receive_resume_grant),
        &[],
        &imported_evidence,
    )
    .unwrap();
    assert_eq!(offline_report.status, "INPUTS_VERIFIED");
    assert_eq!(offline_report.staging_outcome, "STAGED_REPORTED");
    assert_eq!(offline_report.execution_status, "NOT_EVALUATED");

    let mut tampered_evidence = imported_evidence.clone();
    tampered_evidence.payload.package_export_digest[0] ^= 1;
    assert!(verify_offline_distribution_bundle(
        &offline_package_evidence,
        &offline_package_trust,
        &offline_sender,
        &install_grant,
        &[],
        Some(&receive_resume_grant),
        &[],
        &tampered_evidence,
    )
    .is_err());
    drop(staged);
    std::fs::remove_dir_all(&install_root).unwrap();
    stop_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
    std::fs::remove_dir_all(replay_dir).unwrap();
    std::fs::remove_dir_all(PathBuf::from(root)).unwrap();
}
