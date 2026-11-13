//! Bounded, transport-neutral AIP Distribution request/response messages.
//!
//! The codec correlation ID is not authorization. Callers must bind each
//! inbound request to the authenticated connection peer and run the peer and
//! operation-specific policy checks before serving or accepting data.

use crate::{
    authorization::PackageResource,
    peer_binding::{PeerBindingStatement, PeerBindingTrustAnchors, PeerStatusSnapshot},
    revocation_snapshot::VerifiedRevocationSnapshot,
};
use aip_core::SignatureVerifier;
use aip_types::{AgentIdentityDocument, DelegationToken, ScopedToken};
use libp2p::{identity, noise, tcp, yamux, PeerId, Swarm, SwarmBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    error::Error,
    io,
    time::{Duration, Instant},
};

pub const DISTRIBUTION_PROTOCOL: &str = "/aip/distribution/1.0.0";
pub const MAX_REQUEST_BYTES: u64 = 16 * 1024;
pub const MAX_RESPONSE_BYTES: u64 = 300 * 1024;
pub const MAX_IN_FLIGHT_GLOBAL: usize = 128;
pub const MAX_IN_FLIGHT_PER_PEER: usize = 8;
pub const MAX_TRANSFERS_GLOBAL: usize = 32;
pub const MAX_TRANSFERS_PER_PEER: usize = 4;
pub const REPLAY_WINDOW_PER_PEER: usize = 4096;
pub const MAX_TRACKED_PEERS: usize = 1024;
pub const MAX_REQUESTS_PER_MINUTE_PER_PEER: usize = 600;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub request_id: [u8; 16],
    pub resource: PackageResource,
    pub authorization: RequestAuthorization,
    pub message: Request,
}

/// Signed capability evidence carried with an application request. Issuer
/// trust and current revocation state are always resolved locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAuthorization {
    pub capability: ScopedToken,
    pub delegation_chain: Vec<DelegationToken>,
}

impl RequestEnvelope {
    pub fn validate(&self) -> Result<(), AdmissionError> {
        if self.request_id == [0; 16] {
            return Err(AdmissionError::EmptyRequestId);
        }
        for value in [
            self.resource.package_id.as_str(),
            self.resource.publisher_id.as_str(),
            self.resource.recipient_id.as_str(),
        ] {
            validate_text(value, 256)?;
        }
        match &self.message {
            Request::Manifest { package_id } => {
                validate_text(package_id, 256)?;
                if package_id != &self.resource.package_id {
                    return Err(AdmissionError::MalformedMessage);
                }
                Ok(())
            }
            Request::Chunk { transfer_id, .. }
            | Request::TransferStatus { transfer_id }
            | Request::Cancel { transfer_id }
            | Request::Resume { transfer_id, .. } => validate_digest(transfer_id),
        }
    }
}

/// The only supported application admission entry point for inbound
/// requests. Callers resolve `trusted_aid`, binding, status and anchors from
/// local inventory before invoking it; none are accepted from the wire.
#[allow(clippy::too_many_arguments)]
pub fn authorize_inbound_request(
    authenticated_peer: &PeerId,
    trusted_aid: &AgentIdentityDocument,
    trusted_binding: &PeerBindingStatement,
    trusted_status: &PeerStatusSnapshot,
    peer_anchors: &PeerBindingTrustAnchors,
    audience: &str,
    signature_verifier: Option<&dyn SignatureVerifier>,
    request: &RequestEnvelope,
    local_identity_id: &str,
    local_operation_capability: &ScopedToken,
    local_operation_delegations: &[DelegationToken],
    capability_issuer_keys: &HashMap<String, Vec<u8>>,
    revocations: &VerifiedRevocationSnapshot,
    now_ms: u64,
) -> Result<(), crate::authorization::AdmissionError> {
    request.validate().map_err(|error| {
        crate::authorization::AdmissionError::Operation(
            crate::authorization::AuthorizationError::Invalid(format!("request: {error:?}")),
        )
    })?;
    let (remote_operation, local_operation) = match &request.message {
        Request::Manifest { .. } | Request::Chunk { .. } => (
            crate::authorization::PackageOperation::Receive,
            crate::authorization::PackageOperation::Serve,
        ),
        Request::TransferStatus { .. } | Request::Resume { .. } | Request::Cancel { .. } => (
            crate::authorization::PackageOperation::Resume,
            crate::authorization::PackageOperation::ServeResume,
        ),
    };
    crate::authorization::authorize_authenticated_peer_operation(
        authenticated_peer,
        trusted_binding,
        trusted_aid,
        trusted_status,
        peer_anchors,
        audience,
        signature_verifier,
        remote_operation,
        &request.resource,
        &request.authorization.capability,
        &request.authorization.delegation_chain,
        capability_issuer_keys,
        revocations,
        now_ms,
    )?;
    crate::authorization::authorize_package_operation(
        local_operation,
        &request.resource,
        local_identity_id,
        local_operation_capability,
        local_operation_delegations,
        capability_issuer_keys,
        revocations,
        now_ms,
    )
    .map_err(crate::authorization::AdmissionError::Operation)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Request {
    Manifest {
        package_id: String,
    },
    Chunk {
        transfer_id: String,
        index: u32,
    },
    TransferStatus {
        transfer_id: String,
    },
    Resume {
        transfer_id: String,
        manifest_digest: [u8; 32],
    },
    Cancel {
        transfer_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    pub request_id: [u8; 16],
    pub message: Response,
}

impl ResponseEnvelope {
    pub fn validate(&self) -> Result<(), AdmissionError> {
        if self.request_id == [0; 16] {
            return Err(AdmissionError::EmptyRequestId);
        }
        match &self.message {
            Response::Manifest { manifest_json } => {
                if manifest_json.is_empty() || manifest_json.len() > crate::MAX_MANIFEST_JSON_BYTES
                {
                    return Err(AdmissionError::MalformedMessage);
                }
                crate::parse_manifest(manifest_json)
                    .map_err(|_| AdmissionError::MalformedMessage)?;
            }
            Response::Chunk { transfer_id, chunk } => {
                validate_digest(transfer_id)?;
                if chunk.bytes.is_empty()
                    || chunk.bytes.len() > crate::CHUNK_SIZE
                    || chunk.proof.len() > 32
                {
                    return Err(AdmissionError::MalformedMessage);
                }
            }
            Response::TransferStatus { transfer_id, .. }
            | Response::Resumed { transfer_id, .. }
            | Response::Cancelled { transfer_id } => validate_digest(transfer_id)?,
            Response::Reject { .. } => {}
        }
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), AdmissionError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(AdmissionError::MalformedMessage);
    }
    Ok(())
}

fn validate_text(value: &str, max: usize) -> Result<(), AdmissionError> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(AdmissionError::MalformedMessage);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Response {
    Manifest {
        manifest_json: Vec<u8>,
    },
    Chunk {
        transfer_id: String,
        chunk: crate::TransferChunk,
    },
    TransferStatus {
        transfer_id: String,
        verified_chunks: u32,
        total_chunks: u32,
    },
    Resumed {
        transfer_id: String,
        accepted: bool,
    },
    Cancelled {
        transfer_id: String,
    },
    Reject {
        code: RejectCode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectCode {
    Unauthorized,
    NotFound,
    InvalidRequest,
    RateLimited,
    Busy,
    TransferUnavailable,
    Internal,
}

#[derive(Clone, Default)]
pub struct BoundedCborCodec;

impl libp2p::request_response::Codec for BoundedCborCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = RequestEnvelope;
    type Response = ResponseEnvelope;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: futures::io::AsyncRead + Unpin + Send,
    {
        read_cbor_bounded(io, MAX_REQUEST_BYTES).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::io::AsyncRead + Unpin + Send,
    {
        read_cbor_bounded(io, MAX_RESPONSE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::io::AsyncWrite + Unpin + Send,
    {
        write_cbor_bounded(io, &request, MAX_REQUEST_BYTES).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::io::AsyncWrite + Unpin + Send,
    {
        write_cbor_bounded(io, &response, MAX_RESPONSE_BYTES).await
    }
}

async fn read_cbor_bounded<T, IO>(io: &mut IO, maximum: u64) -> io::Result<T>
where
    T: DeserializeOwned + Send,
    IO: futures::io::AsyncRead + Unpin + Send,
{
    use futures::io::AsyncReadExt;
    let mut bytes = Vec::new();
    io.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CBOR message exceeds configured byte limit",
        ));
    }
    cbor4ii::serde::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

async fn write_cbor_bounded<T, IO>(io: &mut IO, value: &T, maximum: u64) -> io::Result<()>
where
    T: Serialize + Send + Sync,
    IO: futures::io::AsyncWrite + Unpin + Send,
{
    use futures::io::AsyncWriteExt;
    let bytes = cbor4ii::serde::to_vec(Vec::new(), value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CBOR message exceeds configured byte limit",
        ));
    }
    io.write_all(&bytes).await
}

pub type CborBehaviour = libp2p::request_response::Behaviour<BoundedCborCodec>;

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "DistributionEvent")]
pub struct DistributionBehaviour {
    pub requests: CborBehaviour,
    pub connection_limits: libp2p::connection_limits::Behaviour,
    pub memory_limits: libp2p::memory_connection_limits::Behaviour,
}

#[derive(Debug)]
pub enum DistributionEvent {
    RequestResponse(libp2p::request_response::Event<RequestEnvelope, ResponseEnvelope>),
}

impl From<libp2p::request_response::Event<RequestEnvelope, ResponseEnvelope>>
    for DistributionEvent
{
    fn from(event: libp2p::request_response::Event<RequestEnvelope, ResponseEnvelope>) -> Self {
        Self::RequestResponse(event)
    }
}

impl From<Infallible> for DistributionEvent {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

pub type DistributionSwarm = Swarm<DistributionBehaviour>;

/// Build the TCP/Noise/Yamux swarm. This function is only compiled with the
/// explicit `live-noise` feature; enabling that feature is not cryptographic
/// provider approval. It performs no public discovery or bootstrap.
pub fn build_swarm(
    identity: identity::Keypair,
    max_process_memory_bytes: usize,
) -> Result<DistributionSwarm, Box<dyn Error + Send + Sync>> {
    if max_process_memory_bytes == 0 {
        return Err("process memory ceiling must be nonzero".into());
    }
    let builder = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("failed to construct TCP/Noise transport: {e}"))?;
    let builder = builder
        .with_behaviour(|_| DistributionBehaviour {
            requests: cbor_behaviour(),
            connection_limits: libp2p::connection_limits::Behaviour::new(
                libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(32))
                    .with_max_pending_outgoing(Some(32))
                    .with_max_established(Some(64))
                    .with_max_established_per_peer(Some(2)),
            ),
            memory_limits: libp2p::memory_connection_limits::Behaviour::with_max_bytes(
                max_process_memory_bytes,
            ),
        })
        .map_err(|e| format!("failed to construct distribution behaviour: {e}"))?;
    Ok(builder
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

/// Static-only dialing input. No address learned from identify or a remote
/// request is promoted to a dial target by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPeer {
    pub peer_id: PeerId,
    pub address: libp2p::Multiaddr,
}

pub fn dial_static_peer(swarm: &mut DistributionSwarm, peer: &StaticPeer) -> Result<(), String> {
    if peer.address.iter().any(
        |protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2p(id) if id != peer.peer_id),
    ) {
        return Err("static address embeds a different PeerId".into());
    }
    swarm.add_peer_address(peer.peer_id, peer.address.clone());
    swarm
        .dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(peer.peer_id)
                .addresses(vec![peer.address.clone()])
                .build(),
        )
        .map_err(|error| format!("static peer dial failed: {error}"))
}

/// Trusted identity and local policy for one statically admitted remote peer.
/// Populate this only from locally provisioned trust data, never from the wire.
#[cfg(unix)]
#[derive(Clone)]
pub struct ManagedPeerTrust {
    pub aid: AgentIdentityDocument,
    pub binding: PeerBindingStatement,
    pub status: PeerStatusSnapshot,
    pub anchors: PeerBindingTrustAnchors,
}

/// Synchronous application dispatcher. It is called only after envelope,
/// peer binding, status, both operation capabilities, revocation state, and
/// durable replay checks have succeeded.
#[cfg(unix)]
pub trait AdmittedRequestHandler: Send {
    fn handle(&mut self, peer: &PeerId, request: &RequestEnvelope) -> Result<Response, RejectCode>;

    fn disconnected(&mut self, _peer: &PeerId) {}
}

/// Managed inbound server. Unlike using `DistributionSwarm` directly, this
/// owns the mandatory admission and replay sequence and exposes no response
/// channel to application code.
#[cfg(unix)]
pub struct ManagedPeerServer<H> {
    swarm: DistributionSwarm,
    trust: HashMap<PeerId, ManagedPeerTrust>,
    audience: String,
    local_identity_id: String,
    local_operations:
        HashMap<crate::authorization::PackageOperation, (ScopedToken, Vec<DelegationToken>)>,
    capability_issuer_keys: HashMap<String, Vec<u8>>,
    revocations: std::sync::Arc<std::sync::RwLock<VerifiedRevocationSnapshot>>,
    replay: crate::persistent_replay::PersistentReplayGuard,
    admission: RequestAdmission,
    expected_chunks_by_peer: HashMap<PeerId, u32>,
    handler: H,
}

/// Cloneable live policy handle. A caller may install only a snapshot already
/// verified against its external authority and checkpoint. Each new request
/// observes the latest value; poisoned policy state fails closed.
#[cfg(unix)]
#[derive(Clone)]
pub struct ManagedPeerPolicyHandle {
    revocations: std::sync::Arc<std::sync::RwLock<VerifiedRevocationSnapshot>>,
}

#[cfg(unix)]
impl ManagedPeerPolicyHandle {
    pub fn replace_revocations(&self, snapshot: VerifiedRevocationSnapshot) -> Result<(), ()> {
        let mut guard = self.revocations.write().map_err(|_| ())?;
        let current = guard.checkpoint();
        let next = snapshot.checkpoint();
        if snapshot.issuer_id() != guard.issuer_id()
            || snapshot.audience() != guard.audience()
            || next.epoch < current.epoch
            || (next.epoch == current.epoch && next.digest != current.digest)
        {
            return Err(());
        }
        *guard = snapshot;
        Ok(())
    }
}

#[cfg(unix)]
impl<H: AdmittedRequestHandler> ManagedPeerServer<H> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        swarm: DistributionSwarm,
        trust: HashMap<PeerId, ManagedPeerTrust>,
        audience: String,
        local_identity_id: String,
        local_operations: HashMap<
            crate::authorization::PackageOperation,
            (ScopedToken, Vec<DelegationToken>),
        >,
        capability_issuer_keys: HashMap<String, Vec<u8>>,
        revocations: VerifiedRevocationSnapshot,
        replay: crate::persistent_replay::PersistentReplayGuard,
        handler: H,
    ) -> Result<Self, &'static str> {
        use crate::authorization::PackageOperation;
        if audience.trim().is_empty() || local_identity_id.trim().is_empty() {
            return Err("managed server requires an audience and local AIP identity");
        }
        for operation in [PackageOperation::Serve, PackageOperation::ServeResume] {
            if !local_operations.contains_key(&operation) {
                return Err("managed server requires local Serve and ServeResume grants");
            }
        }
        Ok(Self {
            swarm,
            trust,
            audience,
            local_identity_id,
            local_operations,
            capability_issuer_keys,
            revocations: std::sync::Arc::new(std::sync::RwLock::new(revocations)),
            replay,
            admission: RequestAdmission::default(),
            expected_chunks_by_peer: HashMap::new(),
            handler,
        })
    }

    pub fn listen_on(&mut self, address: libp2p::Multiaddr) -> Result<(), String> {
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Wait until a listener has bound and return its actual address. Call
    /// before spawning `run` when the configured address uses port zero.
    pub async fn next_listen_address(&mut self) -> Result<libp2p::Multiaddr, String> {
        use futures::StreamExt;
        loop {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
                self.swarm.select_next_some().await
            {
                return Ok(address);
            }
        }
    }

    pub fn dial_static(&mut self, peer: &StaticPeer) -> Result<(), String> {
        dial_static_peer(&mut self.swarm, peer)
    }

    pub fn policy_handle(&self) -> ManagedPeerPolicyHandle {
        ManagedPeerPolicyHandle {
            revocations: self.revocations.clone(),
        }
    }

    /// Run until the supplied oneshot is cancelled. Every inbound request is
    /// authorized and durably replay-recorded before application dispatch.
    pub async fn run(mut self, mut stop: tokio::sync::oneshot::Receiver<()>) -> Result<H, String> {
        use futures::StreamExt;
        loop {
            tokio::select! {
                _ = &mut stop => {
                    for peer in self.trust.keys() {
                        let _ = self.swarm.disconnect_peer_id(*peer);
                    }
                    return Ok(self.handler);
                }
                event = self.swarm.select_next_some() => {
                    match event {
                        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            self.admission.disconnected(&peer_id);
                            self.handler.disconnected(&peer_id);
                        }
                        libp2p::swarm::SwarmEvent::ListenerError { error, .. } => {
                            return Err(format!("distribution listener failed: {error}"));
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                            libp2p::request_response::Event::Message {
                                peer,
                                message: libp2p::request_response::Message::Request { request, channel, .. },
                                ..
                            }
                        )) => {
                            let message = self.admit_and_dispatch(peer, &request);
                            let response = ResponseEnvelope { request_id: request.request_id, message };
                            if self.swarm.behaviour_mut().requests.send_response(channel, response).is_err() {
                                return Err("request response channel closed".into());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn admit_and_dispatch(&mut self, peer: PeerId, request: &RequestEnvelope) -> Response {
        use crate::authorization::PackageOperation;
        let Some(peer_trust) = self.trust.get(&peer) else {
            return Response::Reject {
                code: RejectCode::Unauthorized,
            };
        };
        let local_operation = match &request.message {
            Request::Manifest { .. } | Request::Chunk { .. } => PackageOperation::Serve,
            _ => PackageOperation::ServeResume,
        };
        let Some((local_capability, local_delegations)) =
            self.local_operations.get(&local_operation)
        else {
            return Response::Reject {
                code: RejectCode::Unauthorized,
            };
        };
        let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_millis().try_into().unwrap_or(u64::MAX),
            Err(_) => {
                return Response::Reject {
                    code: RejectCode::Internal,
                }
            }
        };
        let revocations = match self.revocations.read() {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return Response::Reject {
                    code: RejectCode::Internal,
                }
            }
        };
        if authorize_inbound_request(
            &peer,
            &peer_trust.aid,
            &peer_trust.binding,
            &peer_trust.status,
            &peer_trust.anchors,
            &self.audience,
            None,
            request,
            &self.local_identity_id,
            local_capability,
            local_delegations,
            &self.capability_issuer_keys,
            &revocations,
            now_ms,
        )
        .is_err()
        {
            return Response::Reject {
                code: RejectCode::Unauthorized,
            };
        }
        if self
            .admission
            .begin_durable(&mut self.replay, peer, request.request_id, now_ms)
            .is_err()
        {
            return Response::Reject {
                code: RejectCode::RateLimited,
            };
        }
        let starts_transfer = matches!(
            &request.message,
            Request::Manifest { .. } | Request::Resume { .. }
        );
        if starts_transfer && self.admission.begin_transfer(peer).is_err() {
            self.admission.finish(&peer);
            return Response::Reject {
                code: RejectCode::Busy,
            };
        }
        let result = self.handler.handle(&peer, request);
        self.admission.finish(&peer);
        match result {
            Ok(response) => {
                if let Response::Manifest { manifest_json } = &response {
                    if let Ok(manifest) = crate::parse_manifest(manifest_json) {
                        self.expected_chunks_by_peer
                            .insert(peer, manifest.chunk_count);
                    }
                }
                let transfer_complete = match &response {
                    Response::Cancelled { .. } => true,
                    Response::Resumed { accepted, .. } => !accepted,
                    Response::TransferStatus {
                        verified_chunks,
                        total_chunks,
                        ..
                    } => verified_chunks >= total_chunks,
                    _ => false,
                };
                let last_chunk = match (&request.message, &response) {
                    (Request::Chunk { index, .. }, Response::Chunk { chunk, .. }) => self
                        .expected_chunks_by_peer
                        .get(&peer)
                        .is_some_and(|total| {
                            chunk.index == *index && index.checked_add(1) == Some(*total)
                        }),
                    _ => false,
                };
                if starts_transfer && matches!(&response, Response::Reject { .. }) {
                    self.admission.finish_transfer(&peer);
                }
                if transfer_complete || last_chunk {
                    self.admission.finish_transfer(&peer);
                }
                let clear_transfer = match &response {
                    Response::Cancelled { .. } => true,
                    Response::TransferStatus {
                        verified_chunks,
                        total_chunks,
                        ..
                    } => verified_chunks >= total_chunks,
                    _ => false,
                };
                if clear_transfer {
                    self.expected_chunks_by_peer.remove(&peer);
                }
                response
            }
            Err(code) => {
                if starts_transfer {
                    self.admission.finish_transfer(&peer);
                }
                Response::Reject { code }
            }
        }
    }
}

/// Managed outbound request client. It binds the configured static PeerId to
/// externally trusted AIP evidence and checks local Receive/Resume authority
/// before sending. It validates both the transport peer and response request
/// correlation before returning application data.
#[cfg(unix)]
pub struct ManagedPeerClient {
    swarm: DistributionSwarm,
    peer: StaticPeer,
    remote: ManagedPeerTrust,
    audience: String,
    local_identity_id: String,
    resource: PackageResource,
    local_operations:
        HashMap<crate::authorization::PackageOperation, (ScopedToken, Vec<DelegationToken>)>,
    capability_issuer_keys: HashMap<String, Vec<u8>>,
    revocations: VerifiedRevocationSnapshot,
}

#[cfg(unix)]
impl ManagedPeerClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        swarm: DistributionSwarm,
        peer: StaticPeer,
        remote: ManagedPeerTrust,
        audience: String,
        local_identity_id: String,
        resource: PackageResource,
        local_operations: HashMap<
            crate::authorization::PackageOperation,
            (ScopedToken, Vec<DelegationToken>),
        >,
        capability_issuer_keys: HashMap<String, Vec<u8>>,
        revocations: VerifiedRevocationSnapshot,
    ) -> Result<Self, &'static str> {
        use crate::authorization::PackageOperation;
        if audience.trim().is_empty() || local_identity_id.trim().is_empty() {
            return Err("managed client requires audience and local AIP identity");
        }
        for operation in [PackageOperation::Receive, PackageOperation::Resume] {
            if !local_operations.contains_key(&operation) {
                return Err("managed client requires local Receive and Resume grants");
            }
        }
        Ok(Self {
            swarm,
            peer,
            remote,
            audience,
            local_identity_id,
            resource,
            local_operations,
            capability_issuer_keys,
            revocations,
        })
    }

    pub fn dial(&mut self) -> Result<(), String> {
        dial_static_peer(&mut self.swarm, &self.peer)
    }

    pub fn disconnect(&mut self) {
        let _ = self.swarm.disconnect_peer_id(self.peer.peer_id);
    }

    pub async fn request(
        &mut self,
        request_id: [u8; 16],
        message: Request,
    ) -> Result<ResponseEnvelope, String> {
        use crate::authorization::{authorize_package_operation, PackageOperation};
        use futures::StreamExt;
        if request_id == [0; 16] {
            return Err("zero request ID is invalid".into());
        }
        let operation = match &message {
            Request::Manifest { .. } | Request::Chunk { .. } => PackageOperation::Receive,
            _ => PackageOperation::Resume,
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis()
            .try_into()
            .map_err(|_| "system time exceeds u64 milliseconds")?;
        crate::peer_binding::verify_authenticated_peer(
            &self.peer.peer_id,
            &self.remote.binding,
            &self.remote.aid,
            &self.remote.status,
            &self.remote.anchors,
            &self.audience,
            now_ms,
            None,
        )
        .map_err(|error| format!("remote AIP peer verification failed: {error}"))?;
        let (capability, delegation_chain) = self
            .local_operations
            .get(&operation)
            .ok_or_else(|| "missing local operation capability".to_string())?;
        authorize_package_operation(
            operation,
            &self.resource,
            &self.local_identity_id,
            capability,
            delegation_chain,
            &self.capability_issuer_keys,
            &self.revocations,
            now_ms,
        )
        .map_err(|error| format!("local package operation denied: {error}"))?;
        let request_message = message.clone();
        let envelope = RequestEnvelope {
            request_id,
            resource: self.resource.clone(),
            authorization: RequestAuthorization {
                capability: capability.clone(),
                delegation_chain: delegation_chain.clone(),
            },
            message,
        };
        envelope
            .validate()
            .map_err(|error| format!("invalid request: {error:?}"))?;
        let outbound_id = self
            .swarm
            .behaviour_mut()
            .requests
            .send_request(&self.peer.peer_id, envelope);
        loop {
            match self.swarm.select_next_some().await {
                libp2p::swarm::SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                    libp2p::request_response::Event::Message {
                        peer,
                        message:
                            libp2p::request_response::Message::Response {
                                request_id: received_id,
                                response,
                            },
                        ..
                    },
                )) if peer == self.peer.peer_id && received_id == outbound_id => {
                    response
                        .validate()
                        .map_err(|error| format!("invalid response: {error:?}"))?;
                    if response.request_id != request_id {
                        return Err("response request correlation mismatch".into());
                    }
                    validate_response_for_request(&request_message, &response.message)?;
                    return Ok(response);
                }
                libp2p::swarm::SwarmEvent::Behaviour(DistributionEvent::RequestResponse(
                    libp2p::request_response::Event::OutboundFailure {
                        request_id: failed_id,
                        error,
                        ..
                    },
                )) if failed_id == outbound_id => {
                    return Err(format!("distribution request failed: {error}"));
                }
                _ => {}
            }
        }
    }
}

#[cfg(unix)]
fn validate_response_for_request(request: &Request, response: &Response) -> Result<(), String> {
    match (request, response) {
        (Request::Manifest { package_id }, Response::Manifest { manifest_json }) => {
            let manifest = crate::parse_manifest(manifest_json)
                .map_err(|error| format!("invalid manifest response: {error}"))?;
            let expected = format!("{}/{}", manifest.publisher_id, manifest.package_name);
            if &expected != package_id {
                return Err("manifest response package does not match request".into());
            }
        }
        (
            Request::Chunk { transfer_id, index },
            Response::Chunk {
                transfer_id: response_id,
                chunk,
            },
        ) if transfer_id == response_id && *index == chunk.index => {}
        (
            Request::Resume { transfer_id, .. },
            Response::Resumed {
                transfer_id: response_id,
                ..
            },
        )
        | (
            Request::TransferStatus { transfer_id },
            Response::TransferStatus {
                transfer_id: response_id,
                ..
            },
        )
        | (
            Request::Cancel { transfer_id },
            Response::Cancelled {
                transfer_id: response_id,
            },
        ) if transfer_id == response_id => {}
        (_, Response::Reject { .. }) => {}
        _ => return Err("response type or resource does not match request".into()),
    }
    Ok(())
}

/// Construct the stock CBOR codec with explicit distribution-specific frame
/// ceilings. Its response limit accommodates one maximum-size chunk and proof.
pub fn cbor_behaviour() -> CborBehaviour {
    use libp2p::{
        request_response::{self, ProtocolSupport},
        StreamProtocol,
    };
    CborBehaviour::with_codec(
        BoundedCborCodec,
        [(
            StreamProtocol::new(DISTRIBUTION_PROTOCOL),
            ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_IN_FLIGHT_PER_PEER),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    EmptyRequestId,
    MalformedMessage,
    Replay,
    ReplayWindowFull,
    PeerRequestLimit,
    GlobalRequestLimit,
    TransferLimit,
}

struct PeerWindow {
    seen: VecDeque<[u8; 16]>,
    active: usize,
    transfers: usize,
    request_window_started: Instant,
    requests_in_window: usize,
}

/// Bounded in-memory request accounting. Request IDs are retained for the
/// lifetime of the process and survive connection loss. Once the replay window
/// fills, new requests fail closed. A process restart clears this volatile
/// cache; operations must remain idempotent and durable resume must revalidate
/// the signed manifest, disk journal, peer binding, and authorization.
/// Call `begin` only after authenticating the transport peer and checking its
/// local binding; otherwise unauthenticated peers could consume the peer map.
pub struct RequestAdmission {
    peers: HashMap<PeerId, PeerWindow>,
    active_global: usize,
    transfers_global: usize,
}

impl Default for RequestAdmission {
    fn default() -> Self {
        Self {
            peers: HashMap::new(),
            active_global: 0,
            transfers_global: 0,
        }
    }
}

impl RequestAdmission {
    /// Consult durable replay state before the in-memory quota. Invoke only
    /// after peer authentication and binding validation. If later admission
    /// fails, the ID remains consumed, which is fail-closed.
    #[cfg(all(feature = "live-noise", unix))]
    pub fn begin_durable(
        &mut self,
        durable: &mut crate::persistent_replay::PersistentReplayGuard,
        peer: PeerId,
        request_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        durable
            .record(peer, request_id, now_ms)
            .map_err(|error| match error.kind() {
                io::ErrorKind::AlreadyExists => AdmissionError::Replay,
                io::ErrorKind::WouldBlock => AdmissionError::ReplayWindowFull,
                _ => AdmissionError::MalformedMessage,
            })?;
        self.begin(peer, request_id)
    }

    pub fn begin(&mut self, peer: PeerId, request_id: [u8; 16]) -> Result<(), AdmissionError> {
        if request_id == [0; 16] {
            return Err(AdmissionError::EmptyRequestId);
        }
        if self.active_global >= MAX_IN_FLIGHT_GLOBAL {
            return Err(AdmissionError::GlobalRequestLimit);
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_TRACKED_PEERS {
            return Err(AdmissionError::GlobalRequestLimit);
        }
        let entry = self.peers.entry(peer).or_insert_with(|| PeerWindow {
            seen: VecDeque::new(),
            active: 0,
            transfers: 0,
            request_window_started: Instant::now(),
            requests_in_window: 0,
        });
        if entry.seen.contains(&request_id) {
            return Err(AdmissionError::Replay);
        }
        if entry.seen.len() >= REPLAY_WINDOW_PER_PEER {
            return Err(AdmissionError::ReplayWindowFull);
        }
        if entry.active >= MAX_IN_FLIGHT_PER_PEER {
            return Err(AdmissionError::PeerRequestLimit);
        }
        if entry.request_window_started.elapsed() >= Duration::from_secs(60) {
            entry.request_window_started = Instant::now();
            entry.requests_in_window = 0;
        }
        if entry.requests_in_window >= MAX_REQUESTS_PER_MINUTE_PER_PEER {
            return Err(AdmissionError::PeerRequestLimit);
        }
        entry.seen.push_back(request_id);
        entry.active += 1;
        entry.requests_in_window += 1;
        self.active_global += 1;
        Ok(())
    }

    pub fn finish(&mut self, peer: &PeerId) {
        if let Some(entry) = self.peers.get_mut(peer) {
            if entry.active > 0 {
                entry.active -= 1;
                self.active_global -= 1;
            }
        }
    }

    pub fn begin_transfer(&mut self, peer: PeerId) -> Result<(), AdmissionError> {
        if self.transfers_global >= MAX_TRANSFERS_GLOBAL {
            return Err(AdmissionError::TransferLimit);
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_TRACKED_PEERS {
            return Err(AdmissionError::TransferLimit);
        }
        let entry = self.peers.entry(peer).or_insert_with(|| PeerWindow {
            seen: VecDeque::new(),
            active: 0,
            transfers: 0,
            request_window_started: Instant::now(),
            requests_in_window: 0,
        });
        if entry.transfers >= MAX_TRANSFERS_PER_PEER {
            return Err(AdmissionError::TransferLimit);
        }
        entry.transfers += 1;
        self.transfers_global += 1;
        Ok(())
    }

    pub fn finish_transfer(&mut self, peer: &PeerId) {
        if let Some(entry) = self.peers.get_mut(peer) {
            if entry.transfers > 0 {
                entry.transfers -= 1;
                self.transfers_global -= 1;
            }
        }
    }

    pub fn disconnected(&mut self, peer: &PeerId) {
        if let Some(entry) = self.peers.get_mut(peer) {
            self.active_global = self.active_global.saturating_sub(entry.active);
            self.transfers_global = self.transfers_global.saturating_sub(entry.transfers);
            entry.active = 0;
            entry.transfers = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_core::capability::issue_scoped_token;
    use aip_crypto::generate_ed25519_keypair;
    use aip_types::CapabilityScope;
    use libp2p::identity;

    fn request_fields() -> (PackageResource, RequestAuthorization) {
        let issuer = generate_ed25519_keypair();
        let capability = issue_scoped_token(
            "aip:test-issuer",
            &issuer.private_key,
            "aip:test-agent",
            CapabilityScope {
                allowed: vec![],
                denied: vec![],
            },
            Some(60_000),
        )
        .unwrap();
        (
            PackageResource {
                package_id: "aip:test-package".into(),
                publisher_id: "aip:test-publisher".into(),
                release_digest: [3; 32],
                recipient_id: "aip:test-agent".into(),
            },
            RequestAuthorization {
                capability,
                delegation_chain: vec![],
            },
        )
    }

    #[test]
    fn protocol_rejects_replay_and_tracks_peer_resources() {
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let mut admission = RequestAdmission::default();
        let id = [1; 16];
        admission.begin(peer, id).unwrap();
        assert_eq!(admission.begin(peer, id), Err(AdmissionError::Replay));
        admission.finish(&peer);
        admission.begin_transfer(peer).unwrap();
        admission.disconnected(&peer);
        assert_eq!(admission.active_global, 0);
        assert_eq!(admission.transfers_global, 0);
        assert_eq!(admission.begin(peer, id), Err(AdmissionError::Replay));
    }

    #[cfg(all(feature = "live-noise", unix))]
    #[test]
    fn durable_request_admission_rejects_replay_after_reopen() {
        let root = std::env::temp_dir().join(format!(
            "aip-admission-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("journal.json");
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        {
            let mut journal = crate::persistent_replay::PersistentReplayGuard::open(&path).unwrap();
            let mut admission = RequestAdmission::default();
            admission
                .begin_durable(&mut journal, peer, [0x42; 16], 1)
                .unwrap();
        }
        let mut journal = crate::persistent_replay::PersistentReplayGuard::open(&path).unwrap();
        let mut admission = RequestAdmission::default();
        assert_eq!(
            admission.begin_durable(&mut journal, peer, [0x42; 16], 2),
            Err(AdmissionError::Replay)
        );
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_wire_shapes_are_not_permitted_by_serde() {
        let malformed = br#"{"request_id":[0,0],"message":{"type":"Chunk","transfer_id":"x","index":0,"extra":1}}"#;
        assert!(serde_json::from_slice::<RequestEnvelope>(malformed).is_err());
    }

    #[test]
    fn request_validation_rejects_bad_ids_and_transfer_names() {
        let (resource, authorization) = request_fields();
        assert_eq!(
            RequestEnvelope {
                request_id: [0; 16],
                resource: resource.clone(),
                authorization: authorization.clone(),
                message: Request::Manifest {
                    package_id: "package".into()
                }
            }
            .validate(),
            Err(AdmissionError::EmptyRequestId)
        );
        assert_eq!(
            RequestEnvelope {
                request_id: [1; 16],
                resource: resource.clone(),
                authorization: authorization.clone(),
                message: Request::Chunk {
                    transfer_id: "../outside".into(),
                    index: 0
                }
            }
            .validate(),
            Err(AdmissionError::MalformedMessage)
        );
        assert!(RequestEnvelope {
            request_id: [1; 16],
            resource,
            authorization,
            message: Request::Chunk {
                transfer_id: "a".repeat(64),
                index: 0
            }
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn per_peer_global_and_transfer_quotas_fail_closed() {
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let mut per_peer = RequestAdmission::default();
        for index in 0..MAX_IN_FLIGHT_PER_PEER {
            let mut id = [0; 16];
            id[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            per_peer.begin(peer, id).unwrap();
        }
        assert_eq!(
            per_peer.begin(peer, [0xff; 16]),
            Err(AdmissionError::PeerRequestLimit)
        );

        let mut global = RequestAdmission::default();
        for index in 0..MAX_IN_FLIGHT_GLOBAL {
            let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
            let mut id = [0; 16];
            id[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            global.begin(peer, id).unwrap();
        }
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(
            global.begin(peer, [0xfe; 16]),
            Err(AdmissionError::GlobalRequestLimit)
        );

        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let mut transfers = RequestAdmission::default();
        for _ in 0..MAX_TRANSFERS_PER_PEER {
            transfers.begin_transfer(peer).unwrap();
        }
        assert_eq!(
            transfers.begin_transfer(peer),
            Err(AdmissionError::TransferLimit)
        );
    }

    #[tokio::test]
    async fn bounded_cbor_codec_rejects_oversized_and_accepts_valid_request() {
        use libp2p::request_response::Codec as _;
        let protocol = libp2p::StreamProtocol::new(DISTRIBUTION_PROTOCOL);
        let (resource, authorization) = request_fields();
        let request = RequestEnvelope {
            request_id: [9; 16],
            resource,
            authorization,
            message: Request::Manifest {
                package_id: "aip:pkg/example".into(),
            },
        };
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
        let mut valid_io = futures::io::Cursor::new(bytes);
        assert_eq!(
            BoundedCborCodec::default()
                .read_request(&protocol, &mut valid_io)
                .await
                .unwrap(),
            request
        );

        let mut oversized = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
        oversized.resize(MAX_REQUEST_BYTES as usize + 1, 0);
        let mut oversized_io = futures::io::Cursor::new(oversized);
        assert_eq!(
            BoundedCborCodec::default()
                .read_request(&protocol, &mut oversized_io)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
