//! A mutual-TLS HTTP transport, so identity comes from the connection.
//!
//! # What this exists to provide
//!
//! [`crate::identity::ChannelCredentialAttestor`] can verify a credential the
//! transport took from the channel, but on stdio there is no channel to take
//! one from — which is why the challenge-response path exists. This transport
//! is the other half: it terminates TLS, requires a client certificate, and
//! hands the verified certificate to the gateway as a
//! [`PeerCredential::ClientCertificate`].
//!
//! That matters because it removes a round trip *and* a class of mistake. The
//! challenge path depends on the client implementing a signing step; here the
//! TLS stack has already proven possession of the private key before a single
//! byte of MCP is read. A client that gets the handshake wrong never reaches
//! the gateway at all.
//!
//! # Where the certificate comes from
//!
//! Only from `rustls`, after a completed handshake against the configured
//! client-CA roots. There is no header, no body field, and no way for a
//! request to influence it — the whole point of the type is that its contents
//! were established before the request existed. `X-Client-Cert`-style headers
//! are deliberately not read: a proxy header is a claim, and a claim is what
//! this module exists to replace.
//!
//! # Sessions
//!
//! MCP's streamable-HTTP transport identifies a session with the
//! `Mcp-Session-Id` header. The gateway assigns one at `initialize` and the
//! client returns it thereafter. Session state — context taint, the
//! established principal — hangs off that id.
//!
//! A session is additionally pinned to the certificate that opened it: a
//! request bearing a valid session id but a *different* client certificate is
//! refused rather than served. Otherwise a leaked session id would be a
//! bearer token that outranks the mTLS the deployment chose specifically to
//! avoid bearer tokens.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::gateway::{Handling, McpGateway};
use crate::identity::PeerCredential;
use crate::pem::parse_pem;
use crate::protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, INTERNAL_ERROR, INVALID_REQUEST, PARSE_ERROR,
};
use crate::session::{Session, TrustPolicy};
use crate::sink::EvidenceSink;
use crate::upstream::Upstream;

/// The header carrying the MCP session id.
pub const SESSION_HEADER: &str = "mcp-session-id";

/// The path the governed endpoint is served on.
pub const MCP_PATH: &str = "/mcp";

/// Largest request body accepted, to bound what one caller can make the
/// gateway buffer.
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// Loads a PEM certificate chain.
pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read(path.as_ref())
        .map_err(|e| format!("cannot read {}: {e}", path.as_ref().display()))?;
    let certs = parse_pem(&pem, "CERTIFICATE")
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(format!("no certificates in {}", path.as_ref().display()));
    }
    Ok(certs)
}

/// Loads a PEM private key (PKCS#8 or SEC1).
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, String> {
    let pem = std::fs::read(path.as_ref())
        .map_err(|e| format!("cannot read {}: {e}", path.as_ref().display()))?;
    if let Some(der) = parse_pem(&pem, "PRIVATE KEY").into_iter().next() {
        return PrivateKeyDer::try_from(der).map_err(|e| format!("bad PKCS#8 key: {e}"));
    }
    if let Some(der) = parse_pem(&pem, "EC PRIVATE KEY").into_iter().next() {
        return PrivateKeyDer::try_from(der).map_err(|e| format!("bad SEC1 key: {e}"));
    }
    if let Some(der) = parse_pem(&pem, "RSA PRIVATE KEY").into_iter().next() {
        return PrivateKeyDer::try_from(der).map_err(|e| format!("bad PKCS#1 key: {e}"));
    }
    Err(format!("no private key in {}", path.as_ref().display()))
}

/// Loads the certificate revocation lists in a PEM file ("X509 CRL" blocks).
pub fn load_crls(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateRevocationListDer<'static>>, String> {
    let pem = std::fs::read(path.as_ref())
        .map_err(|e| format!("cannot read {}: {e}", path.as_ref().display()))?;
    let crls: Vec<CertificateRevocationListDer<'static>> = parse_pem(&pem, "X509 CRL")
        .into_iter()
        .map(CertificateRevocationListDer::from)
        .collect();
    if crls.is_empty() {
        // A configured-but-empty CRL file is far more likely a broken export
        // than a deliberate "revoke nothing", and treating it as the latter
        // would silently turn revocation checking off.
        return Err(format!("no X509 CRL blocks in {}", path.as_ref().display()));
    }
    Ok(crls)
}

/// Builds a TLS configuration that **requires** a client certificate signed
/// by one of `client_ca`, and — when CRLs are supplied — refuses revoked
/// certificates during the handshake.
///
/// Client auth is required rather than optional on purpose. An
/// optional-client-auth server serves anonymous connections too, and then
/// the identity guarantee depends on every handler remembering to check —
/// which is the kind of thing that holds until someone adds a handler.
///
/// With CRLs present, rustls' default revocation policy applies: status must
/// be determinable and revoked means refused — fail closed, which is the
/// only defensible reading for a deployment that went to the trouble of
/// publishing a CRL.
pub fn require_client_certificate(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: Vec<CertificateDer<'static>>,
) -> Result<ServerConfig, String> {
    require_client_certificate_with_crls(server_chain, server_key, client_ca, Vec::new())
}

/// [`require_client_certificate`], with revocation lists enforced.
pub fn require_client_certificate_with_crls(
    server_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<ServerConfig, String> {
    let mut roots = RootCertStore::empty();
    for ca in client_ca {
        roots
            .add(ca)
            .map_err(|e| format!("bad client CA certificate: {e}"))?;
    }
    let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if !crls.is_empty() {
        builder = builder.with_crls(crls);
    }
    let verifier = builder
        .build()
        .map_err(|e| format!("cannot build client verifier: {e}"))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .map_err(|e| format!("bad server certificate or key: {e}"))
}

/// The TLS material's file paths, rebuildable on change.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    /// PEM server certificate chain.
    pub cert: PathBuf,
    /// PEM server private key.
    pub key: PathBuf,
    /// PEM client CA bundle.
    pub client_ca: PathBuf,
    /// PEM CRL file, when revocation checking is on.
    pub crls: Option<PathBuf>,
}

impl TlsPaths {
    /// Loads everything and builds the server configuration.
    pub fn build(&self) -> Result<ServerConfig, String> {
        require_client_certificate_with_crls(
            load_certs(&self.cert)?,
            load_private_key(&self.key)?,
            load_certs(&self.client_ca)?,
            match &self.crls {
                Some(path) => load_crls(path)?,
                None => Vec::new(),
            },
        )
    }
}

/// Rebuilds the TLS configuration when its files change on disk.
///
/// # Why this exists
///
/// A CRL is only as good as its freshness: a revocation published to a file
/// the server read once at startup does not revoke anything until someone
/// remembers to restart, and the window between "compromise discovered" and
/// "restart happened" is exactly when the revoked credential is being used.
/// The reloader stats the files before each accepted connection — a stat is
/// cheap against a TLS handshake — and rebuilds when any changed, so
/// dropping a new CRL (or a renewed server certificate) into place takes
/// effect on the next connection.
///
/// # Failure direction
///
/// A rebuild that fails keeps the previous configuration and logs loudly. A
/// malformed CRL upload should not take the service down — that would make
/// "corrupt the CRL" a denial-of-service — and the old configuration still
/// enforces every revocation it knew, so nothing already revoked becomes
/// valid again. What is lost until the file is fixed is only the *new*
/// revocations, and the log line says so.
pub struct TlsReloader {
    paths: TlsPaths,
    stamp: Vec<Option<(std::time::SystemTime, u64)>>,
    config: Arc<ServerConfig>,
}

impl TlsReloader {
    /// Builds the initial configuration; fails when the material is bad, so
    /// a broken deployment fails at startup rather than at first connection.
    pub fn new(paths: TlsPaths) -> Result<Self, String> {
        let config = Arc::new(paths.build()?);
        let stamp = Self::stamp_of(&paths);
        Ok(Self {
            paths,
            stamp,
            config,
        })
    }

    fn stamp_of(paths: &TlsPaths) -> Vec<Option<(std::time::SystemTime, u64)>> {
        let mut watched: Vec<&PathBuf> = vec![&paths.cert, &paths.key, &paths.client_ca];
        if let Some(crls) = &paths.crls {
            watched.push(crls);
        }
        watched
            .into_iter()
            .map(|path| {
                std::fs::metadata(path)
                    .ok()
                    .and_then(|meta| meta.modified().ok().map(|time| (time, meta.len())))
            })
            .collect()
    }

    /// The current configuration, rebuilt if any watched file changed.
    pub fn config(&mut self) -> Arc<ServerConfig> {
        let stamp = Self::stamp_of(&self.paths);
        if stamp != self.stamp {
            match self.paths.build() {
                Ok(rebuilt) => {
                    eprintln!("ot-mcp-gateway: TLS material changed on disk; reloaded");
                    self.config = Arc::new(rebuilt);
                }
                Err(why) => {
                    eprintln!(
                        "ot-mcp-gateway: TLS material changed but failed to load ({why});                          keeping the previous configuration — existing revocations still                          enforced, NEW revocations not in effect until the file is fixed"
                    );
                }
            }
            // Recorded either way, so a bad file is reported once per change
            // rather than once per connection.
            self.stamp = stamp;
        }
        Arc::clone(&self.config)
    }
}

/// Binds a listener, so a caller can establish it can serve before it starts
/// writing evidence.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind {addr}: {e}"))
}

/// Everything one governed endpoint needs, shared across connections.
struct Shared<S: EvidenceSink, P: TrustPolicy> {
    gateway: Mutex<McpGateway<S, P>>,
    upstream: Mutex<Box<dyn Upstream>>,
    sessions: Mutex<HashMap<String, SessionEntry>>,
    nonces: Box<dyn crate::identity::NonceSource>,
    clock: Box<dyn Fn() -> String + Send + Sync>,
}

struct SessionEntry {
    session: Session,
    /// SHA-256 of the certificate that opened this session. A request on a
    /// different certificate does not get to reuse it.
    certificate_digest: String,
}

/// A running governed endpoint.
pub struct HttpGateway<S: EvidenceSink, P: TrustPolicy> {
    shared: Arc<Shared<S, P>>,
    default_agent_did: String,
    default_model_digest: String,
}

impl<S, P> HttpGateway<S, P>
where
    S: EvidenceSink + Send + 'static,
    P: TrustPolicy + Send + 'static,
{
    /// Wraps a gateway and an upstream for serving over HTTP.
    ///
    /// `default_agent_did` and `default_model_digest` seed a new session
    /// before `initialize` names them; the certificate, not these, is what
    /// establishes identity.
    pub fn new(
        gateway: McpGateway<S, P>,
        upstream: Box<dyn Upstream>,
        default_agent_did: impl Into<String>,
        default_model_digest: impl Into<String>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                gateway: Mutex::new(gateway),
                upstream: Mutex::new(upstream),
                sessions: Mutex::new(HashMap::new()),
                nonces: Box::new(crate::identity::OsNonce),
                clock: Box::new(now_utc),
            }),
            default_agent_did: default_agent_did.into(),
            default_model_digest: default_model_digest.into(),
        }
    }

    /// Serves on an already-bound listener, terminating TLS and requiring a
    /// client certificate on every connection.
    ///
    /// Takes a bound listener rather than an address so a caller can prove it
    /// can serve *before* writing anything to the evidence ledger. A process
    /// that registers an agent and then fails to bind leaves orphan genesis
    /// anchors behind, and a ledger with two processes' anchors interleaved
    /// does not verify linearly — a confusing way to discover a port
    /// conflict. See [`bind`].
    pub async fn serve(self, listener: TcpListener, mut tls: TlsReloader) -> Result<(), String> {
        let addr = listener
            .local_addr()
            .map_err(|e| format!("cannot read listener address: {e}"))?;
        eprintln!("ot-mcp-gateway: mTLS listening on https://{addr}{MCP_PATH}");

        loop {
            let (tcp, remote) = match listener.accept().await {
                Ok(pair) => pair,
                // One failed accept is not a reason to stop serving everybody.
                Err(e) => {
                    eprintln!("ot-mcp-gateway: accept failed: {e}");
                    continue;
                }
            };
            // Consulted per connection so a CRL dropped into place revokes on
            // the very next handshake, not the next restart.
            let acceptor = TlsAcceptor::from(tls.config());
            let shared = Arc::clone(&self.shared);
            let did = self.default_agent_did.clone();
            let digest = self.default_model_digest.clone();

            tokio::spawn(async move {
                let stream = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    // A rejected handshake is the common case for an
                    // unauthorised client and is not worth a stack trace.
                    Err(e) => {
                        eprintln!("ot-mcp-gateway: TLS handshake from {remote} failed: {e}");
                        return;
                    }
                };
                // The one place a peer credential may come from.
                let peer = match stream.get_ref().1.peer_certificates() {
                    Some([leaf, ..]) => PeerCredential::ClientCertificate(leaf.to_vec()),
                    // Unreachable while the verifier requires client auth, but
                    // encoded rather than assumed: if the config is ever
                    // loosened, this stays fail-closed.
                    _ => PeerCredential::None,
                };

                let service = service_fn(move |request: Request<Incoming>| {
                    let shared = Arc::clone(&shared);
                    let peer = peer.clone();
                    let did = did.clone();
                    let digest = digest.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            serve_one(request, peer, shared, did, digest).await,
                        )
                    }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    eprintln!("ot-mcp-gateway: connection from {remote} ended: {e}");
                }
            });
        }
    }
}

async fn serve_one<S, P>(
    request: Request<Incoming>,
    peer: PeerCredential,
    shared: Arc<Shared<S, P>>,
    default_did: String,
    default_digest: String,
) -> Response<Full<Bytes>>
where
    S: EvidenceSink + Send + 'static,
    P: TrustPolicy + Send + 'static,
{
    if request.uri().path() != MCP_PATH {
        return plain(StatusCode::NOT_FOUND, "not found");
    }
    if request.method() != hyper::Method::POST {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "POST only");
    }
    let session_header = request
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let body = match read_body(request).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let text = String::from_utf8_lossy(&body).to_string();

    // Blocking work — the gateway, the sink and the stdio upstream are all
    // synchronous — moved off the async runtime so one slow tool call cannot
    // stall every other connection.
    let peer_for_task = peer.clone();
    let result = tokio::task::spawn_blocking(move || {
        dispatch(
            &text,
            &peer_for_task,
            &shared,
            session_header,
            &default_did,
            &default_digest,
        )
    })
    .await;

    match result {
        Ok(Dispatched::Response { body, session_id }) => {
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json");
            if let Some(id) = session_id {
                builder = builder.header(SESSION_HEADER, id);
            }
            builder
                .body(Full::new(Bytes::from(body)))
                .unwrap_or_else(|_| {
                    plain(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                })
        }
        Ok(Dispatched::Empty) => Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")),
        Ok(Dispatched::Refused(reason)) => plain(StatusCode::FORBIDDEN, &reason),
        Err(e) => plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("dispatch task failed: {e}"),
        ),
    }
}

enum Dispatched {
    Response {
        body: String,
        session_id: Option<String>,
    },
    Empty,
    Refused(String),
}

fn dispatch<S, P>(
    text: &str,
    peer: &PeerCredential,
    shared: &Shared<S, P>,
    session_header: Option<String>,
    default_did: &str,
    default_digest: &str,
) -> Dispatched
where
    S: EvidenceSink,
    P: TrustPolicy,
{
    let parsed = match JsonRpcRequest::parse(text) {
        Ok(request) => request,
        Err(error) => {
            return Dispatched::Response {
                body: JsonRpcResponse::error(Value::Null, error)
                    .to_json()
                    .to_string(),
                session_id: None,
            }
        }
    };

    let certificate_digest = peer.digest().unwrap_or_default();
    let mut sessions = match shared.sessions.lock() {
        Ok(guard) => guard,
        Err(_) => return Dispatched::Refused("gateway session table is poisoned".into()),
    };

    // Resolve the session, pinning it to the certificate that opened it.
    let session_id = match session_header {
        Some(id) => match sessions.get(&id) {
            Some(entry) if entry.certificate_digest == certificate_digest => id,
            // A valid session id on a different certificate. Refused rather
            // than served: otherwise a leaked id outranks the mTLS this
            // deployment chose in order not to have bearer tokens.
            Some(_) => {
                return Dispatched::Refused(
                    "session id does not belong to this client certificate".into(),
                )
            }
            None => {
                return Dispatched::Refused("unknown session id".into());
            }
        },
        None => {
            let id = shared.nonces.next_nonce();
            sessions.insert(
                id.clone(),
                SessionEntry {
                    session: Session::new(default_did, default_digest),
                    certificate_digest: certificate_digest.clone(),
                },
            );
            id
        }
    };

    let entry = sessions.get_mut(&session_id).expect("just resolved");
    let now = (shared.clock)();

    let handling = {
        let mut gateway = match shared.gateway.lock() {
            Ok(guard) => guard,
            Err(_) => return Dispatched::Refused("gateway is poisoned".into()),
        };
        gateway.handle_with_peer(&mut entry.session, parsed, peer, &now)
    };

    let response = match handling {
        Handling::Silent => return Dispatched::Empty,
        Handling::Respond(response) => *response,
        Handling::Forward(ticket) => {
            let outcome = match shared.upstream.lock() {
                Ok(mut up) => up.round_trip(ticket.upstream_request()),
                Err(_) => Err(JsonRpcError::new(
                    INTERNAL_ERROR,
                    "upstream connection is poisoned",
                )),
            };
            let mut gateway = match shared.gateway.lock() {
                Ok(guard) => guard,
                Err(_) => return Dispatched::Refused("gateway is poisoned".into()),
            };
            match gateway.complete(&mut entry.session, ticket, outcome, &now) {
                Some(response) => response,
                None => return Dispatched::Empty,
            }
        }
    };

    Dispatched::Response {
        body: response.to_json().to_string(),
        session_id: Some(session_id),
    }
}

async fn read_body(request: Request<Incoming>) -> Result<Bytes, Response<Full<Bytes>>> {
    let body = request.into_body();
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.len() > MAX_BODY_BYTES {
                return Err(plain(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                ));
            }
            Ok(bytes)
        }
        Err(e) => Err(plain(
            StatusCode::BAD_REQUEST,
            &format!("cannot read body: {e}"),
        )),
    }
}

fn plain(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": if status == StatusCode::FORBIDDEN { INVALID_REQUEST } else { PARSE_ERROR },
            "message": message,
        }
    })
    .to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("a static response always builds")
}

/// ISO-8601 UTC to millisecond precision.
fn now_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (secs, millis) = (now.as_secs() as i64, now.subsec_millis());
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_iso_8601_utc_to_the_millisecond() {
        let stamp = now_utc();
        assert_eq!(stamp.len(), 24, "{stamp}");
        assert!(stamp.ends_with('Z'));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }
}
