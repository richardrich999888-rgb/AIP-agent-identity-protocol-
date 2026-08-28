//! `ot-mcp-gateway-http` — the governed proxy over mutual TLS.
//!
//! Identical adjudication to the stdio binary, with identity taken from the
//! TLS client certificate instead of a signed challenge. The certificate is
//! proven during the handshake, before any MCP is read, so a client that
//! cannot authenticate never reaches the gateway at all.
//!
//! ```text
//! ot-mcp-gateway-http \
//!     --policy mission.json --evidence evidence.jsonl \
//!     --listen 0.0.0.0:8443 \
//!     --cert server.pem --key server-key.pem --client-ca client-ca.pem \
//!     -- python -m my_tool_server
//! ```
//!
//! The policy file's `agent.credentials` entries hold the SHA-256 of each
//! authorised client certificate's DER, enrolled with method `MUTUAL_TLS`.
//! Certificates the client CA signs but nobody enrolled complete the
//! handshake and are then refused as `IDENTITY_UNVERIFIED` — signed by the
//! right CA establishes that a certificate is genuine, never that it speaks
//! for a particular agent.

use clap::Parser;
use ot_accountability_core::aip::{AipFunnel, CoSignatureVerifier, DenyAllCoSignatures};
use ot_accountability_core::authority::{EdgeVerifier, TrustedStoreVerifier};
use ot_mcp_gateway::config::GatewayPolicy;
use ot_mcp_gateway::gateway::McpGateway;
use ot_mcp_gateway::http::{bind, HttpGateway, TlsPaths, TlsReloader};
use ot_mcp_gateway::identity::{shared, ChannelCredentialAttestor};
use ot_mcp_gateway::session::PrefixTrustPolicy;
use ot_mcp_gateway::sink::JsonlEvidenceSink;
use ot_mcp_gateway::trust::{PqcCoSignatureVerifier, SignedEdgeVerifier};
use ot_mcp_gateway::upstream::StdioUpstream;

#[derive(Parser, Debug)]
#[command(
    name = "ot-mcp-gateway-http",
    about = "Governed MCP proxy over mutual TLS: identity comes from the client certificate",
    long_about = None
)]
struct Args {
    /// Policy document: tool manifest, delegation edges, agent identity,
    /// enrolled credentials, and resource trust classification.
    #[arg(long, value_name = "FILE")]
    policy: String,

    /// Append-only JSONL forensic ledger. Created if absent, never truncated.
    #[arg(long, value_name = "FILE")]
    evidence: String,

    /// Address to listen on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8443")]
    listen: String,

    /// PEM server certificate chain.
    #[arg(long, value_name = "FILE")]
    cert: String,

    /// PEM server private key.
    #[arg(long, value_name = "FILE")]
    key: String,

    /// PEM certificate authority that signs authorised client certificates.
    #[arg(long, value_name = "FILE")]
    client_ca: String,

    /// PEM certificate revocation list for client certificates. Watched for
    /// changes: dropping an updated CRL into place revokes on the next
    /// connection, no restart. Without this flag a revoked-but-unexpired
    /// certificate keeps authenticating until its enrolment is pulled.
    #[arg(long, value_name = "FILE")]
    client_crl: Option<String>,

    /// The upstream MCP server to launch and govern, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    upstream: Vec<String>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("ot-mcp-gateway-http: {why}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args = Args::parse();
    // Install the process-wide crypto provider before anything builds a TLS
    // config, so the choice is explicit rather than dependent on which
    // feature flags happened to be enabled.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "a crypto provider is already installed".to_string())?;

    let started = now_utc();
    let policy = GatewayPolicy::load(&args.policy)?.compile(&started)?;
    let agent = policy.agent.clone();

    // Trust roots come from the policy when it declares them, and fail
    // closed when it does not — announced either way, because "the store is
    // the trust boundary" is a real deployment choice and a silent one is a
    // liability.
    let edges: Box<dyn EdgeVerifier + Send + Sync> = match policy.issuers {
        Some(issuers) => {
            eprintln!(
                "ot-mcp-gateway-http: delegation edges must be signed by {} authorised issuer(s)",
                issuers.len()
            );
            Box::new(SignedEdgeVerifier::new(issuers))
        }
        None => {
            eprintln!(
                "ot-mcp-gateway-http: WARNING — no `issuers` in the policy, so delegation edges are trusted \
                 because the store returned them. Correct only if this policy file is itself \
                 the trust boundary; add `issuers` and signed edges otherwise."
            );
            Box::new(TrustedStoreVerifier)
        }
    };
    let cosign: Box<dyn CoSignatureVerifier + Send + Sync> = match policy.co_signatories {
        Some(authority) => Box::new(PqcCoSignatureVerifier::new(authority)),
        None => {
            // Not a warning: refusing every approval is the correct posture
            // for a deployment that has named no supervisor.
            Box::new(DenyAllCoSignatures)
        }
    };
    let funnel = AipFunnel::new(Box::new(policy.store), edges, cosign, policy.manifest);

    // Everything that can fail without touching the ledger happens first: the
    // TLS material, the address, the listener, the upstream. Only once the
    // process knows it can actually serve does it write a genesis anchor —
    // otherwise a port conflict leaves orphan anchors in the evidence file
    // and the next reader finds a chain that does not verify.
    let tls = TlsReloader::new(TlsPaths {
        cert: args.cert.clone().into(),
        key: args.key.clone().into(),
        client_ca: args.client_ca.clone().into(),
        crls: args.client_crl.clone().map(Into::into),
    })?;
    if args.client_crl.is_none() {
        eprintln!(
            "ot-mcp-gateway-http: WARNING — no --client-crl, so a revoked-but-unexpired              client certificate keeps authenticating until its enrolment is pulled from              the policy. Publish a CRL and pass it to close that window."
        );
    }
    let addr = args
        .listen
        .parse()
        .map_err(|e| format!("bad --listen address {:?}: {e}", args.listen))?;
    let listener = bind(addr).await?;
    let upstream = StdioUpstream::launch(&args.upstream)?;

    let sink = JsonlEvidenceSink::open(&args.evidence)?;
    let registry = shared(Default::default());
    let mut gateway: McpGateway<JsonlEvidenceSink, PrefixTrustPolicy> =
        McpGateway::new(funnel, sink, policy.trust)
            .with_attestor(Box::new(ChannelCredentialAttestor::new(registry.clone())))
            .with_registry(registry);
    gateway.register_agent(
        &agent.did,
        &agent.supervisor_did,
        &agent.model_digest,
        &started,
    )?;

    let mut enrolled = 0usize;
    for record in policy.credentials.records_for(&agent.did) {
        if record.revoked {
            continue;
        }
        gateway.enrol_credential(&agent.did, &record.digest, record.method, &started)?;
        enrolled += 1;
    }
    if enrolled == 0 {
        eprintln!(
            "ot-mcp-gateway-http: WARNING — no credentials enrolled for {}. Certificates the \
             client CA signs will complete the TLS handshake and then be refused as \
             IDENTITY_UNVERIFIED. Add `agent.credentials` entries holding the SHA-256 of each \
             authorised client certificate's DER, with method MUTUAL_TLS.",
            agent.did
        );
    }

    eprintln!(
        "ot-mcp-gateway-http: governing {} for {} — {enrolled} credential(s) enrolled, evidence to {}",
        args.upstream.join(" "),
        agent.did,
        args.evidence
    );

    HttpGateway::new(
        gateway,
        Box::new(upstream),
        agent.did.clone(),
        agent.model_digest.clone(),
    )
    .serve(listener, tls)
    .await
}

/// ISO-8601 UTC to millisecond precision.
fn now_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (secs, millis) = (now.as_secs() as i64, now.subsec_millis());
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}
