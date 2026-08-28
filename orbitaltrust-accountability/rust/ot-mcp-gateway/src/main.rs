//! `ot-mcp-gateway` — a governed stdio proxy for a Model Context Protocol
//! server.
//!
//! It speaks MCP to a client on stdin/stdout and MCP to a real server it
//! launches as a child process, adjudicating and sealing everything that
//! passes between them.
//!
//! ```text
//! ot-mcp-gateway --policy mission.json --evidence evidence.jsonl \
//!     -- python -m my_tool_server
//! ```
//!
//! Drop it into any MCP client config in place of the server it wraps; the
//! client sees an ordinary MCP server, and the tools it is shown are the ones
//! the policy file actually delegated.
//!
//! # What the transport is responsible for
//!
//! The gateway library performs no I/O, so this binary owns the loop: read a
//! line, dispatch, forward to the child when handed a ticket, complete the
//! ticket with the child's reply, write the response. Because a
//! [`ForwardTicket`](ot_mcp_gateway::ForwardTicket) is `#[must_use]` and
//! `complete` is the only thing that takes one, a transport bug that executes
//! without sealing shows up as a compiler warning here rather than as a
//! missing record in an audit.

use std::io::{BufRead, Write};

use clap::Parser;
use ot_accountability_core::aip::{AipFunnel, CoSignatureVerifier, DenyAllCoSignatures};
use ot_accountability_core::authority::{EdgeVerifier, TrustedStoreVerifier};
use ot_mcp_gateway::config::GatewayPolicy;
use ot_mcp_gateway::gateway::{Handling, McpGateway};
use ot_mcp_gateway::identity::{shared, PqcChallengeAttestor};
use ot_mcp_gateway::protocol::{JsonRpcRequest, JsonRpcResponse};
use ot_mcp_gateway::session::{PrefixTrustPolicy, Session};
use ot_mcp_gateway::sink::JsonlEvidenceSink;
use ot_mcp_gateway::trust::{PqcCoSignatureVerifier, SignedEdgeVerifier};
use ot_mcp_gateway::upstream::{StdioUpstream, Upstream};
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "ot-mcp-gateway",
    about = "Governed MCP proxy: every tools/call is adjudicated and sealed before it reaches the upstream server",
    long_about = None
)]
struct Args {
    /// Policy document: tool manifest, delegation edges, agent identity, and
    /// resource trust classification.
    #[arg(long, value_name = "FILE")]
    policy: String,

    /// Append-only JSONL forensic ledger. Created if absent, never truncated.
    #[arg(long, value_name = "FILE")]
    evidence: String,

    /// The upstream MCP server to launch and govern, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    upstream: Vec<String>,
}

/// ISO-8601 UTC to millisecond precision, matching the console's timestamps.
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

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to a
/// proleptic-Gregorian date. Inlined rather than pulled from `chrono` because
/// a formatting helper is not worth a dependency in the one binary that has to
/// be auditable line by line.
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

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("ot-mcp-gateway: {why}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
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
                "ot-mcp-gateway: delegation edges must be signed by {} authorised issuer(s)",
                issuers.len()
            );
            Box::new(SignedEdgeVerifier::new(issuers))
        }
        None => {
            eprintln!(
                "ot-mcp-gateway: WARNING — no `issuers` in the policy, so delegation edges are trusted \
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

    // Launched before the ledger is touched: a process that writes a genesis
    // anchor and then fails to start its upstream leaves orphan records that
    // break linear verification of the evidence file.
    let mut upstream = StdioUpstream::launch(&args.upstream)?;

    let sink = JsonlEvidenceSink::open(&args.evidence)?;
    // The registry starts empty and is populated by `enrol_credential` below,
    // so every credential this gateway honours has an anchor on the chain
    // saying when it became authoritative — rather than being trusted because
    // a file said so.
    let registry = shared(Default::default());
    let mut gateway: McpGateway<JsonlEvidenceSink, PrefixTrustPolicy> =
        McpGateway::new(funnel, sink, policy.trust)
            .with_attestor(Box::new(PqcChallengeAttestor::new(registry.clone())))
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
            "ot-mcp-gateway: WARNING — no credentials enrolled for {}, so nothing can \
             authenticate as it and every call will be refused as IDENTITY_UNVERIFIED. \
             Add an `agent.credentials` entry to the policy.",
            agent.did
        );
    }

    let mut session = Session::new(&agent.did, &agent.model_digest);

    eprintln!(
        "ot-mcp-gateway: governing {} for {} — {enrolled} credential(s) enrolled, evidence to {}",
        args.upstream.join(" "),
        agent.did,
        args.evidence
    );

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("cannot read client: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request = match JsonRpcRequest::parse(&line) {
            Ok(request) => request,
            Err(error) => {
                // A malformed frame has no id to answer against; JSON-RPC
                // says to reply with a null id rather than stay silent.
                emit(&mut stdout, &JsonRpcResponse::error(Value::Null, error))?;
                continue;
            }
        };

        let now = now_utc();
        match gateway.handle(&mut session, request, &now) {
            Handling::Silent => {}
            Handling::Respond(response) => emit(&mut stdout, &response)?,
            Handling::Forward(ticket) => {
                let outcome = upstream.round_trip(ticket.upstream_request());
                if let Some(response) = gateway.complete(&mut session, ticket, outcome, &now) {
                    emit(&mut stdout, &response)?;
                }
            }
        }
    }

    upstream.shutdown();
    Ok(())
}

fn emit(out: &mut std::io::Stdout, response: &JsonRpcResponse) -> Result<(), String> {
    writeln!(out, "{}", response.to_json())
        .and_then(|()| out.flush())
        .map_err(|e| format!("cannot write client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_iso_8601_utc_to_the_millisecond() {
        let stamp = now_utc();
        assert_eq!(stamp.len(), 24, "{stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
        // Lexicographic comparison of these is chronological, which is what
        // the delegation validity windows rely on.
        assert!(stamp.as_str() > "2026-01-01T00:00:00.000Z", "{stamp}");
    }

    #[test]
    fn the_civil_calendar_conversion_agrees_with_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // A leap day, which an off-by-one in the era arithmetic would miss.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(20_675), (2026, 8, 10));
    }
}
