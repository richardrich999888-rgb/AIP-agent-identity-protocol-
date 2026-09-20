//! A governed Model Context Protocol gateway.
//!
//! MCP is where an agent's authority actually lives. A model's tools are the
//! only way it touches anything outside its own context window, and today
//! that boundary is enforced — when it is enforced at all — by an allow-list
//! in a client config, evaluated once at connection time, with no record of
//! what was invoked, under whose authority, or on what basis.
//!
//! This crate puts the AIP funnel on that wire. Every `tools/call` is
//! adjudicated against a live delegation graph and sealed into a hash-chained
//! forensic ledger *before* it reaches the upstream server; `tools/list` is
//! filtered to the agent's effective authority; and content read through
//! `resources/read` taints the session, which mechanically removes tools that
//! declared they will not run alongside untrusted input.
//!
//! ```text
//!   MCP client (the model's runtime)
//!         │  tools/call, tools/list, resources/read
//!         ▼
//!   ┌─────────────────────────────────────────┐
//!   │  McpGateway                             │
//!   │    • lifecycle: born, open, right weights│
//!   │    • authority: delegation graph walk    │
//!   │    • mandate:  scope, clearance, taint,  │
//!   │                supervisor co-signature   │
//!   │    • seal:     evidence packet + anchor  │──▶ EvidenceSink
//!   └─────────────────────────────────────────┘
//!         │  only what survived
//!         ▼
//!   upstream MCP server (the real tools)
//! ```
//!
//! # The three properties
//!
//! **Nothing executes unevidenced.** [`McpGateway::handle`] returns a
//! `#[must_use]` [`ForwardTicket`] for a permitted call, and
//! [`McpGateway::complete`] is the only thing that consumes one. A transport
//! that forwards a call and forgets to complete it does not compile cleanly.
//! Refusals are sealed too: a denied call is a packet in the chain, so a gap
//! in the sequence is itself the tell.
//!
//! **Authority is resolved, never cached.** Every call walks the delegation
//! graph to an officer root. Revoking one edge removes authority from its
//! whole subtree at the next call, with no invalidation to distribute and no
//! window during which a stale grant still works.
//!
//! **Taint removes tools rather than detecting attacks.** A tool whose
//! mandate sets `max_context_taint` below `UNTRUSTED` stops appearing in
//! `tools/list` and stops being invocable once the session has read anything
//! untrusted. The injected instruction never has to be recognised as
//! hostile — by the time the model has read it, the capability the attacker
//! wanted is gone. See [`session::PrefixTrustPolicy`], which classifies
//! unknown origins as untrusted so an unclassified resource makes the
//! gateway stricter, not laxer.
//!
//! # Example
//!
//! ```no_run
//! use ot_accountability_core::aip::{AipFunnel, DenyAllCoSignatures};
//! use ot_accountability_core::authority::{
//!     ClearanceLevel, MemoryAuthorityStore, ToolManifest, ToolMandate,
//!     TrustedStoreVerifier, TrustTier,
//! };
//! use ot_mcp_gateway::{
//!     gateway::{Handling, McpGateway},
//!     protocol::{JsonRpcRequest, JsonRpcResponse},
//!     session::{PrefixTrustPolicy, Session},
//!     sink::JsonlEvidenceSink,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut manifest = ToolManifest::new();
//! manifest.insert(
//!     "send_command".into(),
//!     ToolMandate::new("command", ClearanceLevel::Secret)
//!         .with_max_context_taint(TrustTier::Internal),
//! );
//!
//! let funnel = AipFunnel::new(
//!     Box::new(MemoryAuthorityStore::new()),
//!     Box::new(TrustedStoreVerifier),
//!     Box::new(DenyAllCoSignatures),
//!     manifest,
//! );
//! let mut gateway = McpGateway::new(
//!     funnel,
//!     JsonlEvidenceSink::open("evidence.jsonl")?,
//!     PrefixTrustPolicy::new().declare("file:///opt/mission/", TrustTier::Trusted),
//! );
//! let mut session = Session::new("did:syntriass:agent:AGT-1", "a".repeat(64));
//!
//! let request = JsonRpcRequest::parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)?;
//! match gateway.handle(&mut session, request, "2026-08-27T00:00:00.000Z") {
//!     Handling::Respond(response) => println!("{}", response.to_json()),
//!     Handling::Forward(ticket) => {
//!         // send `ticket.upstream_request()` to the real server, then:
//!         let outcome = JsonRpcResponse::parse_outcome(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
//!         let _ = gateway.complete(&mut session, ticket, outcome, "2026-08-27T00:00:00.000Z");
//!     }
//!     Handling::Silent => {}
//! }
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod gateway;
#[cfg(feature = "http")]
pub mod http;
pub mod identity;
pub mod keyring;
pub mod pem;
pub mod protocol;
pub mod provision;
pub mod session;
pub mod sink;
pub mod trust;
pub mod upstream;

pub use config::{CompiledPolicy, GatewayPolicy};
pub use gateway::{ForwardTicket, Handling, McpGateway, PROTOCOL_VERSION};
pub use protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, Method};
pub use session::{PrefixTrustPolicy, Session, TrustPolicy};
pub use sink::{EvidenceSink, JsonlEvidenceSink, MemoryEvidenceSink};
pub use trust::{CoSignatureAuthority, IssuerRegistry, PqcCoSignatureVerifier, SignedEdgeVerifier};
pub use upstream::{ScriptedUpstream, StdioUpstream, Upstream};
