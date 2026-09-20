//! `aip-http-gateway` — B10: receipt issuance at an institution's HTTP API.
//!
//! ```text
//!   agent  ──HTTP──▶  aip-http-gateway  ──HTTP──▶  the institution's API
//!                          │
//!                          │  resolve against the institution's SIGNED route map
//!                          │  recompute the argument commitment ITSELF
//!                          │  forward only what it can name and read
//!                          ▼
//!                    SignedToolReceipt  ──▶  the reconciler
//! ```
//!
//! # The gap this closes
//!
//! The kernel observer sees a socket from the agent to an API. It cannot see
//! *which operation was invoked with what parameters* inside that TLS session,
//! and it must not guess — which is why an unauthorised transfer, today,
//! surfaces as "a connection to a registered destination" rather than as "a
//! transfer of ₹40 lakh to an unapproved beneficiary". The only party that can
//! close that gap is the one that terminates the request.
//!
//! `aip-mcp-gateway` does this for MCP. An institution's estate is HTTP: this
//! crate does it there, and the two share the commitment functions, so a
//! receipt for the same arguments is **byte-identical whichever boundary
//! issued it**. Moving a tool from an HTTP route to an MCP server does not
//! invalidate the institution's history.
//!
//! # Three properties, and where each is enforced
//!
//! **The gateway commits to what it received, not to what it was told.**
//! [`issue::receipt_for_admitted`] computes the parameter commitment from the
//! arguments this crate assembled from the wire. A client that sends one
//! commitment and different arguments is caught before the receipt exists.
//!
//! **The gateway does not decide what anything is called.** The map from an
//! HTTP request to a tool identity is the *institution's* signed statement
//! ([`routemap::RouteMap`]), anchored to its key, refused if two routes could
//! name one request. A gateway that named routes itself could be re-pointed,
//! and every receipt it had ever signed would become a claim about a name only
//! it controlled.
//!
//! **Nothing reaches the upstream unnamed.** A request that resolves to no
//! route is refused, not forwarded. That is the property that makes the
//! receipt stream mean something: a deployment where unrouted requests pass
//! through is a deployment with a silent bypass, and the reconciler would have
//! no record to find missing.
//!
//! # What this is not, and what it costs
//!
//! It is **not authorisation**. Resolution answers *what is this called*, never
//! *may this happen*. Authority is the decision point's and the comparison is
//! the reconciler's; this crate holds no policy and grants nothing.
//!
//! It is **not a claim about the response body** unless that body is JSON. A
//! non-JSON response commits to nothing rather than to a digest of a guess, and
//! that is a real gap: a tool that answers in CSV or a binary format has its
//! request receipted and its answer uncommitted. Stated here rather than
//! papered over; closing it needs a commitment defined over opaque bytes, which
//! is a format change and not this crate's to make.
//!
//! It **cannot see inside a request it is not in front of**. A deployment that
//! leaves a second path to the same API has a bypass, and no property of this
//! crate detects that — the kernel observer and the out-of-band reconciler are
//! what cover it, which is why the three are deployed together.

pub mod issue;
pub mod request;
pub mod routemap;

pub use issue::{
    admit, receipt_for_admitted, receipt_for_refused, Admission, AdmittedCall, RefusedCall,
    RequestParts, Unreceiptable,
};
pub use request::{assemble_arguments, ArgumentError, Source};
pub use routemap::{
    Resolution, RouteEntry, RouteMap, RouteMapAnchors, RouteMapError, ROUTE_MAP_DOMAIN,
    ROUTE_MAP_VERSION,
};
