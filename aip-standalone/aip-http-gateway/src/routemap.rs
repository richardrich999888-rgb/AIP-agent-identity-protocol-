//! The institution's signed route map: which HTTP requests are which tools.
//!
//! # Why this is signed, and by the institution
//!
//! A receipt says "agent A called tool T with arguments whose commitment is
//! X". The binding from an HTTP request to the name `T` is what makes that
//! sentence mean anything, and it is a statement about the institution's
//! estate — the same class of statement as the resource registry, and signed
//! the same way, by the institution's own key. A gateway that decided for
//! itself which route was which tool could be re-pointed, and every receipt it
//! ever signed would become a claim about a name only it controlled.
//!
//! # Path templates, and why ambiguity is refused rather than resolved
//!
//! A template is a path split on `/` where a segment written `{name}` matches
//! any one segment and contributes an argument under `name`. `/orbits/{norad}`
//! matched against `/orbits/25544` yields `{"norad": "25544"}`.
//!
//! Two templates that could match the same request are **refused at
//! verification**, not resolved by an order rule. A first-match rule makes the
//! meaning of a receipt depend on the order entries happen to sit in a file,
//! which is exactly the kind of silent dependency an auditor cannot check. The
//! overlap test is decidable: same method, same segment count, and every
//! position compatible (equal literals, or either side a parameter).
//!
//! # What a route map cannot do
//!
//! It cannot grant anything. Resolution answers "what is this request called",
//! never "may this happen" — authority is the decision point's, and the
//! reconciler compares the two afterwards. A route map with every route in it
//! and no decision point in front is a gateway that names everything and
//! permits nothing extra.

use std::collections::BTreeSet;

use aip_crypto::hybrid::{verify_under_policy, HybridError, SignaturePolicy};
use aip_crypto::{sha256, verify_ed25519};
use aip_types::canonical::*;
use aip_types::Signature;
use serde::{Deserialize, Serialize};

/// Domain tag for the route map's signing preimage.
pub const ROUTE_MAP_DOMAIN: &str = "GHOST/HttpRouteMap/v1";

/// The only version this crate accepts.
pub const ROUTE_MAP_VERSION: u16 = 1;

/// One route: an HTTP method and path template, and the tool it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Tool identifier, in the **same vocabulary** the decision point's
    /// `tool_invoke_parameters` uses. If the two disagree, every comparison
    /// downstream answers "not comparable" and the boundary is decoration.
    pub tool_id: String,
    /// Upper-case HTTP method.
    pub method: String,
    /// Path template, absolute, `/`-separated, `{name}` for a parameter.
    pub path: String,
}

impl RouteEntry {
    /// Template segments, without the leading empty one.
    fn segments(&self) -> Vec<&str> {
        self.path.trim_start_matches('/').split('/').collect()
    }
}

/// The parameter name of a template segment, if it is one.
fn param_name(segment: &str) -> Option<&str> {
    segment
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .filter(|s| !s.is_empty())
}

/// The institution's signed map from HTTP requests to tool identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMap {
    pub version: u16,
    /// Names the map. Receipts do not cite it; the gateway's health output
    /// does, so an operator can tell which map a running gateway loaded.
    pub map_id: String,
    /// The institution identity whose key signs this map.
    pub issuer_id: String,
    /// Monotone per `map_id`. A verifier that has seen revision N refuses a
    /// later-presented revision below N for the same id.
    pub revision: u64,
    /// The instant from which this revision describes the estate.
    pub valid_from_ms: u64,
    /// Sorted by `(method, path)`, unique, pairwise non-overlapping.
    pub routes: Vec<RouteEntry>,
    pub signature: Signature,
}

/// Why a route map is refused. Every variant is a refusal to resolve against
/// a map that could name one request two ways, or that the institution did
/// not sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteMapError {
    UnsupportedVersion(u16),
    EmptyMapId,
    EmptyIssuerId,
    NoRoutes,
    EmptyToolId,
    /// A method that is not upper-case ASCII, so two spellings of one method
    /// could sit in the same map.
    BadMethod(String),
    /// A path that is not absolute, or carries an empty or malformed segment.
    BadPath(String),
    /// `{}`, or a parameter name repeated inside one template.
    BadParameter {
        path: String,
        name: String,
    },
    NotSorted,
    Duplicate {
        method: String,
        path: String,
    },
    /// Two templates that could match the same request.
    Overlapping {
        a: String,
        b: String,
    },
    UntrustedIssuer(String),
    SignerMismatch,
    PayloadHashMismatch,
    SignatureInvalid,
    /// A hybrid or policy refusal, carrying which half or which rule.
    Signature(HybridError),
}

/// Issuer keys a verifier was provisioned with. The map never carries the key
/// that verifies it.
#[derive(Debug, Clone, Default)]
pub struct RouteMapAnchors {
    keys: std::collections::HashMap<String, Vec<u8>>,
}

impl RouteMapAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(mut self, issuer_id: &str, public_key: &[u8]) -> Self {
        self.keys.insert(issuer_id.to_owned(), public_key.to_vec());
        self
    }

    pub fn get(&self, issuer_id: &str) -> Option<&[u8]> {
        self.keys.get(issuer_id).map(Vec::as_slice)
    }
}

/// What a request resolved to. Total: every request is one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// The institution named this request, with the arguments the path
    /// template contributed.
    Named {
        route: &'a RouteEntry,
        path_arguments: Vec<(String, String)>,
    },
    /// No route matched. **Not an error and not a tool**: the gateway has no
    /// name to put in a receipt, so it issues none and refuses the request.
    Unrouted,
}

impl RouteMap {
    /// The bytes this map's signature covers.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + 64 * self.routes.len());
        put_domain(&mut buf, ROUTE_MAP_DOMAIN);
        put_u16(&mut buf, self.version);
        put_str(&mut buf, &self.map_id);
        put_str(&mut buf, &self.issuer_id);
        put_u64(&mut buf, self.revision);
        put_u64(&mut buf, self.valid_from_ms);
        put_u32(&mut buf, self.routes.len() as u32);
        for r in &self.routes {
            put_str(&mut buf, &r.tool_id);
            put_str(&mut buf, &r.method);
            put_str(&mut buf, &r.path);
        }
        buf
    }

    /// Structural checks, before any cryptography.
    pub fn check_well_formed(&self) -> Result<(), RouteMapError> {
        if self.version != ROUTE_MAP_VERSION {
            return Err(RouteMapError::UnsupportedVersion(self.version));
        }
        if self.map_id.is_empty() {
            return Err(RouteMapError::EmptyMapId);
        }
        if self.issuer_id.is_empty() {
            return Err(RouteMapError::EmptyIssuerId);
        }
        if self.routes.is_empty() {
            return Err(RouteMapError::NoRoutes);
        }
        for r in &self.routes {
            if r.tool_id.is_empty() {
                return Err(RouteMapError::EmptyToolId);
            }
            if r.method.is_empty()
                || !r
                    .method
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'-')
            {
                return Err(RouteMapError::BadMethod(r.method.clone()));
            }
            if !r.path.starts_with('/') {
                return Err(RouteMapError::BadPath(r.path.clone()));
            }
            let mut names = BTreeSet::new();
            for seg in r.segments() {
                if seg.is_empty() {
                    return Err(RouteMapError::BadPath(r.path.clone()));
                }
                // A segment that opens a parameter must close it and name it,
                // or `{}` and `{a` would be treated as literals that can never
                // match anything an operator meant.
                if seg.starts_with('{') || seg.ends_with('}') {
                    let Some(name) = param_name(seg) else {
                        return Err(RouteMapError::BadParameter {
                            path: r.path.clone(),
                            name: seg.to_string(),
                        });
                    };
                    if !names.insert(name) {
                        return Err(RouteMapError::BadParameter {
                            path: r.path.clone(),
                            name: name.to_string(),
                        });
                    }
                }
            }
        }
        // Sorted and unique, so one map has one reading.
        for pair in self.routes.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let (ka, kb) = ((&a.method, &a.path), (&b.method, &b.path));
            if ka == kb {
                return Err(RouteMapError::Duplicate {
                    method: a.method.clone(),
                    path: a.path.clone(),
                });
            }
            if ka > kb {
                return Err(RouteMapError::NotSorted);
            }
        }
        // Pairwise non-overlapping: no request may have two names.
        for (i, a) in self.routes.iter().enumerate() {
            for b in &self.routes[i + 1..] {
                if templates_overlap(a, b) {
                    return Err(RouteMapError::Overlapping {
                        a: format!("{} {}", a.method, a.path),
                        b: format!("{} {}", b.method, b.path),
                    });
                }
            }
        }
        Ok(())
    }

    /// Verify against the verifier's anchors: well-formedness, an anchored
    /// issuer, a signature that names it, the payload hash over this struct's
    /// own preimage, and the Ed25519 signature — in that order.
    pub fn verify(&self, anchors: &RouteMapAnchors) -> Result<(), RouteMapError> {
        self.check_well_formed()?;
        let key = anchors
            .get(&self.issuer_id)
            .ok_or_else(|| RouteMapError::UntrustedIssuer(self.issuer_id.clone()))?;
        if self.signature.signer_id != self.issuer_id {
            return Err(RouteMapError::SignerMismatch);
        }
        if self.signature.payload_hash != sha256(&self.signing_preimage()) {
            return Err(RouteMapError::PayloadHashMismatch);
        }
        match verify_ed25519(key, &self.signature) {
            Ok(true) => Ok(()),
            _ => Err(RouteMapError::SignatureInvalid),
        }
    }

    /// Verify under a signature policy, so an institution mid-migration can
    /// require a hybrid signature on its route map without invalidating the
    /// Ed25519-signed maps already deployed.
    ///
    /// Additive: [`RouteMap::verify`] is unchanged and every map signed before
    /// this existed verifies byte-identically through it. `ml_dsa_public` is
    /// the issuer's ML-DSA-65 verifying key, absent while the institution is
    /// still Ed25519-only — a hybrid map presented without one is refused
    /// rather than half-checked.
    pub fn verify_under_policy(
        &self,
        anchors: &RouteMapAnchors,
        policy: SignaturePolicy,
        ml_dsa_public: Option<&[u8]>,
    ) -> Result<(), RouteMapError> {
        self.check_well_formed()?;
        let key = anchors
            .get(&self.issuer_id)
            .ok_or_else(|| RouteMapError::UntrustedIssuer(self.issuer_id.clone()))?;
        if self.signature.signer_id != self.issuer_id {
            return Err(RouteMapError::SignerMismatch);
        }
        if self.signature.payload_hash != sha256(&self.signing_preimage()) {
            return Err(RouteMapError::PayloadHashMismatch);
        }
        verify_under_policy(policy, key, ml_dsa_public, &self.signature)
            .map_err(RouteMapError::Signature)
    }

    /// Resolve one request. Total and deterministic: a well-formed map cannot
    /// match a request twice, so the first match is the only match.
    ///
    /// Callers must have verified the map; this does not re-check, so a caller
    /// resolving against an unverified map has chosen to trust it.
    pub fn resolve(&self, method: &str, path: &str) -> Resolution<'_> {
        let want: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        for route in &self.routes {
            if route.method != method {
                continue;
            }
            let template = route.segments();
            if template.len() != want.len() {
                continue;
            }
            let mut path_arguments = Vec::new();
            let mut matched = true;
            for (t, w) in template.iter().zip(want.iter()) {
                match param_name(t) {
                    Some(name) => {
                        // An empty segment never matches a parameter: `/orbits/`
                        // is not a request for orbit "".
                        if w.is_empty() {
                            matched = false;
                            break;
                        }
                        path_arguments.push((name.to_string(), (*w).to_string()));
                    }
                    None if t == w => {}
                    None => {
                        matched = false;
                        break;
                    }
                }
            }
            if matched {
                return Resolution::Named {
                    route,
                    path_arguments,
                };
            }
        }
        Resolution::Unrouted
    }
}

/// Could these two templates match the same request?
fn templates_overlap(a: &RouteEntry, b: &RouteEntry) -> bool {
    if a.method != b.method {
        return false;
    }
    let (sa, sb) = (a.segments(), b.segments());
    if sa.len() != sb.len() {
        return false;
    }
    // Compatible position by position: a parameter matches anything, two
    // literals only match each other.
    sa.iter()
        .zip(sb.iter())
        .all(|(x, y)| param_name(x).is_some() || param_name(y).is_some() || x == y)
}
