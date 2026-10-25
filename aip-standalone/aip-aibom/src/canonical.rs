//! Canonical encoding of a manifest, and its digest.
//!
//! # Three properties, each required
//!
//! **Domain-separated.** The encoding begins with [`MANIFEST_DOMAIN`], so the
//! bytes of a manifest cannot be replayed as the bytes of any other signed
//! object in this workspace.
//!
//! **Injective.** Every string and byte field is length-prefixed and every
//! optional field carries a presence byte (`aip_types::canonical`), so
//! `["ab", "c"]` and `["a", "bc"]` encode differently, as do `None` and
//! `Some("")`.
//!
//! **Order-independent over sets.** Collections the report treats as sets —
//! tools, models, permissions, and so on — are encoded element by element,
//! sorted by their own encoding, then written. Reordering a manifest's tools
//! is not a change to the manifest, and does not change its digest. Validation
//! has already refused duplicates, so sorting loses nothing.
//!
//! # What is not in here
//!
//! The digest. A manifest that carried its own digest could not be encoded
//! without a rule for excluding it; the seal is detached instead (`seal.rs`).

use crate::model::*;
use aip_crypto::sha256;
use aip_types::canonical::{
    encode_scope_action, put_bytes, put_domain, put_opt_str, put_opt_u64, put_str, put_u16,
    put_u32, put_u64, put_u8,
};

/// Domain tag for a manifest's canonical bytes.
pub const MANIFEST_DOMAIN: &str = "AIP-AIBOM-MANIFEST-v1";

/// The manifest's canonical bytes.
pub fn manifest_bytes(m: &Manifest) -> Vec<u8> {
    let mut b = Vec::new();
    put_domain(&mut b, MANIFEST_DOMAIN);
    put_u16(&mut b, m.schema_version);
    validity(&mut b, &m.validity);
    agent(&mut b, &m.agent);
    set(&mut b, m.models.iter().map(model));
    set(&mut b, m.frameworks.iter().map(framework));
    set(&mut b, m.tools.iter().map(tool));
    permissions(&mut b, &m.permissions);
    set(&mut b, m.data_access.iter().map(data));
    environment(&mut b, &m.environment);
    relationships(&mut b, &m.relationships);
    set(&mut b, m.security_controls.iter().map(control));
    crypto(&mut b, &m.crypto);
    set(&mut b, m.supply_chain.iter().map(supply));
    governance(&mut b, &m.governance);
    b
}

/// SHA-256 of [`manifest_bytes`].
pub fn manifest_digest(m: &Manifest) -> [u8; 32] {
    sha256(&manifest_bytes(m))
}

/// The digest as lowercase hex, the form every report prints.
pub fn manifest_digest_hex(m: &Manifest) -> String {
    hex::encode(manifest_digest(m))
}

/// Write a set: each element encoded alone, sorted by its encoding, counted,
/// and length-prefixed.
fn set(b: &mut Vec<u8>, items: impl Iterator<Item = Vec<u8>>) {
    let mut encoded: Vec<Vec<u8>> = items.collect();
    encoded.sort();
    put_u32(b, encoded.len() as u32);
    for e in &encoded {
        put_bytes(b, e);
    }
}

fn strings<'a>(items: impl Iterator<Item = &'a String> + 'a) -> impl Iterator<Item = Vec<u8>> + 'a {
    items.map(|s| {
        let mut b = Vec::new();
        put_str(&mut b, s);
        b
    })
}

fn put_bool(b: &mut Vec<u8>, v: bool) {
    put_u8(b, u8::from(v));
}

fn action(a: &aip_types::ScopeAction) -> Vec<u8> {
    let mut b = Vec::new();
    encode_scope_action(&mut b, a);
    b
}

fn amount(b: &mut Vec<u8>, a: &Amount) {
    put_u64(b, a.minor_units);
    put_str(b, &a.currency);
    put_u8(b, a.exponent);
}

fn validity(b: &mut Vec<u8>, v: &Validity) {
    put_u64(b, v.issued_at_ms);
    put_opt_u64(b, &v.valid_until_ms);
}

fn agent(b: &mut Vec<u8>, a: &AgentIdentity) {
    put_str(b, &a.id);
    put_str(b, &a.name);
    put_str(b, &a.owner);
    put_str(b, &a.version);
    put_str(b, &a.deployment);
}

fn model(m: &Model) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, &m.provider);
    put_str(&mut b, &m.model);
    put_opt_str(&mut b, &m.version);
    put_u8(&mut b, hosting_code(m.hosting));
    put_opt_str(&mut b, &m.weight_sha256);
    b
}

fn framework(f: &Framework) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, &f.name);
    put_str(&mut b, &f.version);
    b
}

fn tool(t: &Tool) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, &t.id);
    put_u8(&mut b, tool_kind_code(t.kind));
    set(&mut b, strings(t.actions.iter()));
    put_opt_str(&mut b, &t.endpoint);
    b
}

fn permissions(b: &mut Vec<u8>, p: &Permissions) {
    set(b, p.allowed.iter().map(action));
    set(
        b,
        p.limits.iter().map(|l| {
            let mut e = action(&l.action);
            put_u8(&mut e, period_code(l.per));
            amount(&mut e, &l.max);
            e
        }),
    );
    set(
        b,
        p.approval_gates.iter().map(|g| {
            let mut e = action(&g.action);
            amount(&mut e, &g.above);
            put_str(&mut e, &g.approver);
            e
        }),
    );
}

fn data(d: &DataAccess) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, &d.resource);
    put_u8(&mut b, resource_code(d.kind));
    put_u8(&mut b, access_code(d.access));
    b
}

fn environment(b: &mut Vec<u8>, e: &Environment) {
    put_u8(b, runtime_code(e.runtime));
    put_u8(b, network_code(e.network));
    match &e.binary {
        None => put_u8(b, 0),
        Some(bin) => {
            put_u8(b, 1);
            put_str(b, &bin.exe_sha256);
            put_opt_str(b, &bin.exe_path);
        }
    }
}

fn relationships(b: &mut Vec<u8>, r: &Relationships) {
    put_opt_str(b, &r.parent_agent);
    set(b, strings(r.delegated_from.iter()));
    set(b, strings(r.delegates_to.iter()));
}

fn control(c: &SecurityControl) -> Vec<u8> {
    let mut b = Vec::new();
    put_u8(&mut b, control_code(c.kind));
    put_str(&mut b, &c.description);
    b
}

fn crypto(b: &mut Vec<u8>, c: &CryptoPosture) {
    match c.identity_key_algorithm {
        None => put_u8(b, 0),
        Some(a) => {
            put_u8(b, 1);
            put_u8(b, a as u8);
        }
    }
    set(b, strings(c.signing.iter()));
    put_bool(b, c.post_quantum);
}

fn supply(s: &SupplyComponent) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, &s.component);
    put_str(&mut b, &s.version);
    put_opt_str(&mut b, &s.sha256);
    put_opt_str(&mut b, &s.origin);
    b
}

fn governance(b: &mut Vec<u8>, g: &Governance) {
    put_opt_str(b, &g.risk_class);
    set(b, strings(g.policies.iter()));
    put_opt_str(b, &g.audit_owner);
}

// ── Wire codes. Explicit, so reordering a variant cannot change a digest. ──

fn hosting_code(h: Hosting) -> u8 {
    match h {
        Hosting::Hosted => 0x01,
        Hosting::Local => 0x02,
    }
}

fn tool_kind_code(k: ToolKind) -> u8 {
    match k {
        ToolKind::Api => 0x01,
        ToolKind::Mcp => 0x02,
        ToolKind::Plugin => 0x03,
        ToolKind::Function => 0x04,
    }
}

fn period_code(p: LimitPeriod) -> u8 {
    match p {
        LimitPeriod::PerAction => 0x01,
        LimitPeriod::PerDay => 0x02,
        LimitPeriod::PerMonth => 0x03,
    }
}

fn resource_code(k: ResourceKind) -> u8 {
    match k {
        ResourceKind::Database => 0x01,
        ResourceKind::Documents => 0x02,
        ResourceKind::Secret => 0x03,
        ResourceKind::External => 0x04,
    }
}

fn access_code(a: Access) -> u8 {
    match a {
        Access::Read => 0x01,
        Access::Write => 0x02,
        Access::ReadWrite => 0x03,
    }
}

fn runtime_code(r: RuntimeKind) -> u8 {
    match r {
        RuntimeKind::Process => 0x01,
        RuntimeKind::Container => 0x02,
        RuntimeKind::Vm => 0x03,
        RuntimeKind::Serverless => 0x04,
        RuntimeKind::Other => 0x05,
    }
}

fn network_code(n: NetworkPosture) -> u8 {
    match n {
        NetworkPosture::Restricted => 0x01,
        NetworkPosture::Open => 0x02,
        NetworkPosture::Unknown => 0x03,
    }
}

fn control_code(c: ControlKind) -> u8 {
    match c {
        ControlKind::Sandbox => 0x01,
        ControlKind::Authentication => 0x02,
        ControlKind::ApprovalGate => 0x03,
        ControlKind::RateLimit => 0x04,
        ControlKind::Other => 0x05,
    }
}
