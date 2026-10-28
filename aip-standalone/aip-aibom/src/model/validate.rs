//! Manifest validation. Every rule fails closed and names the field.

use super::limits::*;
use super::*;
use aip_types::ScopeAction;
use std::collections::BTreeSet;

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Malformed(String),
    UnsupportedSchema { found: u16, supported: u16 },
    Empty,
    TooLong { max: usize },
    ControlCharacter,
    TooMany { max: usize },
    Duplicate,
    NotSha256Hex,
    BadCurrency,
    ExponentTooLarge { max: u8 },
    WindowInverted,
}

/// A refusal, with the JSON path of the offending value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub path: String,
    pub reason: Reason,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.path, self.reason)
    }
}

impl std::error::Error for ManifestError {}

type R = Result<(), ManifestError>;

fn err(path: impl Into<String>, reason: Reason) -> R {
    Err(ManifestError {
        path: path.into(),
        reason,
    })
}

/// Bounded, non-empty, and free of control characters. Control characters are
/// refused because every string here is later rendered into text and CSV
/// reports, and a value that can rewrite a terminal or a spreadsheet row is
/// not an inventory entry.
pub(crate) fn text(path: &str, s: &str, max: usize) -> R {
    if s.is_empty() {
        return err(path, Reason::Empty);
    }
    if s.len() > max {
        return err(path, Reason::TooLong { max });
    }
    if s.chars().any(char::is_control) {
        return err(path, Reason::ControlCharacter);
    }
    Ok(())
}

fn opt_text(path: &str, s: &Option<String>, max: usize) -> R {
    match s {
        Some(v) => text(path, v, max),
        None => Ok(()),
    }
}

fn sha256_hex(path: &str, s: &str) -> R {
    let ok = s.len() == SHA256_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        err(path, Reason::NotSha256Hex)
    }
}

fn opt_sha256_hex(path: &str, s: &Option<String>) -> R {
    match s {
        Some(v) => sha256_hex(path, v),
        None => Ok(()),
    }
}

fn count(path: &str, n: usize) -> R {
    if n > MAX_ITEMS {
        err(path, Reason::TooMany { max: MAX_ITEMS })
    } else {
        Ok(())
    }
}

/// Reject duplicate keys in a collection the report treats as a set.
fn unique<K: Ord>(path: &str, keys: impl IntoIterator<Item = K>) -> R {
    let mut seen = BTreeSet::new();
    for k in keys {
        if !seen.insert(k) {
            return err(path, Reason::Duplicate);
        }
    }
    Ok(())
}

fn action(path: &str, a: &ScopeAction) -> R {
    match a {
        ScopeAction::Standard(_) => Ok(()),
        ScopeAction::Custom(s) => text(path, s, MAX_CUSTOM_ACTION_LEN),
    }
}

/// The action's canonical bytes, used as a set key so that duplicates are
/// detected exactly as the core would distinguish them.
fn action_key(a: &ScopeAction) -> Vec<u8> {
    let mut b = Vec::new();
    aip_types::canonical::encode_scope_action(&mut b, a);
    b
}

fn amount(path: &str, a: &Amount) -> R {
    let ok =
        a.currency.len() == CURRENCY_CODE_LEN && a.currency.bytes().all(|b| b.is_ascii_uppercase());
    if !ok {
        return err(format!("{path}.currency"), Reason::BadCurrency);
    }
    if a.exponent > MAX_AMOUNT_EXPONENT {
        return err(
            format!("{path}.exponent"),
            Reason::ExponentTooLarge {
                max: MAX_AMOUNT_EXPONENT,
            },
        );
    }
    Ok(())
}

pub(crate) fn manifest(m: &Manifest) -> R {
    if m.schema_version != AIBOM_SCHEMA_VERSION {
        return err(
            "$.schema_version",
            Reason::UnsupportedSchema {
                found: m.schema_version,
                supported: AIBOM_SCHEMA_VERSION,
            },
        );
    }
    validity(&m.validity)?;
    agent(&m.agent)?;
    models(&m.models)?;
    frameworks(&m.frameworks)?;
    tools(&m.tools)?;
    permissions(&m.permissions)?;
    data(&m.data_access)?;
    environment(&m.environment)?;
    relationships(&m.relationships)?;
    controls(&m.security_controls)?;
    crypto(&m.crypto)?;
    supply(&m.supply_chain)?;
    governance(&m.governance)
}

fn validity(v: &Validity) -> R {
    match v.valid_until_ms {
        Some(until) if until <= v.issued_at_ms => {
            err("$.validity.valid_until_ms", Reason::WindowInverted)
        }
        _ => Ok(()),
    }
}

fn agent(a: &AgentIdentity) -> R {
    text("$.agent.id", &a.id, MAX_ID_LEN)?;
    text("$.agent.name", &a.name, MAX_TEXT_LEN)?;
    text("$.agent.owner", &a.owner, MAX_TEXT_LEN)?;
    text("$.agent.version", &a.version, MAX_TEXT_LEN)?;
    text("$.agent.deployment", &a.deployment, MAX_TEXT_LEN)
}

fn models(ms: &[Model]) -> R {
    count("$.models", ms.len())?;
    for (i, m) in ms.iter().enumerate() {
        let p = format!("$.models[{i}]");
        text(&format!("{p}.provider"), &m.provider, MAX_ID_LEN)?;
        text(&format!("{p}.model"), &m.model, MAX_ID_LEN)?;
        opt_text(&format!("{p}.version"), &m.version, MAX_TEXT_LEN)?;
        opt_sha256_hex(&format!("{p}.weight_sha256"), &m.weight_sha256)?;
    }
    unique(
        "$.models",
        ms.iter().map(|m| (m.provider.as_str(), m.model.as_str())),
    )
}

fn frameworks(fs: &[Framework]) -> R {
    count("$.frameworks", fs.len())?;
    for (i, f) in fs.iter().enumerate() {
        text(&format!("$.frameworks[{i}].name"), &f.name, MAX_ID_LEN)?;
        text(
            &format!("$.frameworks[{i}].version"),
            &f.version,
            MAX_TEXT_LEN,
        )?;
    }
    unique("$.frameworks", fs.iter().map(|f| f.name.as_str()))
}

fn tools(ts: &[Tool]) -> R {
    count("$.tools", ts.len())?;
    for (i, t) in ts.iter().enumerate() {
        let p = format!("$.tools[{i}]");
        text(&format!("{p}.id"), &t.id, MAX_ID_LEN)?;
        count(&format!("{p}.actions"), t.actions.len())?;
        for (j, a) in t.actions.iter().enumerate() {
            text(&format!("{p}.actions[{j}]"), a, MAX_ID_LEN)?;
        }
        unique(&format!("{p}.actions"), t.actions.iter())?;
        opt_text(&format!("{p}.endpoint"), &t.endpoint, MAX_TEXT_LEN)?;
    }
    unique("$.tools", ts.iter().map(|t| t.id.as_str()))
}

fn permissions(p: &Permissions) -> R {
    count("$.permissions.allowed", p.allowed.len())?;
    for (i, a) in p.allowed.iter().enumerate() {
        action(&format!("$.permissions.allowed[{i}]"), a)?;
    }
    unique("$.permissions.allowed", p.allowed.iter().map(action_key))?;

    count("$.permissions.limits", p.limits.len())?;
    for (i, l) in p.limits.iter().enumerate() {
        let path = format!("$.permissions.limits[{i}]");
        action(&format!("{path}.action"), &l.action)?;
        amount(&format!("{path}.max"), &l.max)?;
    }
    unique(
        "$.permissions.limits",
        p.limits.iter().map(|l| (action_key(&l.action), l.per)),
    )?;

    count("$.permissions.approval_gates", p.approval_gates.len())?;
    for (i, g) in p.approval_gates.iter().enumerate() {
        let path = format!("$.permissions.approval_gates[{i}]");
        action(&format!("{path}.action"), &g.action)?;
        amount(&format!("{path}.above"), &g.above)?;
        text(&format!("{path}.approver"), &g.approver, MAX_TEXT_LEN)?;
    }
    unique(
        "$.permissions.approval_gates",
        p.approval_gates.iter().map(|g| action_key(&g.action)),
    )
}

fn data(ds: &[DataAccess]) -> R {
    count("$.data_access", ds.len())?;
    for (i, d) in ds.iter().enumerate() {
        text(
            &format!("$.data_access[{i}].resource"),
            &d.resource,
            MAX_ID_LEN,
        )?;
    }
    unique("$.data_access", ds.iter().map(|d| d.resource.as_str()))
}

fn environment(e: &Environment) -> R {
    if let Some(b) = &e.binary {
        sha256_hex("$.environment.binary.exe_sha256", &b.exe_sha256)?;
        opt_text("$.environment.binary.exe_path", &b.exe_path, MAX_TEXT_LEN)?;
    }
    Ok(())
}

fn relationships(r: &Relationships) -> R {
    opt_text("$.relationships.parent_agent", &r.parent_agent, MAX_ID_LEN)?;
    for (field, list) in [
        ("delegated_from", &r.delegated_from),
        ("delegates_to", &r.delegates_to),
    ] {
        let path = format!("$.relationships.{field}");
        count(&path, list.len())?;
        for (i, s) in list.iter().enumerate() {
            text(&format!("{path}[{i}]"), s, MAX_ID_LEN)?;
        }
        unique(&path, list.iter())?;
    }
    Ok(())
}

fn controls(cs: &[SecurityControl]) -> R {
    count("$.security_controls", cs.len())?;
    for (i, c) in cs.iter().enumerate() {
        text(
            &format!("$.security_controls[{i}].description"),
            &c.description,
            MAX_TEXT_LEN,
        )?;
    }
    unique(
        "$.security_controls",
        cs.iter().map(|c| (c.kind, c.description.as_str())),
    )
}

fn crypto(c: &CryptoPosture) -> R {
    count("$.crypto.signing", c.signing.len())?;
    for (i, s) in c.signing.iter().enumerate() {
        text(&format!("$.crypto.signing[{i}]"), s, MAX_ID_LEN)?;
    }
    unique("$.crypto.signing", c.signing.iter())
}

fn supply(ss: &[SupplyComponent]) -> R {
    count("$.supply_chain", ss.len())?;
    for (i, s) in ss.iter().enumerate() {
        let p = format!("$.supply_chain[{i}]");
        text(&format!("{p}.component"), &s.component, MAX_ID_LEN)?;
        text(&format!("{p}.version"), &s.version, MAX_TEXT_LEN)?;
        opt_sha256_hex(&format!("{p}.sha256"), &s.sha256)?;
        opt_text(&format!("{p}.origin"), &s.origin, MAX_TEXT_LEN)?;
    }
    unique("$.supply_chain", ss.iter().map(|s| s.component.as_str()))
}

fn governance(g: &Governance) -> R {
    opt_text("$.governance.risk_class", &g.risk_class, MAX_TEXT_LEN)?;
    opt_text("$.governance.audit_owner", &g.audit_owner, MAX_TEXT_LEN)?;
    count("$.governance.policies", g.policies.len())?;
    for (i, p) in g.policies.iter().enumerate() {
        text(&format!("$.governance.policies[{i}]"), p, MAX_TEXT_LEN)?;
    }
    unique("$.governance.policies", g.policies.iter())
}
