//! Change detection between two versions of one agent's manifest.
//!
//! Every change is reported with a **direction**: `Widening` when the agent
//! can now do more, reach more or is held to less; `Narrowing` for the
//! reverse; `Neutral` when the change does not itself determine either (a
//! version bump). Where direction cannot be read off the change — a limit
//! re-expressed in another currency, an access mode swapped for a different
//! one — it is `Widening`: the previous guarantee can no longer be compared,
//! so it no longer holds.

use crate::assess::authority_label as action_label;
use crate::model::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Whether a change grows or shrinks what the agent may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Widening,
    Narrowing,
    Neutral,
}

/// What changed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed {
        from: String,
        to: String,
    },
    /// An amount now in a different currency or scale: not comparable.
    Redenominated {
        from: String,
        to: String,
    },
}

/// One change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Change {
    pub direction: Direction,
    pub component: Component,
    pub key: String,
    pub change: ChangeKind,
}

/// Every change from `old` to `new`, in report order.
pub fn diff(old: &Manifest, new: &Manifest) -> Vec<Change> {
    let mut out = Vec::new();
    identity(old, new, &mut out);
    keyed_sets(old, new, &mut out);
    limits(old, new, &mut out);
    gates(old, new, &mut out);
    data(old, new, &mut out);
    environment(old, new, &mut out);
    relationships(old, new, &mut out);
    crypto(old, new, &mut out);
    validity(old, new, &mut out);
    if old.governance != new.governance {
        push(
            &mut out,
            Direction::Neutral,
            Component::Governance,
            "governance",
            changed(&old.governance, &new.governance),
        );
    }
    out.sort();
    out
}

/// True when any change widens what the agent may do.
pub fn widens(changes: &[Change]) -> bool {
    changes.iter().any(|c| c.direction == Direction::Widening)
}

fn push(
    out: &mut Vec<Change>,
    direction: Direction,
    component: Component,
    key: impl Into<String>,
    change: ChangeKind,
) {
    out.push(Change {
        direction,
        component,
        key: key.into(),
        change,
    });
}

fn changed<T: std::fmt::Debug>(from: &T, to: &T) -> ChangeKind {
    ChangeKind::Changed {
        from: format!("{from:?}"),
        to: format!("{to:?}"),
    }
}

/// Added → `on_add`, removed → the opposite; present in both with a different
/// value → `on_change`.
fn compare_map<V: PartialEq + std::fmt::Debug>(
    out: &mut Vec<Change>,
    component: Component,
    old: BTreeMap<String, V>,
    new: BTreeMap<String, V>,
    on_add: Direction,
    on_change: Direction,
) {
    let on_remove = match on_add {
        Direction::Widening => Direction::Narrowing,
        Direction::Narrowing => Direction::Widening,
        Direction::Neutral => Direction::Neutral,
    };
    for (k, v) in &new {
        match old.get(k) {
            None => push(out, on_add, component, k.clone(), ChangeKind::Added),
            Some(o) if o != v => push(out, on_change, component, k.clone(), changed(o, v)),
            Some(_) => {}
        }
    }
    for k in old.keys().filter(|k| !new.contains_key(*k)) {
        push(out, on_remove, component, k.clone(), ChangeKind::Removed);
    }
}

fn identity(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    if old.agent.id != new.agent.id {
        push(
            out,
            Direction::Widening,
            Component::Identity,
            "agent.id",
            changed(&old.agent.id, &new.agent.id),
        );
    }
    for (k, a, b) in [
        ("agent.name", &old.agent.name, &new.agent.name),
        ("agent.owner", &old.agent.owner, &new.agent.owner),
        ("agent.version", &old.agent.version, &new.agent.version),
        (
            "agent.deployment",
            &old.agent.deployment,
            &new.agent.deployment,
        ),
    ] {
        if a != b {
            push(
                out,
                Direction::Neutral,
                Component::Identity,
                k,
                changed(a, b),
            );
        }
    }
}

fn keyed_sets(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let models = |m: &Manifest| -> BTreeMap<String, (Option<String>, Hosting, Option<String>)> {
        m.models
            .iter()
            .map(|x| {
                (
                    format!("{}/{}", x.provider, x.model),
                    (x.version.clone(), x.hosting, x.weight_sha256.clone()),
                )
            })
            .collect()
    };
    compare_map(
        out,
        Component::Models,
        models(old),
        models(new),
        Direction::Widening,
        Direction::Widening,
    );

    let fw = |m: &Manifest| -> BTreeMap<String, String> {
        m.frameworks
            .iter()
            .map(|f| (f.name.clone(), f.version.clone()))
            .collect()
    };
    compare_map(
        out,
        Component::Frameworks,
        fw(old),
        fw(new),
        Direction::Widening,
        Direction::Neutral,
    );

    let tools = |m: &Manifest| -> BTreeMap<String, (ToolKind, BTreeSet<String>, Option<String>)> {
        m.tools
            .iter()
            .map(|t| {
                (
                    t.id.clone(),
                    (
                        t.kind,
                        t.actions.iter().cloned().collect(),
                        t.endpoint.clone(),
                    ),
                )
            })
            .collect()
    };
    compare_map(
        out,
        Component::Tools,
        tools(old),
        tools(new),
        Direction::Widening,
        Direction::Widening,
    );

    let allowed = |m: &Manifest| -> BTreeMap<String, ()> {
        m.permissions
            .allowed
            .iter()
            .map(|a| (action_label(a), ()))
            .collect()
    };
    compare_map(
        out,
        Component::Permissions,
        allowed(old),
        allowed(new),
        Direction::Widening,
        Direction::Neutral,
    );

    let controls = |m: &Manifest| -> BTreeMap<String, ()> {
        m.security_controls
            .iter()
            .map(|c| (format!("{:?}:{}", c.kind, c.description), ()))
            .collect()
    };
    compare_map(
        out,
        Component::SecurityControls,
        controls(old),
        controls(new),
        Direction::Narrowing,
        Direction::Neutral,
    );

    let supply = |m: &Manifest| -> BTreeMap<String, (String, Option<String>, Option<String>)> {
        m.supply_chain
            .iter()
            .map(|s| {
                (
                    s.component.clone(),
                    (s.version.clone(), s.sha256.clone(), s.origin.clone()),
                )
            })
            .collect()
    };
    compare_map(
        out,
        Component::SupplyChain,
        supply(old),
        supply(new),
        Direction::Widening,
        Direction::Neutral,
    );
}

fn amount_label(a: &Amount) -> String {
    format!("{} {} e-{}", a.minor_units, a.currency, a.exponent)
}

/// Compare two amounts on one scale. `None` when the scales differ.
fn compare_amounts(a: &Amount, b: &Amount) -> Option<std::cmp::Ordering> {
    (a.currency == b.currency && a.exponent == b.exponent)
        .then(|| a.minor_units.cmp(&b.minor_units))
}

fn limits(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let key = |l: &Limit| format!("{}/{:?}", action_label(&l.action), l.per);
    let o: BTreeMap<String, &Amount> = old
        .permissions
        .limits
        .iter()
        .map(|l| (key(l), &l.max))
        .collect();
    let n: BTreeMap<String, &Amount> = new
        .permissions
        .limits
        .iter()
        .map(|l| (key(l), &l.max))
        .collect();
    amounts(out, Component::Permissions, "limit", o, n, true);
}

fn gates(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let o: BTreeMap<String, &ApprovalGate> = old
        .permissions
        .approval_gates
        .iter()
        .map(|g| (action_label(&g.action), g))
        .collect();
    let n: BTreeMap<String, &ApprovalGate> = new
        .permissions
        .approval_gates
        .iter()
        .map(|g| (action_label(&g.action), g))
        .collect();
    let oa = o.iter().map(|(k, g)| (k.clone(), &g.above)).collect();
    let na = n.iter().map(|(k, g)| (k.clone(), &g.above)).collect();
    amounts(out, Component::Permissions, "approval", oa, na, true);
    for (k, g) in &n {
        if let Some(og) = o.get(k) {
            if og.approver != g.approver {
                push(
                    out,
                    Direction::Neutral,
                    Component::Permissions,
                    format!("approval/{k}/approver"),
                    changed(&og.approver, &g.approver),
                );
            }
        }
    }
}

/// A cap: adding one narrows, removing one widens, raising one widens.
fn amounts(
    out: &mut Vec<Change>,
    component: Component,
    what: &str,
    old: BTreeMap<String, &Amount>,
    new: BTreeMap<String, &Amount>,
    is_cap: bool,
) {
    let (add, remove) = if is_cap {
        (Direction::Narrowing, Direction::Widening)
    } else {
        (Direction::Widening, Direction::Narrowing)
    };
    for (k, v) in &new {
        let key = format!("{what}/{k}");
        match old.get(k) {
            None => push(out, add, component, key, ChangeKind::Added),
            Some(o) => match compare_amounts(o, v) {
                Some(std::cmp::Ordering::Equal) => {}
                Some(std::cmp::Ordering::Less) => push(
                    out,
                    remove,
                    component,
                    key,
                    ChangeKind::Changed {
                        from: amount_label(o),
                        to: amount_label(v),
                    },
                ),
                Some(std::cmp::Ordering::Greater) => push(
                    out,
                    add,
                    component,
                    key,
                    ChangeKind::Changed {
                        from: amount_label(o),
                        to: amount_label(v),
                    },
                ),
                None => push(
                    out,
                    Direction::Widening,
                    component,
                    key,
                    ChangeKind::Redenominated {
                        from: amount_label(o),
                        to: amount_label(v),
                    },
                ),
            },
        }
    }
    for k in old.keys().filter(|k| !new.contains_key(*k)) {
        push(
            out,
            remove,
            component,
            format!("{what}/{k}"),
            ChangeKind::Removed,
        );
    }
}

fn data(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let map = |m: &Manifest| -> BTreeMap<String, (ResourceKind, Access)> {
        m.data_access
            .iter()
            .map(|d| (d.resource.clone(), (d.kind, d.access)))
            .collect()
    };
    let (o, n) = (map(old), map(new));
    for (k, (kind, access)) in &n {
        match o.get(k) {
            None => push(
                out,
                Direction::Widening,
                Component::DataAccess,
                k.clone(),
                ChangeKind::Added,
            ),
            Some((ok, oa)) if ok != kind || oa != access => {
                let narrower = ok == kind
                    && matches!(
                        (oa, access),
                        (Access::ReadWrite, Access::Read) | (Access::ReadWrite, Access::Write)
                    );
                let dir = if narrower {
                    Direction::Narrowing
                } else {
                    Direction::Widening
                };
                push(
                    out,
                    dir,
                    Component::DataAccess,
                    k.clone(),
                    changed(&(ok, oa), &(kind, access)),
                );
            }
            Some(_) => {}
        }
    }
    for k in o.keys().filter(|k| !n.contains_key(*k)) {
        push(
            out,
            Direction::Narrowing,
            Component::DataAccess,
            k.clone(),
            ChangeKind::Removed,
        );
    }
}

fn environment(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let (o, n) = (&old.environment, &new.environment);
    if o.runtime != n.runtime {
        push(
            out,
            Direction::Widening,
            Component::Environment,
            "runtime",
            changed(&o.runtime, &n.runtime),
        );
    }
    if o.network != n.network {
        let dir = match (o.network, n.network) {
            (NetworkPosture::Open, NetworkPosture::Restricted) => Direction::Narrowing,
            _ => Direction::Widening,
        };
        push(
            out,
            dir,
            Component::Environment,
            "network",
            changed(&o.network, &n.network),
        );
    }
    if o.binary != n.binary {
        push(
            out,
            Direction::Widening,
            Component::Environment,
            "binary",
            changed(&o.binary, &n.binary),
        );
    }
}

fn relationships(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let (o, n) = (&old.relationships, &new.relationships);
    if o.parent_agent != n.parent_agent {
        push(
            out,
            Direction::Widening,
            Component::Relationships,
            "parent_agent",
            changed(&o.parent_agent, &n.parent_agent),
        );
    }
    let set =
        |v: &[String]| -> BTreeMap<String, ()> { v.iter().map(|s| (s.clone(), ())).collect() };
    let before = out.len();
    compare_map(
        out,
        Component::Relationships,
        set(&o.delegated_from),
        set(&n.delegated_from),
        Direction::Widening,
        Direction::Neutral,
    );
    compare_map(
        out,
        Component::Relationships,
        set(&o.delegates_to),
        set(&n.delegates_to),
        Direction::Widening,
        Direction::Neutral,
    );
    for c in &mut out[before..] {
        c.key = format!("delegation/{}", c.key);
    }
}

fn crypto(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let (o, n) = (&old.crypto, &new.crypto);
    if o.identity_key_algorithm != n.identity_key_algorithm {
        push(
            out,
            Direction::Widening,
            Component::Cryptography,
            "identity_key_algorithm",
            changed(&o.identity_key_algorithm, &n.identity_key_algorithm),
        );
    }
    if o.post_quantum != n.post_quantum {
        push(
            out,
            Direction::Neutral,
            Component::Cryptography,
            "post_quantum",
            changed(&o.post_quantum, &n.post_quantum),
        );
    }
    if o.signing != n.signing {
        push(
            out,
            Direction::Neutral,
            Component::Cryptography,
            "signing",
            changed(&o.signing, &n.signing),
        );
    }
}

fn validity(old: &Manifest, new: &Manifest, out: &mut Vec<Change>) {
    let (o, n) = (old.validity.valid_until_ms, new.validity.valid_until_ms);
    let dir = match (o, n) {
        (Some(a), Some(b)) if b > a => Some(Direction::Widening),
        (Some(a), Some(b)) if b < a => Some(Direction::Narrowing),
        (Some(_), None) => Some(Direction::Widening),
        (None, Some(_)) => Some(Direction::Narrowing),
        _ => None,
    };
    if let Some(d) = dir {
        push(
            out,
            d,
            Component::Validity,
            "valid_until_ms",
            changed(&o, &n),
        );
    }
}
