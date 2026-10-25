//! Change detection. Every change carries a direction; where the change does
//! not determine one, it widens.

mod common;

use aip_aibom::diff::{diff, widens, ChangeKind, Direction};
use aip_aibom::model::*;
use common::*;

fn before() -> Manifest {
    let mut m = manifest("agent");
    m.tools = vec![Tool {
        id: "payments-api".into(),
        kind: ToolKind::Api,
        actions: vec!["read_balance".into()],
        endpoint: None,
    }];
    m.permissions.allowed = vec![custom("read_balance")];
    m.permissions.limits = vec![Limit {
        action: custom("create_payment"),
        per: LimitPeriod::PerAction,
        max: usd(1000),
    }];
    m.permissions.approval_gates = vec![ApprovalGate {
        action: custom("create_payment"),
        above: usd(500),
        approver: "cfo".into(),
    }];
    m.security_controls = vec![SecurityControl {
        kind: ControlKind::Sandbox,
        description: "gVisor".into(),
    }];
    m.data_access = vec![DataAccess {
        resource: "ledger-db".into(),
        kind: ResourceKind::Database,
        access: Access::ReadWrite,
    }];
    m
}

fn only(m: &Manifest) -> Vec<(Direction, String)> {
    diff(&before(), m)
        .into_iter()
        .map(|c| (c.direction, c.key))
        .collect()
}

#[test]
fn an_identical_manifest_has_no_changes() {
    assert!(diff(&before(), &before()).is_empty());
}

#[test]
fn reordering_is_not_a_change() {
    let mut m = before();
    m.tools.push(Tool {
        id: "b".into(),
        kind: ToolKind::Api,
        actions: vec![],
        endpoint: None,
    });
    let mut r = m.clone();
    r.tools.reverse();
    assert!(diff(&m, &r).is_empty());
}

#[test]
fn a_new_permission_widens_and_a_removed_one_narrows() {
    let mut m = before();
    m.permissions.allowed.push(custom("create_payment"));
    assert_eq!(
        only(&m),
        [(Direction::Widening, "custom:create_payment".into())]
    );
    let mut m = before();
    m.permissions.allowed.clear();
    assert_eq!(
        only(&m),
        [(Direction::Narrowing, "custom:read_balance".into())]
    );
}

#[test]
fn raising_a_limit_widens_and_lowering_it_narrows() {
    let mut m = before();
    m.permissions.limits[0].max = usd(5000);
    let c = diff(&before(), &m);
    assert_eq!(c[0].direction, Direction::Widening);
    assert!(matches!(c[0].change, ChangeKind::Changed { .. }));
    m.permissions.limits[0].max = usd(100);
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Narrowing);
}

/// A limit re-expressed in another currency cannot be compared without an
/// exchange rate this crate does not have. The old guarantee no longer holds.
#[test]
fn redenominating_a_limit_widens() {
    let mut m = before();
    m.permissions.limits[0].max = Amount {
        minor_units: 100_000,
        currency: "EUR".into(),
        exponent: 2,
    };
    let c = diff(&before(), &m);
    assert_eq!(c[0].direction, Direction::Widening);
    assert!(matches!(c[0].change, ChangeKind::Redenominated { .. }));
}

#[test]
fn removing_a_limit_or_an_approval_gate_widens() {
    let mut m = before();
    m.permissions.limits.clear();
    m.permissions.approval_gates.clear();
    let c = diff(&before(), &m);
    assert_eq!(c.len(), 2);
    assert!(c
        .iter()
        .all(|x| x.direction == Direction::Widening && x.change == ChangeKind::Removed));
}

#[test]
fn raising_an_approval_threshold_widens() {
    let mut m = before();
    m.permissions.approval_gates[0].above = usd(5000);
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Widening);
}

#[test]
fn removing_a_security_control_widens() {
    let mut m = before();
    m.security_controls.clear();
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Widening);
}

#[test]
fn a_new_tool_or_tool_action_widens() {
    let mut m = before();
    m.tools[0].actions.push("create_payment".into());
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Widening);
    let mut m = before();
    m.tools.push(Tool {
        id: "crm".into(),
        kind: ToolKind::Mcp,
        actions: vec![],
        endpoint: None,
    });
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Widening);
}

#[test]
fn opening_the_network_widens_and_restricting_it_narrows() {
    let mut m = before();
    m.environment.network = NetworkPosture::Open;
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Widening);
    assert_eq!(diff(&m, &before())[0].direction, Direction::Narrowing);
}

#[test]
fn narrowing_data_access_narrows_and_swapping_it_widens() {
    let mut m = before();
    m.data_access[0].access = Access::Read;
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Narrowing);
    let mut a = before();
    a.data_access[0].access = Access::Read;
    let mut b = before();
    b.data_access[0].access = Access::Write;
    assert_eq!(diff(&a, &b)[0].direction, Direction::Widening);
}

#[test]
fn a_different_agent_id_widens() {
    let m = manifest("someone-else");
    assert!(diff(&manifest("agent"), &m)
        .iter()
        .any(|c| c.key == "agent.id" && c.direction == Direction::Widening));
}

#[test]
fn extending_or_removing_the_validity_window_widens() {
    let mut m = before();
    m.validity.valid_until_ms = None;
    assert_eq!(diff(&before(), &m)[0].direction, Direction::Widening);
}

#[test]
fn a_version_bump_is_neutral_and_does_not_widen() {
    let mut m = before();
    m.agent.version = "1.3.0".into();
    let c = diff(&before(), &m);
    assert_eq!(c[0].direction, Direction::Neutral);
    assert!(!widens(&c));
}
