//! Manifest parsing and validation (A1, A13). Every refusal is fail-closed and
//! names the field.

mod common;

use aip_aibom::model::{Manifest, ManifestError, Reason};
use common::*;
use serde_json::{json, Value};

fn base() -> Value {
    serde_json::to_value(manifest("agent-payment-001")).unwrap()
}

fn parse(v: &Value) -> Result<Manifest, ManifestError> {
    Manifest::from_json(&serde_json::to_vec(v).unwrap())
}

fn reason(v: &Value) -> Reason {
    parse(v).unwrap_err().reason
}

#[test]
fn a_minimal_manifest_round_trips() {
    let m = parse(&base()).unwrap();
    assert_eq!(m, manifest("agent-payment-001"));
}

/// **A1.** There is nowhere to write a standing. A manifest that tries is
/// refused, at the top level and inside a component, rather than having the
/// key silently ignored where a human might still read it.
#[test]
fn a_manifest_cannot_assert_its_own_standing() {
    let mut v = base();
    v["verified"] = json!(true);
    assert!(matches!(reason(&v), Reason::Malformed(_)));

    let mut v = base();
    v["tools"] = json!([{"id": "payments-api", "kind": "api", "basis": "verified"}]);
    assert!(matches!(reason(&v), Reason::Malformed(_)));

    let mut v = base();
    v["permissions"] = json!({"allowed": [], "signature_status": "verified"});
    assert!(matches!(reason(&v), Reason::Malformed(_)));
}

#[test]
fn an_unsupported_schema_version_is_refused() {
    let mut v = base();
    v["schema_version"] = json!(2);
    assert_eq!(
        reason(&v),
        Reason::UnsupportedSchema {
            found: 2,
            supported: 1
        }
    );
}

/// **A13.** Amounts are integers with an explicit currency and scale. A float
/// is not representable; a currency or scale that cannot be read is refused.
#[test]
fn an_amount_must_be_an_integer_with_currency_and_scale() {
    let limit = |amount: Value| {
        let mut v = base();
        v["permissions"] = json!({"limits": [{
            "action": {"Custom": "create_payment"}, "per": "per_action", "max": amount
        }]});
        v
    };
    assert!(parse(&limit(
        json!({"minor_units": 100000, "currency": "USD", "exponent": 2})
    ))
    .is_ok());
    assert!(matches!(
        reason(&limit(
            json!({"minor_units": 1000.5, "currency": "USD", "exponent": 2})
        )),
        Reason::Malformed(_)
    ));
    assert!(matches!(
        reason(&limit(json!({"minor_units": 1000, "currency": "USD"}))),
        Reason::Malformed(_)
    ));
    assert_eq!(
        reason(&limit(
            json!({"minor_units": 1, "currency": "usd", "exponent": 2})
        )),
        Reason::BadCurrency
    );
    assert_eq!(
        reason(&limit(
            json!({"minor_units": 1, "currency": "USDT", "exponent": 2})
        )),
        Reason::BadCurrency
    );
    assert_eq!(
        reason(&limit(
            json!({"minor_units": 1, "currency": "USD", "exponent": 10})
        )),
        Reason::ExponentTooLarge { max: 9 }
    );
}

#[test]
fn duplicates_in_a_set_are_refused() {
    let mut v = base();
    v["tools"] = json!([
        {"id": "payments-api", "kind": "api"},
        {"id": "payments-api", "kind": "mcp"}
    ]);
    assert_eq!(reason(&v), Reason::Duplicate);

    let mut v = base();
    v["permissions"] = json!({"allowed": [{"Custom": "pay"}, {"Custom": "pay"}]});
    assert_eq!(reason(&v), Reason::Duplicate);
}

/// Strings reach terminal and spreadsheet reports. A control character is
/// refused at the door.
#[test]
fn control_characters_are_refused() {
    let mut v = base();
    v["agent"]["name"] = json!("Treasury\u{1b}[2J Agent");
    let e = parse(&v).unwrap_err();
    assert_eq!(e.reason, Reason::ControlCharacter);
    assert_eq!(e.path, "$.agent.name");
}

#[test]
fn digests_must_be_lowercase_sha256_hex() {
    let bin = |d: &str| {
        let mut v = base();
        v["environment"]["binary"] = json!({"exe_sha256": d});
        v
    };
    assert!(parse(&bin(&"a".repeat(64))).is_ok());
    assert_eq!(reason(&bin(&"A".repeat(64))), Reason::NotSha256Hex);
    assert_eq!(reason(&bin(&"a".repeat(63))), Reason::NotSha256Hex);
    assert_eq!(
        reason(&bin("sha256:<computed-digest>")),
        Reason::NotSha256Hex
    );
}

#[test]
fn an_inverted_validity_window_is_refused() {
    let mut v = base();
    v["validity"] = json!({"issued_at_ms": 100, "valid_until_ms": 100});
    assert_eq!(reason(&v), Reason::WindowInverted);
}

#[test]
fn a_custom_action_must_fit_the_core_bound() {
    let mut v = base();
    v["permissions"] = json!({"allowed": [{"Custom": "x".repeat(65)}]});
    assert_eq!(reason(&v), Reason::TooLong { max: 64 });
}

#[test]
fn collections_are_bounded() {
    let mut v = base();
    let many: Vec<Value> = (0..513)
        .map(|i| json!({"name": format!("f{i}"), "version": "1"}))
        .collect();
    v["frameworks"] = Value::Array(many);
    assert_eq!(reason(&v), Reason::TooMany { max: 512 });
}

#[test]
fn empty_required_text_is_refused() {
    let mut v = base();
    v["agent"]["owner"] = json!("");
    let e = parse(&v).unwrap_err();
    assert_eq!(
        (e.path.as_str(), e.reason),
        ("$.agent.owner", Reason::Empty)
    );
}
