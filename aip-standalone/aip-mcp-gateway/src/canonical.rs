//! Deterministic canonical JSON, so a commitment over tool arguments is the
//! same on the AIRI SDK and the gateway that received it.
//!
//! # Why not `serde_json::to_vec`
//!
//! Object key order in JSON is not significant, and a client, an SDK and a
//! gateway serialising the same arguments will not agree on it, nor on
//! whitespace. A commitment computed over a non-canonical encoding would
//! diverge on a byte that carries no meaning, turning an honest request into a
//! false `ReceiptDoesNotMatchAuthorization`. So the encoding here fixes the
//! two free choices: **object keys are sorted**, and there is **no
//! insignificant whitespace**. Numbers are left as `serde_json` renders them;
//! callers that need cross-language number canonicalisation (integers vs
//! floats) should agree an integer-only argument convention, which the pilot
//! does.
//!
//! This is a small, self-contained canonicaliser rather than a dependency: the
//! rule is four lines of intent, and a commitment function that everyone must
//! agree on should have no moving parts a reader cannot see.

use serde_json::Value;

/// Canonical UTF-8 bytes of a JSON value: object keys sorted, no insignificant
/// whitespace, arrays in order (array order *is* significant).
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

/// The gateway's AIRI parameter commitment over canonical argument bytes.
/// This matches Python `commit_json` and Rust `aip_airi::parameter_commitment`.
pub fn args_commitment(value: &Value) -> [u8; 32] {
    aip_airi::parameter_commitment(&canonical_json_bytes(value))
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        // `serde_json`'s own rendering of a number is deterministic for a given
        // in-memory value; it is not re-parsed here.
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // The one canonicalisation that matters: sort keys.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(k, out);
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
    }
}

/// A JSON string literal with the minimal required escaping. Matches the set
/// `serde_json` escapes, so a canonical string equals a compact `serde_json`
/// string for the same value.
fn write_json_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::sha256;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_the_commitment() {
        let a = json!({"beneficiary": "acct-9", "amount": 500, "currency": "INR"});
        let b = json!({"currency": "INR", "amount": 500, "beneficiary": "acct-9"});
        assert_eq!(args_commitment(&a), args_commitment(&b));
    }

    #[test]
    fn a_changed_value_changes_the_commitment() {
        let a = json!({"amount": 500, "beneficiary": "acct-9"});
        let b = json!({"amount": 5000, "beneficiary": "acct-9"});
        assert_ne!(args_commitment(&a), args_commitment(&b));
    }

    #[test]
    fn array_order_is_significant() {
        let a = json!({"to": ["a", "b"]});
        let b = json!({"to": ["b", "a"]});
        assert_ne!(args_commitment(&a), args_commitment(&b));
    }

    #[test]
    fn nested_objects_are_canonicalised_recursively() {
        let a = json!({"outer": {"z": 1, "a": 2}});
        let b = json!({"outer": {"a": 2, "z": 1}});
        assert_eq!(args_commitment(&a), args_commitment(&b));
    }

    #[test]
    fn whitespace_and_compact_forms_agree() {
        let spaced: Value = serde_json::from_str("{ \"amount\" : 500 }").unwrap();
        let compact: Value = serde_json::from_str("{\"amount\":500}").unwrap();
        assert_eq!(args_commitment(&spaced), args_commitment(&compact));
    }

    #[test]
    fn strings_needing_escapes_round_trip_stably() {
        let a = json!({"note": "line1\nline2\t\"q\""});
        let b: Value = serde_json::from_str(r#"{"note":"line1\nline2\t\"q\""}"#).unwrap();
        assert_eq!(args_commitment(&a), args_commitment(&b));
    }

    #[test]
    fn shared_python_airi_parameter_commitment_vector_matches() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../sdk/python/tests/parameter_commitment_vector.json"
        ))
        .unwrap();
        let arguments = &vector["arguments"];
        let canonical = vector["canonical_utf8"].as_str().unwrap().as_bytes();
        assert_eq!(canonical_json_bytes(arguments), canonical);
        assert_eq!(
            hex::encode(args_commitment(arguments)),
            vector["commitment_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(sha256(canonical)),
            vector["bare_sha256_hex"].as_str().unwrap()
        );
        assert_ne!(args_commitment(arguments), sha256(canonical));
        assert_eq!(crate::response_commitment(arguments), sha256(canonical));
    }

    #[test]
    fn argument_commitment_is_domain_separated_and_nested_values_are_canonical() {
        let a = json!({"outer":{"z":[1,{"b":true,"a":null}],"a":"x"}});
        let b = json!({"outer":{"a":"x","z":[1,{"a":null,"b":true}]}});
        assert_eq!(args_commitment(&a), args_commitment(&b));
        assert_ne!(args_commitment(&a), sha256(&canonical_json_bytes(&a)));
        assert_ne!(
            args_commitment(&a),
            args_commitment(&json!({"outer":{"a":"y","z":[1,{"a":null,"b":true}]}}))
        );
    }
}
