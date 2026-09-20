//! Turning an HTTP request into the canonical arguments a receipt commits to.
//!
//! # The property this module has to have
//!
//! A commitment is worth something only if **one request has one reading**. An
//! HTTP request carries arguments in three places — the path template, the
//! query string and the body — and every web framework merges them slightly
//! differently. If the gateway's reading could differ from the upstream
//! service's, the receipt commits to arguments the tool never saw, and the
//! whole boundary is decoration.
//!
//! So this module refuses every case where the reading is not forced:
//!
//! * **A repeated query key.** `?id=1&id=2` has no single canonical reading:
//!   some frameworks take the first, some the last, some build a list. A
//!   commitment whose value depends on which framework the upstream happens to
//!   use is not a commitment.
//! * **A body that is not a JSON object.** An array or a scalar has no named
//!   arguments to merge, and inventing a name for it would be the gateway
//!   deciding what the request meant.
//! * **The same name from two sources.** If the path says `id=7` and the body
//!   says `id=9`, the gateway does not know which the tool will use. Picking
//!   one is a guess; guessing is what this system exists not to do.
//!
//! Each of those is a refusal, and each refusal is still receipted where a
//! tool and a decision were named — see [`crate::issue`].
//!
//! # Why values stay strings from the path and query
//!
//! `/orbits/25544` yields `"25544"`, not `25544`. The gateway does not know
//! the upstream's schema and must not infer a type: `"007"` and `7` are
//! different strings and the same integer, and choosing for the upstream would
//! make the commitment depend on a guess. A decision point that authorises
//! this tool commits over the same string form.

use serde_json::{Map, Value};

/// Why a request could not be canonicalised into arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentError {
    /// A body was present and is not valid JSON.
    BodyNotJson,
    /// A body was present and is JSON, but not an object.
    BodyNotObject,
    /// A query key appeared more than once.
    RepeatedQueryKey(String),
    /// One name arrived from two of {path, query, body}.
    Collision {
        name: String,
        first: Source,
        second: Source,
    },
}

/// Where an argument came from. Named in a collision so an operator can fix
/// the route map or the caller rather than guess which side to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Path,
    Query,
    Body,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Body => "body",
        }
    }
}

/// Assemble the canonical argument object from the three places HTTP puts
/// arguments.
///
/// `path_arguments` come from the route template (already matched),
/// `query` is the raw query string without its leading `?`, and `body` is the
/// request body if one was sent. Order of the three sources does not affect
/// the result: any overlap is a refusal, so there is nothing for precedence
/// to decide.
pub fn assemble_arguments(
    path_arguments: &[(String, String)],
    query: Option<&str>,
    body: Option<&[u8]>,
) -> Result<Value, ArgumentError> {
    let mut out: Map<String, Value> = Map::new();
    let mut origin: Vec<(String, Source)> = Vec::new();

    let insert = |name: String,
                  value: Value,
                  source: Source,
                  out: &mut Map<String, Value>,
                  origin: &mut Vec<(String, Source)>|
     -> Result<(), ArgumentError> {
        if let Some((_, first)) = origin.iter().find(|(n, _)| *n == name) {
            return Err(ArgumentError::Collision {
                name,
                first: *first,
                second: source,
            });
        }
        origin.push((name.clone(), source));
        out.insert(name, value);
        Ok(())
    };

    for (name, value) in path_arguments {
        insert(
            name.clone(),
            Value::String(value.clone()),
            Source::Path,
            &mut out,
            &mut origin,
        )?;
    }

    if let Some(query) = query.filter(|q| !q.is_empty()) {
        let mut seen: Vec<String> = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (percent_decode(k), percent_decode(v)),
                // A bare flag is the empty string, not `true`: the gateway does
                // not know the upstream's convention for a valueless key.
                None => (percent_decode(pair), String::new()),
            };
            if seen.contains(&key) {
                return Err(ArgumentError::RepeatedQueryKey(key));
            }
            seen.push(key.clone());
            insert(
                key,
                Value::String(value),
                Source::Query,
                &mut out,
                &mut origin,
            )?;
        }
    }

    if let Some(body) = body.filter(|b| !b.is_empty()) {
        let parsed: Value = serde_json::from_slice(body).map_err(|_| ArgumentError::BodyNotJson)?;
        let Value::Object(fields) = parsed else {
            return Err(ArgumentError::BodyNotObject);
        };
        for (name, value) in fields {
            insert(name, value, Source::Body, &mut out, &mut origin)?;
        }
    }

    Ok(Value::Object(out))
}

/// Percent-decoding for one query component, with `+` as space.
///
/// Written here rather than taken as a dependency: it is twenty lines, the
/// behaviour has to be pinned by this crate's own tests because a commitment
/// depends on it, and a malformed escape must **not** be silently dropped —
/// `%zz` stays the literal three characters, so two different query strings
/// cannot decode to the same arguments.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    // Not an escape. Keep it verbatim rather than dropping it.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // Invalid UTF-8 is replaced rather than refused: the bytes are still
    // committed to deterministically, and refusing here would reject requests
    // the upstream would have served.
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn q01_the_three_sources_merge_into_one_object() {
        let args = assemble_arguments(
            &path(&[("norad", "25544")]),
            Some("points=180"),
            Some(br#"{"engine":"sgp4"}"#),
        )
        .unwrap();
        assert_eq!(
            args,
            serde_json::json!({"norad": "25544", "points": "180", "engine": "sgp4"})
        );
    }

    #[test]
    fn q02_path_and_query_values_stay_strings() {
        // The gateway does not know the upstream's schema. "007" and 7 are
        // different strings and the same integer; choosing would make the
        // commitment depend on a guess.
        let args = assemble_arguments(&path(&[("id", "007")]), Some("n=7"), None).unwrap();
        assert_eq!(args["id"], Value::String("007".into()));
        assert_eq!(args["n"], Value::String("7".into()));
    }

    #[test]
    fn q03_body_types_are_preserved_because_json_carries_them() {
        let args = assemble_arguments(&[], None, Some(br#"{"n":7,"ok":true,"x":null}"#)).unwrap();
        assert_eq!(args["n"], serde_json::json!(7));
        assert_eq!(args["ok"], serde_json::json!(true));
        assert_eq!(args["x"], Value::Null);
    }

    #[test]
    fn q04_a_repeated_query_key_is_refused() {
        // No single canonical reading exists across frameworks.
        let e = assemble_arguments(&[], Some("id=1&id=2"), None).unwrap_err();
        assert_eq!(e, ArgumentError::RepeatedQueryKey("id".into()));
    }

    #[test]
    fn q05_a_non_object_body_is_refused() {
        assert_eq!(
            assemble_arguments(&[], None, Some(b"[1,2]")).unwrap_err(),
            ArgumentError::BodyNotObject
        );
        assert_eq!(
            assemble_arguments(&[], None, Some(b"7")).unwrap_err(),
            ArgumentError::BodyNotObject
        );
        assert_eq!(
            assemble_arguments(&[], None, Some(b"{not json")).unwrap_err(),
            ArgumentError::BodyNotJson
        );
    }

    #[test]
    fn q06_a_name_from_two_sources_is_refused_and_both_are_named() {
        let e = assemble_arguments(&path(&[("id", "7")]), None, Some(br#"{"id":9}"#)).unwrap_err();
        assert_eq!(
            e,
            ArgumentError::Collision {
                name: "id".into(),
                first: Source::Path,
                second: Source::Body
            }
        );
        let e = assemble_arguments(&[], Some("id=7"), Some(br#"{"id":9}"#)).unwrap_err();
        assert!(matches!(
            e,
            ArgumentError::Collision {
                first: Source::Query,
                second: Source::Body,
                ..
            }
        ));
    }

    #[test]
    fn q07_an_absent_or_empty_body_is_not_an_error() {
        assert_eq!(
            assemble_arguments(&[], None, None).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            assemble_arguments(&[], Some(""), Some(b"")).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn q08_percent_and_plus_decoding_is_pinned_by_this_crate() {
        let args = assemble_arguments(&[], Some("q=a%20b+c&dest=%2Ftmp%2Fx"), None).unwrap();
        assert_eq!(args["q"], Value::String("a b c".into()));
        assert_eq!(args["dest"], Value::String("/tmp/x".into()));
    }

    #[test]
    fn q09_a_malformed_escape_is_kept_verbatim_not_dropped() {
        // Dropping it would let two different query strings decode to the same
        // arguments, and therefore to the same commitment.
        let a = assemble_arguments(&[], Some("q=%zz"), None).unwrap();
        let b = assemble_arguments(&[], Some("q=zz"), None).unwrap();
        assert_eq!(a["q"], Value::String("%zz".into()));
        assert_ne!(a["q"], b["q"]);
    }

    #[test]
    fn q10_a_valueless_key_is_the_empty_string_not_true() {
        let args = assemble_arguments(&[], Some("verbose"), None).unwrap();
        assert_eq!(args["verbose"], Value::String(String::new()));
    }
}
