//! CEF escaping.
//!
//! This is the whole security surface of a log exporter. A field that is
//! concatenated into a line without escaping lets whoever controls that
//! field inject a second event, or terminate the extension and append
//! attacker-chosen key/value pairs that an analyst then reads as facts the
//! system reported.
//!
//! The fields at risk here are not hypothetical: `reconciler_id` and
//! `agent_id` are strings that reach a verdict from outside, and a
//! `ReasonCode` rendering is fixed but a future one might not be.
//!
//! The rules are ArcSight's, and the two halves of a CEF line escape
//! **differently**:
//!
//! | Position | Escaped |
//! |---|---|
//! | header field (the seven `\|`-delimited fields) | `\` → `\\`, `\|` → `\\\|` |
//! | extension value | `\` → `\\`, `=` → `\=` |
//!
//! Newlines are escaped in both, to the two characters `\` and `n`. An
//! unescaped newline in either position ends the syslog record, and
//! everything after it becomes a new line in the analyst's console with no
//! marker that it came from one event.

/// Escape a CEF **header** field: `\` and `|`, plus line breaks.
///
/// `=` is deliberately *not* escaped here. It is not a delimiter in the
/// header, and escaping it would corrupt any identifier that contains one.
pub fn header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '|' => out.push_str(r"\|"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            c => out.push(c),
        }
    }
    out
}

/// Escape a CEF **extension** value: `\` and `=`, plus line breaks.
///
/// `|` is not escaped: past the seventh header field it is an ordinary
/// character, and escaping it would make values differ from what the
/// source actually held.
pub fn extension(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '=' => out.push_str(r"\="),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            c => out.push(c),
        }
    }
    out
}

/// Whether a string is usable as a CEF extension **key**.
///
/// Keys are not escapable: the format gives no way to express a space or an
/// `=` inside one, so a key containing either cannot be represented and
/// must be rejected rather than mangled. Every key this crate emits is a
/// compile-time constant, and [`crate::cef::CefEvent::to_cef`] is not the
/// place to discover that one is malformed — the test suite is.
pub fn is_valid_key(k: &str) -> bool {
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The injection that matters: a value that tries to close the header
    /// and start its own fields.
    #[test]
    fn a_pipe_in_a_header_field_cannot_open_a_new_field() {
        assert_eq!(header("bank|9|0|evil"), r"bank\|9\|0\|evil");
    }

    /// And the extension-side equivalent: a value that tries to start a new
    /// key.
    #[test]
    fn an_equals_in_an_extension_value_cannot_start_a_new_key() {
        assert_eq!(
            extension("x suser=root"),
            r"x suser\=root",
            "an injected key must stay inside the value it came from"
        );
    }

    /// A backslash must be escaped before anything else, or an attacker
    /// escapes the escape: `\|` supplied literally would otherwise emit
    /// `\\|`, which reads as an escaped backslash followed by a delimiter.
    #[test]
    fn a_backslash_cannot_neutralise_the_escaping() {
        assert_eq!(header(r"a\|b"), r"a\\\|b");
        assert_eq!(extension(r"a\=b"), r"a\\\=b");
    }

    /// A newline would end the syslog record and put the rest on a line of
    /// its own, indistinguishable from a separate event.
    #[test]
    fn line_breaks_cannot_terminate_the_record() {
        assert_eq!(header("a\nb"), r"a\nb");
        assert_eq!(extension("a\r\nb"), r"a\r\nb");
        for s in [header("a\nb"), extension("a\nb")] {
            assert!(!s.contains('\n'), "{s:?}");
        }
    }

    /// Escaping is confined to the delimiters of its own half. Over-
    /// escaping is not safe-by-default: it silently changes values.
    #[test]
    fn each_half_escapes_only_its_own_delimiters() {
        assert_eq!(header("a=b"), "a=b", "`=` is not a header delimiter");
        assert_eq!(extension("a|b"), "a|b", "`|` is not an extension delimiter");
    }

    /// Ordinary text passes through unchanged, including non-ASCII: a CEF
    /// line is UTF-8 and mangling an agent identifier helps no one.
    #[test]
    fn ordinary_text_is_unchanged() {
        for s in ["aip1LoanAgentXYZ", "core-banking-api", "παράδειγμα"] {
            assert_eq!(header(s), s);
            assert_eq!(extension(s), s);
        }
    }

    #[test]
    fn keys_reject_what_cef_cannot_express() {
        assert!(is_valid_key("aipResult"));
        assert!(is_valid_key("cs1Label"));
        assert!(is_valid_key("aip.decision_id"));
        for bad in ["", "has space", "has=equals", "has|pipe", "has\\slash"] {
            assert!(!is_valid_key(bad), "{bad:?}");
        }
    }
}
