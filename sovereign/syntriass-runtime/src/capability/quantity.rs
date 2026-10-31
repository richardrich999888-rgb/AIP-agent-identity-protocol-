//! Unit-aware quantity extraction from free text. Deterministic and pure.
//!
//! This is runtime infrastructure, not part of any learned capability: the
//! unit spellings and conversion factors below are reviewed code. A
//! capability only *selects* quantity kinds and cue words; it cannot add a
//! unit or a conversion.
//!
//! Number rule: a decimal literal not preceded by a letter, digit, `-`, `.`
//! or `:` (so `M-7`, `CT-F2`, `14:30` and part numbers are not quantities).
//! A number followed by a recognised unit becomes a typed quantity in the
//! kind's canonical unit; a bare number is kept only when a cue word for a
//! dimensionless input precedes it.

use serde::{Deserialize, Serialize};

/// Physical kinds the runtime understands, each with one canonical unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// kilovolts
    Voltage,
    /// megohms
    Resistance,
    /// degrees Celsius
    Temperature,
    /// dimensionless value introduced by a cue word (e.g. "PI 2.1")
    Cued,
}

/// One quantity found in the text, in canonical units.
#[derive(Debug, Clone, PartialEq)]
pub struct Quantity {
    pub kind: Kind,
    pub value: f64,
    /// Char offset of the number in the text.
    pub at: usize,
}

/// Maximum characters scanned (bounds work on hostile input).
pub const MAX_TEXT_CHARS: usize = 4096;
/// Maximum characters between a cue word and its number.
const CUE_WINDOW: usize = 16;

fn is_unit_char(c: char) -> bool {
    c.is_ascii_alphabetic() || c == 'Ω' || c == '°' || c == '%'
}

/// Converts a value in a recognised unit to the kind's canonical unit.
type ToCanonical = fn(f64) -> f64;

/// Map a unit spelling to (kind, value → canonical). `next_word` supports
/// two-token spellings such as "deg C" or "degrees F".
fn unit(spelling: &str, next_word: &str) -> Option<(Kind, ToCanonical)> {
    fn id(v: f64) -> f64 {
        v
    }
    fn milli(v: f64) -> f64 {
        v / 1000.0
    }
    fn kilo(v: f64) -> f64 {
        v * 1000.0
    }
    fn f_to_c(v: f64) -> f64 {
        (v - 32.0) * 5.0 / 9.0
    }
    let s = spelling;
    let lower = s.to_ascii_lowercase();
    Some(match s {
        "kV" | "kv" | "KV" | "Kv" => (Kind::Voltage, id),
        "V" | "v" | "volt" | "volts" | "Volt" | "Volts" => (Kind::Voltage, milli),
        "MΩ" | "Mohm" | "MOhm" | "Mohms" | "MOHM" => (Kind::Resistance, id),
        "GΩ" | "Gohm" | "GOhm" | "Gohms" => (Kind::Resistance, kilo),
        "kΩ" | "kohm" | "kOhm" => (Kind::Resistance, milli),
        "°C" | "C" | "c" | "degC" | "degc" => (Kind::Temperature, id),
        "°F" | "F" | "degF" | "degf" => (Kind::Temperature, f_to_c),
        _ => match lower.as_str() {
            "megohm" | "megohms" | "megaohm" | "megaohms" => (Kind::Resistance, id),
            "gigohm" | "gigohms" | "gigaohm" | "gigaohms" => (Kind::Resistance, kilo),
            "deg" | "degree" | "degrees" => match next_word {
                "C" | "c" | "Celsius" | "celsius" => (Kind::Temperature, id),
                "F" | "Fahrenheit" | "fahrenheit" => (Kind::Temperature, f_to_c),
                _ => return None,
            },
            _ => return None,
        },
    })
}

/// A number literal found by the scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct NumberAt {
    pub value: f64,
    pub start: usize,
    pub end: usize,
}

/// All standalone number literals (see module rule).
pub fn numbers(chars: &[char]) -> Vec<NumberAt> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // A minus sign ('-' or U+2212) is part of the number only when it
        // starts a token ("at -5 °C", "(-2 C)"): codes ("M-7") and ranges
        // ("90-100") keep the digit-adjacent '-' and stay excluded below.
        let sign_here = (c == '-' || c == '\u{2212}')
            && i + 1 < chars.len()
            && chars[i + 1].is_ascii_digit()
            && (i == 0 || chars[i - 1].is_whitespace() || chars[i - 1] == '(');
        if sign_here {
            i += 1;
        }
        let negative = sign_here;
        let prev_ok = negative || i == 0 || {
            let p = chars[i - 1];
            !(p.is_alphanumeric() || p == '-' || p == '.' || p == ':')
        };
        if chars[i].is_ascii_digit() && prev_ok {
            let start = if negative { i - 1 } else { i };
            let digits = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            // A digit or ':' right after the literal (times, ranges like 90-100
            // are handled by the caller's ambiguity rule) disqualifies it.
            if i < chars.len() && (chars[i] == ':' || chars[i].is_ascii_digit()) {
                continue;
            }
            let s: String = chars[digits..i].iter().collect();
            if let Ok(v) = s.parse::<f64>() {
                out.push(NumberAt {
                    value: if negative { -v } else { v },
                    start,
                    end: i,
                });
            }
        } else {
            i += 1;
        }
    }
    out
}

fn word_at(chars: &[char], mut i: usize) -> (String, usize) {
    while i < chars.len() && chars[i] == ' ' {
        i += 1;
    }
    let s = i;
    while i < chars.len() && is_unit_char(chars[i]) {
        i += 1;
    }
    (chars[s..i].iter().collect(), i)
}

/// Typed quantities (number + recognised unit).
pub fn quantities(text: &str) -> Vec<Quantity> {
    let chars: Vec<char> = text.chars().take(MAX_TEXT_CHARS).collect();
    let mut out = Vec::new();
    for n in numbers(&chars) {
        // At most one space between number and unit ("40 C", "40C").
        let mut j = n.end;
        if j < chars.len() && chars[j] == ' ' {
            j += 1;
        }
        let s = j;
        while j < chars.len() && is_unit_char(chars[j]) {
            j += 1;
        }
        let w: String = chars[s..j].iter().collect();
        if w.is_empty() {
            continue;
        }
        let (next, _) = word_at(&chars, j);
        if let Some((kind, conv)) = unit(&w, &next) {
            out.push(Quantity {
                kind,
                value: conv(n.value),
                at: n.start,
            });
        }
    }
    out
}

/// Lower-case word-boundary search for a cue phrase; returns char end offsets.
pub fn find_term(text_lower: &[char], term: &str) -> Vec<usize> {
    let t: Vec<char> = term.to_lowercase().chars().collect();
    if t.is_empty() || t.len() > text_lower.len() {
        return vec![];
    }
    let boundary = |c: Option<&char>| c.is_none_or(|c| !c.is_alphanumeric());
    (0..=text_lower.len() - t.len())
        .filter(|&i| {
            text_lower[i..i + t.len()] == t[..]
                && boundary(if i == 0 { None } else { text_lower.get(i - 1) })
                && boundary(text_lower.get(i + t.len()))
        })
        .map(|i| i + t.len())
        .collect()
}

/// Bare numbers introduced by any of `cues` within a short window
/// (e.g. "PI 2.1", "polarisation index of 2.4", "PI: 1.9").
pub fn cued_numbers(text: &str, cues: &[String]) -> Vec<Quantity> {
    let chars: Vec<char> = text.chars().take(MAX_TEXT_CHARS).collect();
    let lower: Vec<char> = chars.iter().flat_map(|c| c.to_lowercase()).collect();
    if lower.len() != chars.len() {
        return vec![]; // case folding changed length: refuse rather than misalign
    }
    let typed: Vec<usize> = quantities(text).iter().map(|q| q.at).collect();
    let nums = numbers(&chars);
    let mut out: Vec<Quantity> = Vec::new();
    for cue in cues {
        for end in find_term(&lower, cue) {
            if let Some(n) = nums.iter().find(|n| {
                n.start >= end && n.start - end <= CUE_WINDOW && !typed.contains(&n.start)
            }) {
                let between: String = chars[end..n.start].iter().collect();
                let filler = between
                    .split(|c: char| c.is_whitespace() || c == ':' || c == '=')
                    .all(|w| {
                        w.is_empty()
                            || matches!(w.to_ascii_lowercase().as_str(), "of" | "is" | "was" | "at")
                    });
                if filler && !out.iter().any(|q| q.at == n.start) {
                    out.push(Quantity {
                        kind: Kind::Cued,
                        value: n.value,
                        at: n.start,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(t: &str) -> Vec<(Kind, f64)> {
        quantities(t)
            .into_iter()
            .map(|q| (q.kind, (q.value * 1e6).round() / 1e6))
            .collect()
    }

    #[test]
    fn typed_units_and_conversions() {
        assert_eq!(
            kinds("Motor 6.6 kV: 180 MΩ at 35 °C"),
            vec![
                (Kind::Voltage, 6.6),
                (Kind::Resistance, 180.0),
                (Kind::Temperature, 35.0)
            ]
        );
        assert_eq!(
            kinds("415 V, 1.2 GΩ, 104 °F"),
            vec![
                (Kind::Voltage, 0.415),
                (Kind::Resistance, 1200.0),
                (Kind::Temperature, 40.0)
            ]
        );
        assert_eq!(
            kinds("3.3kV IR 18 Mohm @ 55C"),
            vec![
                (Kind::Voltage, 3.3),
                (Kind::Resistance, 18.0),
                (Kind::Temperature, 55.0)
            ]
        );
        assert_eq!(
            kinds("300 megohm, 42 degC"),
            vec![(Kind::Resistance, 300.0), (Kind::Temperature, 42.0)]
        );
        assert_eq!(kinds("50 deg C"), vec![(Kind::Temperature, 50.0)]);
    }

    /// Regression (v0.2 holdout): "-2 C" was not read, so an out-of-range
    /// temperature became INSUFFICIENT_INPUT instead of INVALID_TEST. Found
    /// first by a generated boundary probe, then by the expert suite (val-08).
    #[test]
    fn negative_temperatures_are_read_but_codes_and_ranges_are_not() {
        assert_eq!(
            kinds("700 megohms at -2 C"),
            vec![(Kind::Resistance, 700.0), (Kind::Temperature, -2.0)]
        );
        assert_eq!(kinds("oil at −5 °C"), vec![(Kind::Temperature, -5.0)]);
        assert_eq!(kinds("(-40 °F)"), vec![(Kind::Temperature, -40.0)]);
        assert!(kinds("TX-38 M-7 at 14:30").is_empty());
        assert!(
            kinds("range 90-100 C").iter().all(|q| q.1 >= 0.0),
            "a range dash is not a sign"
        );
        assert_eq!(
            kinds("- 5 C"),
            vec![(Kind::Temperature, 5.0)],
            "a detached dash is not a sign"
        );
    }

    #[test]
    fn codes_times_and_bare_numbers_are_not_quantities() {
        assert!(kinds("Motor M-7 after flooding, CT-F2, at 14:30, feeder 4").is_empty());
        assert!(kinds("M-122 TR-3 G-2").is_empty());
    }

    #[test]
    fn cue_numbers() {
        let c = vec![
            "PI".to_string(),
            "polarisation index".to_string(),
            "polarization index".to_string(),
        ];
        let v: Vec<f64> = cued_numbers("IR 18 Mohm @ 55C, polarisation index 2.4", &c)
            .iter()
            .map(|q| q.value)
            .collect();
        assert_eq!(v, vec![2.4]);
        assert_eq!(cued_numbers("PI: 1.9 and PI of 2.0", &c).len(), 2);
        assert!(cued_numbers("PI test not done yet, 140 megohms", &c).is_empty());
        assert!(cued_numbers("PIPE 2.0", &c).is_empty(), "word boundary");
    }

    #[test]
    fn hostile_input_is_bounded() {
        let long = "9 kV ".repeat(5000);
        assert!(quantities(&long).len() <= MAX_TEXT_CHARS);
        assert!(quantities("").is_empty());
        assert!(quantities("1e309 kV").iter().all(|q| q.value.is_finite()));
    }
}
