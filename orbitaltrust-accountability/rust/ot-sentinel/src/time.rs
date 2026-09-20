//! ISO-8601 UTC ↔ epoch milliseconds.
//!
//! The rest of the governance stack compares timestamps as strings, which is
//! correct for ordering and keeps it dependency-free. The sentinel needs
//! *durations* — "was this effect observed within tolerance of its evidence",
//! "is this heartbeat overdue" — so it needs real arithmetic. Hand-rolled
//! rather than pulled from a date library because the parse must reject
//! rather than coerce: a sentinel that silently reads a malformed timestamp
//! as the epoch would date every ghost to 1970 and match nothing.

/// Parses `YYYY-MM-DDTHH:MM:SS[.sss]Z` to milliseconds since the Unix epoch.
///
/// Strict: only the shapes the governance stack actually writes are accepted.
/// `None` for anything else — an unparseable timestamp is a fact worth
/// surfacing, never a zero to compute with.
pub fn parse_iso8601_millis(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    // The shortest accepted form is `YYYY-MM-DDTHH:MM:SSZ` (20 bytes).
    if bytes.len() < 20 || !text.ends_with('Z') {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: u32 = text.get(5..7)?.parse().ok()?;
    let day: u32 = text.get(8..10)?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let millis: i64 = match &text[19..text.len() - 1] {
        "" => 0,
        frac if frac.starts_with('.') => {
            let digits = &frac[1..];
            if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            // Take milliseconds; anything finer is truncated, not rounded, so
            // the value never moves forward past an event it precedes.
            let mut padded = String::from(digits);
            while padded.len() < 3 {
                padded.push('0');
            }
            padded[0..3].parse().ok()?
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    Some(((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000) + millis)
}

/// Howard Hinnant's `days_from_civil`: a proleptic-Gregorian date to days
/// since the Unix epoch.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Absolute difference in milliseconds between two timestamps, or `None` when
/// either fails to parse.
pub fn abs_delta_millis(a: &str, b: &str) -> Option<i64> {
    Some((parse_iso8601_millis(a)? - parse_iso8601_millis(b)?).abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_parse_to_their_epoch_millis() {
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:01Z"), Some(1_000));
        assert_eq!(
            parse_iso8601_millis("2026-08-27T15:07:30.123Z"),
            Some(1_787_843_250_123)
        );
        // A leap day, which off-by-one era arithmetic would miss.
        assert_eq!(
            parse_iso8601_millis("2024-02-29T00:00:00.000Z"),
            Some(1_709_164_800_000)
        );
    }

    #[test]
    fn parsing_agrees_with_string_ordering_the_rest_of_the_stack_relies_on() {
        let stamps = [
            "2026-08-27T00:00:00.000Z",
            "2026-08-27T00:00:00.001Z",
            "2026-08-27T00:00:01.000Z",
            "2026-08-27T01:00:00.000Z",
            "2026-12-31T23:59:59.999Z",
            "2027-01-01T00:00:00.000Z",
        ];
        for pair in stamps.windows(2) {
            assert!(pair[0] < pair[1], "string order: {pair:?}");
            assert!(
                parse_iso8601_millis(pair[0]) < parse_iso8601_millis(pair[1]),
                "numeric order: {pair:?}"
            );
        }
    }

    #[test]
    fn a_malformed_timestamp_is_refused_rather_than_coerced_to_the_epoch() {
        for bad in [
            "",
            "2026-08-27",
            "2026-08-27T15:07:30",       // no zone
            "2026-08-27T15:07:30+01:00", // not UTC
            "2026-13-01T00:00:00Z",      // month 13
            "2026-08-32T00:00:00Z",      // day 32
            "2026-08-27T25:00:00Z",      // hour 25
            "2026-08-27T15:07:30.Z",     // empty fraction
            "2026-08-27T15:07:30.abcZ",  // non-numeric fraction
            "not-a-timestamp-at-all!",
        ] {
            assert_eq!(parse_iso8601_millis(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn sub_millisecond_precision_truncates_rather_than_rounding_forward() {
        // Rounding up could place an effect after evidence it actually
        // preceded, which would silently repair a real ordering violation.
        assert_eq!(
            parse_iso8601_millis("2026-08-27T00:00:00.999999Z"),
            parse_iso8601_millis("2026-08-27T00:00:00.999Z")
        );
    }

    #[test]
    fn deltas_are_symmetric_and_absent_when_either_side_is_unparseable() {
        assert_eq!(
            abs_delta_millis("2026-08-27T00:00:05.000Z", "2026-08-27T00:00:00.000Z"),
            Some(5_000)
        );
        assert_eq!(
            abs_delta_millis("2026-08-27T00:00:00.000Z", "2026-08-27T00:00:05.000Z"),
            Some(5_000)
        );
        assert_eq!(
            abs_delta_millis("garbage", "2026-08-27T00:00:00.000Z"),
            None
        );
    }
}
