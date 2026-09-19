//! Unix milliseconds to an RFC 3339 UTC timestamp, without a date library.
//!
//! RFC 5424 requires a TIMESTAMP field in RFC 3339 form. Pulling in a date
//! crate for one conversion would add a dependency tree to a component
//! whose entire job is to format a line, so the civil-date arithmetic is
//! here, with its derivation, and it is tested against known instants.
//!
//! # The algorithm
//!
//! This is Howard Hinnant's `civil_from_days`, the standard branch-free
//! conversion that underlies most date libraries. The idea: shift the epoch
//! so the year starts in **March**, which puts the leap day at the end of
//! the year and makes month lengths follow a repeating pattern with no
//! special case for February.
//!
//! # Boundary conditions
//!
//! * UTC only. No local time, no zone database, no DST. A log line whose
//!   timestamp depends on where the exporter runs is one that cannot be
//!   correlated across sites.
//! * No leap seconds. Unix time has none by definition, and neither does
//!   the value being converted.
//! * Instants before 1970 are not representable: the input is `u64`
//!   milliseconds since the epoch, so there are none.

/// A civil date and time in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utc {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub millisecond: u32,
}

/// Split Unix milliseconds into a UTC civil date and time.
pub fn from_unix_ms(unix_ms: u64) -> Utc {
    let secs = (unix_ms / 1_000) as i64;
    let millisecond = (unix_ms % 1_000) as u32;

    // Days since the epoch, and the second within that day. Both are
    // non-negative because `unix_ms` is unsigned.
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    Utc {
        year,
        month,
        day,
        hour: (sod / 3_600) as u32,
        minute: ((sod % 3_600) / 60) as u32,
        second: (sod % 60) as u32,
        millisecond,
    }
}

/// Days since 1970-01-01 to a civil (year, month, day).
///
/// Derivation, following Hinnant:
///
/// 1. Shift the epoch to 0000-03-01 so that leap days land at the end of a
///    year. `719_468` is the number of days from 0000-03-01 to 1970-01-01.
/// 2. An *era* is 400 years — the Gregorian leap cycle — which is exactly
///    `146_097` days. Split the day count into an era and a day-of-era.
/// 3. Within an era, the year-of-era is recovered by removing the
///    accumulated leap days: subtracting the 4-year, 100-year and 400-year
///    corrections in the numerator, then dividing by 365.
/// 4. The day-of-year (counting from March 1) determines the month through
///    the linear fit `(5*doy + 2)/153`, which is exact for the repeating
///    31/30 month-length pattern that March-based years have.
/// 5. Shift the month back to a January-based year.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    const DAYS_EPOCH_TO_MARCH_ZERO: i64 = 719_468;
    const DAYS_PER_ERA: i64 = 146_097;

    let z = days_since_epoch + DAYS_EPOCH_TO_MARCH_ZERO;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z.rem_euclid(DAYS_PER_ERA); // [0, 146096]

    // Years within the era, after removing accumulated leap days.
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    // Day of the March-based year, [0, 365].
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    // Month index, March = 0.
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
                                                   // Back to a January-based month: March = 0 becomes 3, and January and
                                                   // February (mp 10 and 11) belong to the following civil year.
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format Unix milliseconds as RFC 3339 in UTC, with millisecond
/// precision: `2023-11-14T22:13:20.000Z`.
pub fn rfc3339_ms(unix_ms: u64) -> String {
    let t = from_unix_ms(unix_ms);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second, t.millisecond
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known instants. Each is checkable by hand or with `date -u -d @N`.
    #[test]
    fn known_instants_convert_exactly() {
        for (ms, expected) in [
            (0u64, "1970-01-01T00:00:00.000Z"),
            (1_000, "1970-01-01T00:00:01.000Z"),
            (1_700_000_000_000, "2023-11-14T22:13:20.000Z"),
            (1_700_000_000_123, "2023-11-14T22:13:20.123Z"),
            // A leap day, which is the case a naive implementation misses.
            (1_709_164_800_000, "2024-02-29T00:00:00.000Z"),
            // 1900 was not a leap year and 2000 was: the century rule and
            // its 400-year exception, both inside the same era.
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            // The last second of a year.
            (1_704_067_199_000, "2023-12-31T23:59:59.000Z"),
            (1_704_067_200_000, "2024-01-01T00:00:00.000Z"),
        ] {
            assert_eq!(rfc3339_ms(ms), expected, "at {ms}");
        }
    }

    /// Every day for eleven years, checked for internal consistency: the
    /// date must advance by exactly one day and never produce an invalid
    /// field. Eleven years spans two leap years and their neighbours.
    #[test]
    fn consecutive_days_are_consistent_across_leap_years() {
        const DAY_MS: u64 = 86_400_000;
        // 2018-01-01T00:00:00Z.
        let start = 1_514_764_800_000u64;
        let mut prev = from_unix_ms(start);
        for i in 1..=(365 * 11) {
            let t = from_unix_ms(start + i * DAY_MS);
            assert!((1..=12).contains(&t.month), "{t:?}");
            assert!((1..=31).contains(&t.day), "{t:?}");
            assert_eq!((t.hour, t.minute, t.second, t.millisecond), (0, 0, 0, 0));
            // Either the next day of the same month, or day 1 of the next.
            let advanced = (t.year == prev.year && t.month == prev.month && t.day == prev.day + 1)
                || (t.day == 1
                    && ((t.year == prev.year && t.month == prev.month + 1)
                        || (t.year == prev.year + 1 && t.month == 1 && prev.month == 12)));
            assert!(advanced, "{prev:?} -> {t:?}");
            prev = t;
        }
    }

    /// February's length follows the Gregorian rule, including the
    /// century exception that trips naive implementations.
    #[test]
    fn february_length_follows_the_gregorian_rule() {
        // 2024 is a leap year (divisible by 4, not by 100).
        assert_eq!(rfc3339_ms(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        // 2023 is not: the same day-of-year lands in March.
        assert_eq!(rfc3339_ms(1_677_628_800_000), "2023-03-01T00:00:00.000Z");
        // 2100 will not be a leap year: divisible by 100, not by 400.
        assert_eq!(rfc3339_ms(4_107_542_400_000), "2100-03-01T00:00:00.000Z");
    }

    /// Deterministic and total: the same input always gives the same
    /// output, and no input panics.
    #[test]
    fn the_conversion_is_total_and_deterministic() {
        for ms in [0u64, 1, 999, 86_399_999, u64::MAX / 4, 253_402_300_799_000] {
            let a = rfc3339_ms(ms);
            assert_eq!(a, rfc3339_ms(ms));
            assert!(a.ends_with('Z') && a.len() >= 24, "{a}");
        }
    }

    /// Sub-second precision is kept: two events in the same second are
    /// distinguishable in the log, which is what an incident timeline needs.
    #[test]
    fn milliseconds_are_preserved() {
        assert_ne!(rfc3339_ms(1_700_000_000_001), rfc3339_ms(1_700_000_000_002));
        assert!(rfc3339_ms(1_700_000_000_007).ends_with(".007Z"));
    }
}
