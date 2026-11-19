//! UTC timestamps as `YYYY-MM-DDTHH:MM:SSZ`, without `chrono`.
//!
//! `chrono` is unmaintained (RUSTSEC-2026-0543, no safe upgrade), and this
//! crate used it only to format two kinds of string: token issue/expiry
//! times and the `revoked_at` field that the revocation hash chain covers.
//! The output must therefore be byte-identical to chrono's
//! `format("%Y-%m-%dT%H:%M:%SZ")`; `utc_equivalence` pinned that against
//! chrono itself before chrono was removed, and the fixed vectors in the tests
//! below keep it pinned.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, now. A clock before 1970 reads as 0.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `secs` as `YYYY-MM-DDTHH:MM:SSZ`, or `None` outside the range `time`
/// represents (the caller decides what an unrepresentable time means).
pub fn format_unix(secs: i64) -> Option<String> {
    let t = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    ))
}

/// Now, formatted.
pub fn now_string() -> String {
    format_unix(now_unix()).expect("the current time is representable")
}

#[cfg(test)]
mod tests {
    use super::*;

    // (seconds, chrono's output for the same instant)
    const VECTORS: &[(i64, &str)] = &[
        (0, "1970-01-01T00:00:00Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (1_000_000_000, "2001-09-09T01:46:40Z"),
        (2_147_483_647, "2038-01-19T03:14:07Z"),
        (2_147_483_648, "2038-01-19T03:14:08Z"),
        (4_102_444_799, "2099-12-31T23:59:59Z"),
        (253_402_300_799, "9999-12-31T23:59:59Z"),
    ];

    #[test]
    fn matches_chrono_on_fixed_vectors() {
        for &(secs, want) in VECTORS {
            assert_eq!(format_unix(secs).as_deref(), Some(want), "{secs}");
        }
    }

    #[test]
    fn unrepresentable_times_are_none_not_a_guess() {
        assert_eq!(format_unix(i64::MAX), None);
        assert_eq!(format_unix(i64::MIN), None);
    }

    #[test]
    fn now_is_formatted_and_after_2026() {
        let s = now_string();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.as_str() > "2026-01-01T00:00:00Z", "{s}");
    }
}
