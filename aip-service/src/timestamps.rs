//! Preserve the service's UTC, whole-second timestamp representation.

use time::{macros::format_description, OffsetDateTime, UtcOffset};

pub(crate) fn utc_seconds(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .expect("the fixed date/time format has all required components")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn preserves_utc_wire_format_at_epoch_leap_day_and_year_boundary() {
        for (value, expected) in [
            (OffsetDateTime::UNIX_EPOCH, "1970-01-01T00:00:00Z"),
            (
                datetime!(2024-02-29 23:59:59.999_999_999 UTC),
                "2024-02-29T23:59:59Z",
            ),
            (datetime!(2000-01-01 0:15 +1), "1999-12-31T23:15:00Z"),
        ] {
            assert_eq!(utc_seconds(value), expected);
        }
    }
}
