use time::{OffsetDateTime, UtcOffset};

/// The service wire format and revocation ledger both use whole UTC seconds.
pub(crate) fn utc_seconds(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_format_drops_fractions_and_uses_utc() {
        let instant = OffsetDateTime::from_unix_timestamp(951_827_696)
            .unwrap()
            .replace_nanosecond(999_999_999)
            .unwrap()
            .to_offset(UtcOffset::from_hms(5, 30, 0).unwrap());
        assert_eq!(utc_seconds(instant), "2000-02-29T12:34:56Z");
    }
}
