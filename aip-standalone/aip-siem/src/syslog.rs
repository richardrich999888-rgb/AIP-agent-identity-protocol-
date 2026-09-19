//! RFC 5424 syslog framing.
//!
//! ```text
//! <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
//! ```
//!
//! The CEF line goes in `MSG`. Everything before it is what lets a
//! collector route and attribute the record before parsing the payload.

use crate::cef::CefEvent;
use crate::time::rfc3339_ms;

/// Syslog facility. `local0`–`local7` are the range reserved for local
/// use, which is where an application's records belong; using a
/// system-reserved facility would put them in a stream the operator's
/// existing rules already claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Facility {
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

/// Syslog severity, which is **not** CEF severity and runs the other way:
/// 0 is most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
}

/// Map the exporter's CEF severity to a syslog level.
///
/// The two scales are inverted and a direct copy would file every adverse
/// finding as informational. Kept as one function so the inversion is in
/// one place and testable.
pub fn level_for_cef_severity(cef_severity: u8) -> Level {
    match cef_severity {
        0..=3 => Level::Informational,
        4..=6 => Level::Notice,
        7..=8 => Level::Warning,
        _ => Level::Error,
    }
}

/// Everything about the emitting host that syslog wants and this crate
/// cannot infer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogIdentity {
    pub facility: Facility,
    /// The host as the SIEM should record it. A hostname the exporter read
    /// from its own environment can disagree with what the network calls
    /// it, so it is supplied.
    pub hostname: String,
    pub app_name: String,
    pub proc_id: String,
}

impl SyslogIdentity {
    /// A NILVALUE where a field is unknown. RFC 5424 spells that `-`, and
    /// an empty field is not legal.
    fn field(s: &str) -> &str {
        let t = s.trim();
        if t.is_empty() {
            "-"
        } else {
            t
        }
    }
}

/// Frame a CEF event as one RFC 5424 record.
///
/// `MSGID` is the verdict class, so a collector can route on it without
/// parsing CEF. `STRUCTURED-DATA` is NILVALUE: everything structured is
/// already in the CEF extension, and duplicating it into SD would create
/// two copies that can disagree after an edit.
pub fn frame(event: &CefEvent, identity: &SyslogIdentity) -> String {
    let level = level_for_cef_severity(event.severity);
    // PRI = facility * 8 + severity, per RFC 5424 §6.2.1.
    let pri = (identity.facility as u8) * 8 + (level as u8);
    format!(
        "<{}>1 {} {} {} {} {} - {}",
        pri,
        rfc3339_ms(event.verification_time_ms),
        SyslogIdentity::field(&identity.hostname),
        SyslogIdentity::field(&identity.app_name),
        SyslogIdentity::field(&identity.proc_id),
        SyslogIdentity::field(&event.signature_id),
        event.to_cef()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inversion. A direct copy of the CEF severity would file an
    /// identity divergence as `informational`.
    #[test]
    fn the_two_severity_scales_do_not_get_copied_across() {
        assert_eq!(level_for_cef_severity(0), Level::Informational);
        assert_eq!(level_for_cef_severity(5), Level::Notice);
        assert_eq!(level_for_cef_severity(8), Level::Warning);
        assert_eq!(level_for_cef_severity(10), Level::Error);
        // High CEF severity must never come out as the least urgent level.
        for s in 7..=10u8 {
            assert_ne!(level_for_cef_severity(s), Level::Informational, "cef {s}");
        }
    }

    /// PRI arithmetic, checked against the RFC's own formula.
    #[test]
    fn pri_is_facility_times_eight_plus_level() {
        assert_eq!((Facility::Local0 as u8) * 8 + (Level::Warning as u8), 132);
        assert_eq!((Facility::Local7 as u8) * 8 + (Level::Error as u8), 187);
    }

    /// An empty field is not legal in RFC 5424; the NILVALUE is.
    #[test]
    fn empty_fields_become_the_nilvalue() {
        assert_eq!(SyslogIdentity::field("  "), "-");
        assert_eq!(SyslogIdentity::field(""), "-");
        assert_eq!(SyslogIdentity::field(" host1 "), "host1");
    }
}
