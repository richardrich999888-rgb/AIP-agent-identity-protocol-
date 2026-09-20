//! Clock-domain normalisation between AIP's evidence and a third-party observer.
//!
//! # Why this is its own module
//!
//! A corroboration result is worthless if the two observers' timestamps are not
//! in the same domain, and the failure is silent: mismatched clocks produce a
//! report full of "only one observer saw this", which reads as a damning
//! finding when it is in fact an arithmetic bug. So the conversion is isolated
//! here, is pure, and is tested against the cases that actually break it.
//!
//! # The three domains
//!
//! * **AIP kernel events** carry `kernel_timestamp_ns`, a kernel monotonic
//!   stamp. Its zero is boot, not the epoch.
//! * **bpftrace** `nsecs` is `bpf_ktime_get_ns()` — the same monotonic domain.
//! * **auditd** stamps records with wall-clock seconds since the epoch.
//!
//! The common domain is therefore **wall-clock milliseconds**, reached through
//! the batch's [`BootClockAnchor`], which records `realtime_ms`,
//! `monotonic_ns` and `boottime_ns` captured together.
//!
//! # Signed arithmetic is mandatory
//!
//! An event routinely precedes the anchor: the collector anchors at the end of
//! a batch window and the events inside it are older. `u64` subtraction would
//! wrap into an astronomically large positive number and place a perfectly
//! ordinary event ~584 years in the future, where it matches nothing. Every
//! difference here is computed in `i128` and only then narrowed.

use aip_observe::BootClockAnchor;

/// Milliseconds per nanosecond divisor.
const NS_PER_MS: i128 = 1_000_000;

/// Convert a kernel **monotonic** nanosecond stamp to wall-clock milliseconds.
///
/// Used for both AIP's `kernel_timestamp_ns` and bpftrace's `nsecs`, which
/// share the monotonic domain. `monotonic_ns` is preferred over `boottime_ns`
/// as the base because `bpf_ktime_get_ns` excludes suspend, as does
/// `CLOCK_MONOTONIC`; on a host that never suspended the two are within a
/// microsecond of each other, and on one that did, this is the correct base.
pub fn monotonic_ns_to_wall_ms(anchor: &BootClockAnchor, ns: u64) -> i64 {
    let delta_ms = (ns as i128 - anchor.monotonic_ns as i128) / NS_PER_MS;
    narrow(anchor.realtime_ms as i128 + delta_ms)
}

/// Convert wall-clock milliseconds back to the monotonic domain.
///
/// Present so a window expressed in wall time can be applied to raw kernel
/// stamps without converting every event.
pub fn wall_ms_to_monotonic_ns(anchor: &BootClockAnchor, wall_ms: i64) -> i64 {
    let delta_ns = (wall_ms as i128 - anchor.realtime_ms as i128) * NS_PER_MS;
    narrow(anchor.monotonic_ns as i128 + delta_ns)
}

/// Narrow an `i128` to `i64`, saturating rather than wrapping. A saturated
/// value is far outside any real window and will simply fail to match, which
/// is the safe direction: it can cause a missed match, never a false one.
fn narrow(v: i128) -> i64 {
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> BootClockAnchor {
        BootClockAnchor {
            realtime_ms: 1_789_914_920_810,
            boottime_ns: 9_521_940_670_579,
            monotonic_ns: 9_521_940_669_779,
            clk_tck: 100,
        }
    }

    #[test]
    fn an_event_at_the_anchor_maps_to_the_anchor_wall_time() {
        let a = anchor();
        assert_eq!(
            monotonic_ns_to_wall_ms(&a, a.monotonic_ns),
            a.realtime_ms as i64
        );
    }

    /// The case that a u64 subtraction would destroy: the event precedes the
    /// anchor, which is the normal case for every event in a batch.
    #[test]
    fn an_event_before_the_anchor_goes_backwards_not_584_years_forwards() {
        let a = anchor();
        let one_second_earlier = a.monotonic_ns - 1_000_000_000;
        let wall = monotonic_ns_to_wall_ms(&a, one_second_earlier);
        assert_eq!(wall, a.realtime_ms as i64 - 1_000);
        assert!(
            wall < a.realtime_ms as i64,
            "must move backwards in wall time"
        );
    }

    #[test]
    fn an_event_after_the_anchor_moves_forwards() {
        let a = anchor();
        let wall = monotonic_ns_to_wall_ms(&a, a.monotonic_ns + 2_500_000_000);
        assert_eq!(wall, a.realtime_ms as i64 + 2_500);
    }

    #[test]
    fn the_conversion_round_trips_within_a_millisecond() {
        let a = anchor();
        for offset_ns in [-5_000_000_000i64, -1_000_000, 0, 1_000_000, 7_500_000_000] {
            let ns = (a.monotonic_ns as i128 + offset_ns as i128) as u64;
            let wall = monotonic_ns_to_wall_ms(&a, ns);
            let back = wall_ms_to_monotonic_ns(&a, wall);
            let drift = (back - ns as i64).abs();
            assert!(drift < NS_PER_MS as i64, "round trip drifted {drift} ns");
        }
    }

    /// A real archive's anchor: the two monotonic bases differ by sub-microsecond,
    /// so choosing either must not move an event by a whole millisecond.
    #[test]
    fn boottime_and_monotonic_bases_agree_to_under_a_millisecond() {
        let a = anchor();
        let skew_ns = (a.boottime_ns as i128 - a.monotonic_ns as i128).abs();
        assert!(skew_ns < NS_PER_MS, "unexpected suspend skew: {skew_ns} ns");
    }

    #[test]
    fn a_wild_timestamp_saturates_rather_than_wrapping() {
        let a = anchor();
        let wall = monotonic_ns_to_wall_ms(&a, u64::MAX);
        assert!(
            wall > a.realtime_ms as i64,
            "must stay ordered, not wrap negative"
        );
    }
}
