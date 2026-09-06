//! B-1a — the service applies a temporal bound, by default.
//!
//! # The finding
//!
//! `aip-protocol` gained rule R16 (`VERIFICATION_TIME_BOUND`) and a
//! verifier-supplied `verification_time_ms`. The design is opt-in on purpose:
//! an offline verifier must be able to state what "now" means to it, and a
//! rule the verifier could not run must be reported as NOT EVALUATED rather
//! than as a failure — conflating "could not check" with "failed" would
//! destroy the CANNOT_PROVE / FAILED distinction the whole system rests on.
//!
//! But opt-in propagates only as far as someone remembers to opt in, and the
//! service did not: `verification_time_ms` appeared nowhere in
//! `aip-service/src`, so every service verification was unbounded and a
//! future-dated packet came back with an unqualified `valid: true`.
//!
//! # The fix these tests pin
//!
//! The service substitutes its own clock when the caller supplies none.
//! Omitting the field no longer means "apply no bound"; it means "apply the
//! bound the service knows". A caller may still name an explicit instant to
//! replay a historical verification — but there is no value of the request
//! that reaches unbounded verification through this API.
//!
//! # Why the fixtures are built rather than generated
//!
//! See `support/mod.rs`. In short: `generate_packet` dates packets from the
//! service clock, so it cannot produce the input R16 exists to catch, and the
//! verify endpoint's production shape is client-signed packets anyway. The
//! "generate cannot future-date" property is itself asserted below rather
//! than assumed.
//!
//! # What is deliberately NOT asserted
//!
//! That a future-dated packet is *invalid for every reason*. R16 is one rule
//! among sixteen and these tests check R16's contribution. The fixture issues
//! its authority tokens with a century-wide window precisely so that the
//! date-related rules other than R16 stay satisfied — otherwise a test could
//! pass on an unrelated failure while R16 did nothing.

use aip_protocol::verification_report::rules;
use aip_protocol::EvidencePacket;
use airon_aip::evidence::{verify_request, VerifyRequest};
use std::collections::HashMap;

mod support;
use support::{now_ms, packet_dated, Fixture};

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;
const FIFTY_YEARS_MS: u64 = 50 * 365 * DAY_MS;

/// Build a verify request for `packet` with the temporal controls under test
/// and the issuer keys the fixture produced.
fn vreq(
    packet: EvidencePacket,
    issuers: HashMap<String, String>,
    at: Option<u64>,
    tolerance: Option<u64>,
) -> VerifyRequest {
    VerifyRequest {
        packet,
        trusted_issuers: issuers,
        trusted_counterparties: HashMap::new(),
        revoked_jtis: vec![],
        trace_data: None,
        receipt_data: None,
        verification_time_ms: at,
        future_tolerance_ms: tolerance,
    }
}

/// Verify `fx` with the given temporal controls.
fn verify_fixture(
    fx: Fixture,
    verify_at: Option<u64>,
    tolerance: Option<u64>,
) -> aip_protocol::VerificationReport {
    verify_request(&vreq(fx.packet, fx.issuers, verify_at, tolerance))
        .expect("verification must run")
}

/// The common case: a packet dated `offset_ms` after its authority, verified
/// on the service's default path.
fn verify_dated(offset_ms: u64) -> aip_protocol::VerificationReport {
    verify_fixture(packet_dated(offset_ms), None, None)
}

/// R16's result, which is what almost every assertion here is about.
fn r16(
    report: &aip_protocol::VerificationReport,
) -> &aip_protocol::verification_report::RuleResult {
    report
        .rule(rules::VERIFICATION_TIME_BOUND)
        .expect("R16 must appear in every report")
}

/// Assert R16 refused the packet — and that it *ran*.
///
/// `pass` alone is not enough. A rule the verifier could not evaluate is also
/// recorded with `pass: false`, so an assertion on `pass` alone is satisfied
/// by the very defect under test: before the fix, R16 was never evaluated and
/// every "must be refused" assertion passed vacuously. NOT EVALUATED is not a
/// refusal, and this helper is where that distinction is enforced.
fn assert_refused(report: &aip_protocol::VerificationReport, ctx: &str) {
    let c = r16(report);
    assert!(
        c.evaluated,
        "{ctx}: R16 was NOT EVALUATED. \
         An unevaluated rule is not a refusal — the service applied no bound."
    );
    assert!(!c.pass, "{ctx}: R16 accepted the packet: {}", c.detail);
}

/// Assert R16 accepted the packet — and that it ran.
fn assert_accepted(report: &aip_protocol::VerificationReport, ctx: &str) {
    let c = r16(report);
    assert!(
        c.evaluated,
        "{ctx}: R16 was NOT EVALUATED, so it accepted nothing"
    );
    assert!(c.pass, "{ctx}: R16 refused the packet: {}", c.detail);
}

// ═══ The fixture is sound ═══

#[test]
fn a_present_dated_packet_is_otherwise_valid() {
    // The guard on every test below. If the fixture failed for an unrelated
    // reason, an assertion that a future-dated packet is refused would prove
    // nothing — it would be refused either way.
    let report = verify_dated(0);
    assert!(
        report.valid,
        "the fixture must be valid apart from the date under test; failures: {:?}",
        report.failures()
    );
}

// ═══ The default path is the bounded one ═══

#[test]
fn omitting_the_verification_time_still_applies_a_bound() {
    // The regression that matters. Before the fix this request produced a
    // report with `verification_time_checked: false`, i.e. no temporal bound
    // at all, and a caller reading `valid` had no way to know.
    let report = verify_dated(0);

    assert!(
        report.verification_time_checked,
        "SECURITY (B-1a): the service verified with no temporal bound. \
         Omitting verification_time_ms must fall back to the service clock, \
         not to unbounded verification."
    );
    assert!(report.verification_time_ms.is_some());
}

#[test]
fn r16_is_evaluated_rather_than_skipped_on_the_default_path() {
    let report = verify_dated(0);
    let c = r16(&report);
    assert!(
        c.evaluated,
        "SECURITY (B-1a): R16 was recorded as NOT EVALUATED on the default \
         service path — the rule exists but nothing ran it"
    );
    assert!(c.pass, "a present-dated packet must pass R16: {}", c.detail);
    assert!(
        report
            .not_evaluated()
            .iter()
            .all(|c| c.rule != rules::VERIFICATION_TIME_BOUND),
        "R16 must not appear in the not-evaluated set"
    );
}

// ═══ A future-dated packet is refused ═══

#[test]
fn a_future_dated_packet_is_refused_by_the_service() {
    // The attack B-1a leaves open. Every timestamp inside the packet is
    // mutually consistent and inside the authority window, so every
    // packet-relative rule passes. Only a bound the *verifier* supplies can
    // catch it — and the service now supplies one without being asked.
    let report = verify_dated(FIFTY_YEARS_MS);

    assert!(
        report.verification_time_checked,
        "the bound must have been applied at all"
    );
    assert_refused(&report, "SECURITY (B-1a): a packet dated fifty years ahead");
    assert!(
        !report.valid,
        "SECURITY (B-1a): the service reported a future-dated packet as valid"
    );
}

#[test]
fn r16_is_the_rule_that_catches_it() {
    // Stronger than "invalid": R16 must be the reason. If some other rule
    // happened to reject the fixture, the test above would pass while the
    // temporal bound did nothing — this pins that it is R16 doing the work.
    let report = verify_dated(FIFTY_YEARS_MS);
    let failed: Vec<&str> = report.failures().iter().map(|c| c.rule.as_str()).collect();
    assert_eq!(
        failed,
        vec![rules::VERIFICATION_TIME_BOUND],
        "R16 must be the sole failing rule; failures were {failed:?}"
    );
}

#[test]
fn the_refusal_names_the_offending_timestamp() {
    // A bare `valid: false` tells an operator nothing during an incident. The
    // report must say which rule refused and what it objected to.
    let fx = packet_dated(DAY_MS);
    let decided_at = fx.decided_at_ms;
    let report = verify_fixture(fx, None, None);
    assert_refused(&report, "a packet dated a day ahead");
    let c = r16(&report);
    assert!(
        c.detail.contains(&decided_at.to_string()),
        "the detail must name the offending timestamp: {}",
        c.detail
    );
}

// ═══ An explicit time is honoured ═══

#[test]
fn an_explicit_instant_overrides_the_service_clock() {
    // The discriminator. This packet is dated ten minutes ahead of real time,
    // so the default path refuses it — and an explicit instant just after the
    // decision accepts it. Only genuine use of the supplied value can produce
    // both outcomes for the same packet; a service that accepted the field
    // and then verified against its own clock would fail here.
    let ten_minutes = 10 * 60_000u64;

    let refused = verify_dated(ten_minutes);
    assert_refused(
        &refused,
        "precondition: the default path must refuse a packet ten minutes ahead",
    );

    let fx = packet_dated(ten_minutes);
    let at = fx.decided_at_ms + 1_000;
    let accepted = verify_fixture(fx, Some(at), None);
    assert_eq!(
        accepted.verification_time_ms,
        Some(at),
        "the service must verify at the instant the caller named, not its own"
    );
    assert_accepted(&accepted, "an explicit instant after the decision");
}

#[test]
fn a_packet_stays_verifiable_long_after_the_fact() {
    // Delayed and archival verification: naming an instant far later than the
    // packet must not turn a valid packet invalid. R16 bounds the future, not
    // the past.
    let fx = packet_dated(0);
    let much_later = fx.decided_at_ms + 10 * 365 * DAY_MS;
    let report = verify_fixture(fx, Some(much_later), None);
    assert_accepted(&report, "a decade-old packet");
}

#[test]
fn an_explicit_time_before_the_packet_refuses_it() {
    // The mirror of the case above: asking "was this valid an hour before it
    // happened?" must answer no.
    let fx = packet_dated(0);
    let before = fx.issued_at_ms - HOUR_MS;
    let report = verify_fixture(fx, Some(before), None);
    assert_refused(&report, "a packet dated after the supplied instant");
}

// ═══ Tolerance is a bound, not a licence ═══

#[test]
fn the_default_tolerance_is_zero() {
    // A minute of unexplained skew is not something to wave through by
    // default. A deployment that needs slack must declare it.
    let report = verify_dated(60_000);
    assert_refused(
        &report,
        "SECURITY (B-1a): a packet a minute ahead with no declared tolerance",
    );
}

#[test]
fn a_declared_tolerance_absorbs_skew_and_nothing_more() {
    let ahead_by = 30_000u64;

    // Wider than the skew: accepted.
    let generous = verify_fixture(packet_dated(ahead_by), None, Some(ahead_by + 60_000));
    assert_accepted(&generous, "a tolerance wider than the skew");

    // Narrower than the skew: still refused. A tolerance must not become a
    // blanket pass just because it is non-zero.
    let mean = verify_fixture(packet_dated(ahead_by), None, Some(1_000));
    assert_refused(&mean, "SECURITY (B-1a): a tolerance smaller than the skew");
}

// ═══ The epistemic model is preserved ═══

#[test]
fn the_service_never_reports_a_bound_it_did_not_apply() {
    // The forensic rule: uncertainty must not be converted into a successful
    // assertion. `verification_time_checked` is true only when a time was
    // genuinely handed to the verifier — never set for appearance.
    for tolerance in [None, Some(5_000)] {
        for explicit in [false, true] {
            let fx = packet_dated(0);
            let at = explicit.then_some(fx.decided_at_ms + 1);
            let report = verify_fixture(fx, at, tolerance);
            assert_eq!(
                report.verification_time_checked,
                report.verification_time_ms.is_some(),
                "verification_time_checked must agree with whether a time was applied"
            );
            assert!(
                report.verification_time_checked,
                "no combination of these inputs may reach unbounded verification"
            );
        }
    }
}

#[test]
fn generate_cannot_be_used_to_future_date_a_packet() {
    // Why `packet_at` exists, asserted rather than asserted-in-prose. The
    // generate path stamps its own clock, so the timestamps it produces are
    // bounded by construction. This is a property worth keeping: if a future
    // change let a caller supply `decided_at`, this test fails and the
    // fixture rationale above stops being true.
    let (req, issuers) = support::sample_generate_request();
    let before = now_ms();
    let packet = airon_aip::evidence::generate_packet(&req).expect("generation");
    let after = now_ms();

    assert!(
        packet.decision.decided_at >= before && packet.decision.decided_at <= after,
        "generate must date the decision from its own clock, not from the request"
    );
    let report = verify_request(&vreq(packet, issuers, None, None)).expect("verify");
    assert_accepted(&report, "a freshly generated packet");
}
