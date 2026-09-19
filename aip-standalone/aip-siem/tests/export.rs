//! R15 — the SIEM export, over real signed verdicts.
//!
//! Two properties are under test and they matter for different reasons.
//!
//! The first is cryptographic: a verdict that does not verify produces no
//! event. A SIEM is where an institution's analysts form beliefs, so it is
//! exactly where a forgery would acquire the bank's own provenance.
//!
//! The second is textual, and is the one log exporters actually get wrong:
//! a field that reaches the line unescaped lets whoever controls that field
//! inject a second event, or append key/value pairs an analyst then reads
//! as facts the system reported.

use aip_crypto::generate_ed25519_keypair;
use aip_reconcile::{
    ReconcilerSigner, ReconcilerTrustAnchors, Reconciliation, ReconciliationResult,
    SignedReconciliation,
};
use aip_siem::{
    frame, severity_for, CefEvent, DeviceIdentity, Facility, Level, SiemError, SyslogIdentity,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const RECONCILER: &str = "reconciler-1";
const T0: u64 = 1_700_000_000_000;

fn device() -> DeviceIdentity {
    DeviceIdentity::new("VANIAN", "AIP Ghost", "0.4.0").unwrap()
}

fn syslog_identity() -> SyslogIdentity {
    SyslogIdentity {
        facility: Facility::Local0,
        hostname: "recon-1.bank.internal".into(),
        app_name: "aip-reconcile".into(),
        proc_id: "4021".into(),
    }
}

/// A real signed verdict of the given class, plus the anchors for it.
fn verdict(result: ReconciliationResult) -> (SignedReconciliation, ReconcilerTrustAnchors) {
    verdict_signed_by(result, RECONCILER)
}

fn verdict_signed_by(
    result: ReconciliationResult,
    reconciler_id: &str,
) -> (SignedReconciliation, ReconcilerTrustAnchors) {
    let kp = generate_ed25519_keypair();
    let signer = ReconcilerSigner::new(reconciler_id, 2, &kp.private_key, &kp.public_key).unwrap();
    let mut r = Reconciliation::fixture_default();
    r.result = result;
    r.verification_time_ms = T0;
    (
        signer.sign(&r).unwrap(),
        ReconcilerTrustAnchors::new().trust(reconciler_id, 2, &kp.public_key),
    )
}

const ALL_RESULTS: [ReconciliationResult; 8] = [
    ReconciliationResult::VerifiedExecution,
    ReconciliationResult::UnattributedEffect,
    ReconciliationResult::PhantomClaim,
    ReconciliationResult::IdentityDivergence,
    ReconciliationResult::LineageViolation,
    ReconciliationResult::SensorIntegrityFailure,
    ReconciliationResult::ContinuityFailure,
    ReconciliationResult::CannotProve,
];

// ─── Verification comes first ───

/// **The rule.** No anchors, no event. The SIEM does not become the place
/// where an unsigned verdict acquires the institution's provenance.
#[test]
fn a_verdict_that_does_not_verify_produces_no_event() {
    let (v, _) = verdict(ReconciliationResult::IdentityDivergence);
    let err = CefEvent::from_verdict(&v, &ReconcilerTrustAnchors::new(), &device()).unwrap_err();
    assert!(matches!(err, SiemError::VerdictNotVerified(_)));
    assert!(err.to_string().contains("no event is emitted"), "{err}");

    // An impostor key under the right name is no better.
    let impostor = generate_ed25519_keypair();
    assert!(CefEvent::from_verdict(
        &v,
        &ReconcilerTrustAnchors::new().trust(RECONCILER, 2, &impostor.public_key),
        &device()
    )
    .is_err());
}

/// A verdict edited after signing produces no event, so the SIEM line can
/// never be more favourable — or more damning — than the signed document.
#[test]
fn a_tampered_verdict_produces_no_event() {
    let (mut v, anchors) = verdict(ReconciliationResult::CannotProve);
    v.reconciliation.result = ReconciliationResult::VerifiedExecution;
    assert!(CefEvent::from_verdict(&v, &anchors, &device()).is_err());
}

/// Every CEF header field is mandatory; an empty one yields a line the
/// receiver cannot attribute, so it is refused at construction.
#[test]
fn an_empty_device_field_is_refused() {
    for (vendor, product, version) in [("", "p", "v"), ("vend", "  ", "v"), ("vend", "p", "")] {
        assert!(matches!(
            DeviceIdentity::new(vendor, product, version),
            Err(SiemError::EmptyDeviceField(_))
        ));
    }
}

// ─── The line itself ───

/// The shape a CEF receiver parses: seven pipe-delimited header fields,
/// then the extension.
#[test]
fn the_line_has_the_seven_mandatory_header_fields() {
    let (v, anchors) = verdict(ReconciliationResult::PhantomClaim);
    let line = CefEvent::from_verdict(&v, &anchors, &device())
        .unwrap()
        .to_cef();
    assert!(line.starts_with("CEF:0|VANIAN|AIP Ghost|0.4.0|AIP:3|phantom claim|8|"));
    // Seven fields before the extension: the prefix plus six separators
    // inside it, then the one that opens the extension.
    let header: Vec<&str> = line.splitn(8, '|').collect();
    assert_eq!(header.len(), 8, "{line}");
    assert!(header[7].contains("cs1=PHANTOM_CLAIM"), "{}", header[7]);
}

/// The verdict digest is on the line, so an analyst can ask for the
/// document and verify it rather than trusting the log.
#[test]
fn the_line_cites_the_verdict_by_digest() {
    let (v, anchors) = verdict(ReconciliationResult::IdentityDivergence);
    let line = CefEvent::from_verdict(&v, &anchors, &device())
        .unwrap()
        .to_cef();
    let digest: String = v.digest().iter().map(|b| format!("{b:02x}")).collect();
    assert!(line.contains(&format!("cs4={digest}")), "{line}");
    assert!(line.contains("cs4Label=AipVerdictDigest"), "{line}");
}

/// `CANNOT_PROVE` must reach the analyst as the absence of evidence. A log
/// line that reads as "nothing found, all clear" is the single most
/// consequential misreading this system exists to prevent.
#[test]
fn cannot_prove_is_not_rendered_as_a_clean_result() {
    let (v, anchors) = verdict(ReconciliationResult::CannotProve);
    let event = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
    let line = event.to_cef();
    assert!(
        line.contains("absence of evidence"),
        "the message must say what CANNOT_PROVE means: {line}"
    );
    assert!(line.contains("do not read it as clean"), "{line}");
    // And it must not route as low as a verified execution.
    assert!(
        event.severity > severity_for(ReconciliationResult::VerifiedExecution),
        "CANNOT_PROVE must not file beside VERIFIED_EXECUTION"
    );
}

/// The exporter emits no judgement words of its own. The verdict carries
/// no severity, confidence or score by design; the one number CEF forces
/// is the header severity, and nothing else may creep in.
#[test]
fn the_line_carries_no_invented_judgement() {
    for result in ALL_RESULTS {
        let (v, anchors) = verdict(result);
        let line = CefEvent::from_verdict(&v, &anchors, &device())
            .unwrap()
            .to_cef()
            .to_lowercase();
        for forbidden in [
            "confidence",
            "score",
            "risk=",
            "malicious",
            "benign",
            "safe",
        ] {
            assert!(!line.contains(forbidden), "`{forbidden}` in {line}");
        }
    }
}

// ─── Injection, which is what exporters get wrong ───

/// **The load-bearing test.** A reconciler identifier chosen to break out
/// of its field is refused, and nothing is emitted.
///
/// The identifier is inside the signature, so a *valid* verdict can carry
/// it: verification establishes that the reconciler really said this, not
/// that the string is safe to concatenate into a log line. Escaping alone
/// would make the line safe for a conformant CEF parser while still
/// spelling a literal `CEF:0|` inside it, which a stream consumer that
/// re-scans for `CEF:` reads as a second event. An exporter cannot verify
/// what its receiver does, so it refuses.
#[test]
fn a_hostile_reconciler_id_is_refused_rather_than_logged_ambiguously() {
    let hostile = r"evil|0|CEF:0|Attacker|Fake|1|AIP:1|all clear|0|cs1=VERIFIED_EXECUTION";
    let (v, anchors) = verdict_signed_by(ReconciliationResult::IdentityDivergence, hostile);
    // The verdict itself is perfectly valid.
    v.verify(&anchors)
        .expect("a signed verdict with a hostile id still verifies");

    let err = CefEvent::from_verdict(&v, &anchors, &device()).unwrap_err();
    match &err {
        SiemError::Unrepresentable {
            what,
            verdict_digest,
        } => {
            assert_eq!(*what, "reconciler_id");
            // The refusal names the document, so an adverse verdict is not
            // simply lost: an operator can go and read it.
            assert_eq!(*verdict_digest, hex(&v.digest()));
        }
        other => panic!("{other:?}"),
    }
    assert!(err.to_string().contains("no line is emitted"), "{err}");
}

/// A control character in an identifier is refused for the same reason: it
/// would end the record and put the remainder on a line of its own.
#[test]
fn a_control_character_in_an_identifier_is_refused() {
    for hostile in ["host\ninjected", "host\rx", "host\u{0}x", "a\u{7f}b"] {
        let (v, anchors) = verdict_signed_by(ReconciliationResult::CannotProve, hostile);
        assert!(
            matches!(
                CefEvent::from_verdict(&v, &anchors, &device()),
                Err(SiemError::Unrepresentable { .. })
            ),
            "{hostile:?} must be refused"
        );
    }
}

/// Escaping stays correct regardless, as the layer beneath the refusal: a
/// value that is representable but contains an `=` must not open a key.
#[test]
fn a_representable_value_with_an_equals_cannot_open_a_key() {
    let (v, anchors) = verdict_signed_by(ReconciliationResult::CannotProve, "recon=1 suser=root");
    let line = CefEvent::from_verdict(&v, &anchors, &device())
        .unwrap()
        .to_cef();
    assert!(line.contains(r"dvchost=recon\=1 suser\=root"), "{line}");
    assert_eq!(line.matches("CEF:0|").count(), 1, "{line}");
    assert_eq!(line.lines().count(), 1, "{line}");
}

/// Device identity is operator configuration. A pipe in it is a
/// misconfiguration, and catching it once at start-up beats emitting
/// ambiguous lines for the life of the deployment.
#[test]
fn a_hostile_device_identity_is_refused_at_construction() {
    for (vendor, product, version) in [
        (r"Ven|dor", "p", "v"),
        ("vend", r"Pro|duct", "v"),
        ("vend", "p", r"1|0"),
        ("vend", "p", "1\n0"),
        (r"ven\dor", "p", "v"),
    ] {
        assert!(
            matches!(
                DeviceIdentity::new(vendor, product, version),
                Err(SiemError::Unrepresentable { .. })
            ),
            "{vendor:?} {product:?} {version:?}"
        );
    }
}

/// And a well-formed identity still produces the seven header fields in
/// the right order.
#[test]
fn a_well_formed_device_identity_renders_seven_header_fields() {
    let (v, anchors) = verdict(ReconciliationResult::CannotProve);
    let line = CefEvent::from_verdict(&v, &anchors, &device())
        .unwrap()
        .to_cef();
    let fields: Vec<&str> = line.splitn(8, '|').collect();
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[0], "CEF:0");
    assert_eq!(fields[6], "5", "severity is the seventh field");
}

/// No record may span two lines. Identifiers that could do so are refused
/// above; this checks the whole assembled record for a real verdict.
#[test]
fn no_emitted_record_spans_more_than_one_line() {
    for result in ALL_RESULTS {
        let (v, anchors) = verdict(result);
        let record = frame(
            &CefEvent::from_verdict(&v, &anchors, &device()).unwrap(),
            &syslog_identity(),
        );
        assert_eq!(record.lines().count(), 1, "{record}");
        assert!(!record.contains('\n') && !record.contains('\r'), "{record}");
    }
}

// ─── Severity, which this crate owns and must own consistently ───

/// The table is total and stable: every result maps, in range, and the
/// same result always maps the same way.
#[test]
fn the_severity_table_is_total_stable_and_in_range() {
    for result in ALL_RESULTS {
        let s = severity_for(result);
        assert!(s <= 10, "{result:?} -> {s}");
        assert_eq!(s, severity_for(result), "not stable");
    }
    // Every adverse class routes above the absence-of-evidence class,
    // which routes above a verified execution.
    let adverse = severity_for(ReconciliationResult::IdentityDivergence);
    let unknown = severity_for(ReconciliationResult::CannotProve);
    let clean = severity_for(ReconciliationResult::VerifiedExecution);
    assert!(
        adverse > unknown && unknown > clean,
        "{adverse} {unknown} {clean}"
    );
    for r in [
        ReconciliationResult::UnattributedEffect,
        ReconciliationResult::PhantomClaim,
        ReconciliationResult::LineageViolation,
        ReconciliationResult::SensorIntegrityFailure,
        ReconciliationResult::ContinuityFailure,
    ] {
        assert_eq!(
            severity_for(r),
            adverse,
            "{r:?} must route with the adverse class"
        );
    }
}

/// Severity is a function of the class alone. Two verdicts differing only
/// in evidence strength must route identically, or an analyst's rules
/// would silently depend on a field this exporter is not ranking.
#[test]
fn severity_does_not_depend_on_evidence_strength() {
    use aip_reconcile::EvidenceStrength;
    let kp = generate_ed25519_keypair();
    let signer = ReconcilerSigner::new(RECONCILER, 2, &kp.private_key, &kp.public_key).unwrap();
    let anchors = ReconcilerTrustAnchors::new().trust(RECONCILER, 2, &kp.public_key);

    let mut severities = Vec::new();
    for strength in [
        EvidenceStrength::Heuristic,
        EvidenceStrength::Correlated,
        EvidenceStrength::Attested,
        EvidenceStrength::Proven,
    ] {
        let mut r = Reconciliation::fixture_default();
        r.result = ReconciliationResult::PhantomClaim;
        r.strength = strength;
        r.verification_time_ms = T0;
        let v = signer.sign(&r).unwrap();
        severities.push(
            CefEvent::from_verdict(&v, &anchors, &device())
                .unwrap()
                .severity,
        );
    }
    assert!(
        severities.windows(2).all(|w| w[0] == w[1]),
        "{severities:?}"
    );
}

// ─── Syslog framing ───

/// The RFC 5424 record, field by field.
#[test]
fn the_syslog_record_has_the_shape_rfc_5424_defines() {
    let (v, anchors) = verdict(ReconciliationResult::IdentityDivergence);
    let event = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
    let record = frame(&event, &syslog_identity());

    // PRI for local0 (16) at warning (4) = 16*8+4 = 132.
    assert!(record.starts_with("<132>1 "), "{record}");
    let parts: Vec<&str> = record.splitn(8, ' ').collect();
    assert_eq!(parts[1], "2023-11-14T22:13:20.000Z", "{record}");
    assert_eq!(parts[2], "recon-1.bank.internal");
    assert_eq!(parts[3], "aip-reconcile");
    assert_eq!(parts[4], "4021");
    assert_eq!(parts[5], "AIP:4", "MSGID routes without parsing CEF");
    assert_eq!(parts[6], "-", "structured data is NILVALUE, not duplicated");
    assert!(parts[7].starts_with("CEF:0|"), "{record}");
}

/// An unknown syslog field is the NILVALUE, never empty: an empty field is
/// not legal and some collectors drop the whole record.
#[test]
fn unknown_syslog_fields_become_the_nilvalue() {
    let (v, anchors) = verdict(ReconciliationResult::CannotProve);
    let event = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
    let record = frame(
        &event,
        &SyslogIdentity {
            facility: Facility::Local3,
            hostname: String::new(),
            app_name: "  ".into(),
            proc_id: String::new(),
        },
    );
    // local3 (19) at notice (5) = 19*8+5 = 157.
    assert!(record.starts_with("<157>1 "), "{record}");
    let parts: Vec<&str> = record.splitn(8, ' ').collect();
    assert_eq!((parts[2], parts[3], parts[4]), ("-", "-", "-"));
}

/// The two severity scales are inverted. An adverse finding filed as
/// `informational` is a finding nobody sees.
#[test]
fn an_adverse_verdict_is_not_framed_as_informational() {
    for result in [
        ReconciliationResult::IdentityDivergence,
        ReconciliationResult::SensorIntegrityFailure,
        ReconciliationResult::PhantomClaim,
    ] {
        let (v, anchors) = verdict(result);
        let event = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
        let level = aip_siem::level_for_cef_severity(event.severity);
        assert_ne!(level, Level::Informational, "{result:?}");
    }
}

/// Rendering is deterministic: the same verdict yields byte-identical
/// output, so a diff in a log is a change in the system.
#[test]
fn rendering_is_deterministic() {
    let (v, anchors) = verdict(ReconciliationResult::PhantomClaim);
    let a = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
    let b = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.to_cef(), b.to_cef());
    assert_eq!(frame(&a, &syslog_identity()), frame(&b, &syslog_identity()));
}

/// No trailing newline: framing belongs to the transport, and an exporter
/// that adds one produces a blank record when the transport adds another.
#[test]
fn nothing_is_emitted_with_a_trailing_newline() {
    let (v, anchors) = verdict(ReconciliationResult::CannotProve);
    let event = CefEvent::from_verdict(&v, &anchors, &device()).unwrap();
    assert!(!event.to_cef().ends_with('\n'));
    assert!(!frame(&event, &syslog_identity()).ends_with('\n'));
}
