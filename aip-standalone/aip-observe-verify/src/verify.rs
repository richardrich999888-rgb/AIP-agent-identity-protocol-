//! The pure verification core: parsed records and anchors in, a
//! [`ChainReport`] out. No filesystem, no clock, no network, no process exit.

use std::collections::BTreeMap;

use aip_observe::{
    verify_attested_batch, verify_signed_health, AttestedBatch, ObserverTrustAnchors,
    SignedSensorHealth,
};

use crate::report::{BatchReport, ChainReport, ChainStart, Finding, HealthReport};

/// A line read from an archive, carrying its 1-based line number so a finding
/// can name the offending line in a file of thousands.
#[derive(Debug, Clone)]
pub struct Line<T> {
    pub number: usize,
    pub record: T,
}

/// Records as they came off disk: either parsed, or a parse error the
/// verifier must report rather than skip. A verifier that silently skips
/// unparseable lines will pass an archive that has been half destroyed.
#[derive(Debug, Clone)]
pub enum Parsed<T> {
    Ok(Line<T>),
    Failed { number: usize, error: String },
}

/// Split one JSONL text into parse results, one per non-blank line.
///
/// Blank lines are ignored deliberately: an append-only file can end with a
/// newline, and that is not corruption. Anything else that does not parse is.
pub fn parse_jsonl<T: serde::de::DeserializeOwned>(text: &str) -> Vec<Parsed<T>> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            let number = i + 1;
            match serde_json::from_str::<T>(l) {
                Ok(record) => Parsed::Ok(Line { number, record }),
                Err(e) => Parsed::Failed {
                    number,
                    error: e.to_string(),
                },
            }
        })
        .collect()
}

fn split<T>(parsed: Vec<Parsed<T>>, findings: &mut Vec<Finding>) -> Vec<Line<T>> {
    let mut ok = Vec::new();
    for p in parsed {
        match p {
            Parsed::Ok(l) => ok.push(l),
            Parsed::Failed { number, error } => {
                findings.push(Finding::Unparseable {
                    line: number,
                    error,
                });
            }
        }
    }
    ok
}

/// Verify a batch archive: every signature, then the chain that links them.
///
/// The two are checked in that order and both are checked in full. Stopping
/// at the first bad signature would leave the reader unable to tell one bad
/// record from an archive that is bad throughout.
fn verify_batches(
    lines: &[Line<AttestedBatch>],
    anchors: &ObserverTrustAnchors,
    findings: &mut Vec<Finding>,
) -> BatchReport {
    if lines.is_empty() {
        findings.push(Finding::Empty { what: "batches" });
        return BatchReport {
            records: 0,
            first_sequence: None,
            last_sequence: None,
            start: None,
            final_head: None,
            observations: 0,
            kernel_events: 0,
        };
    }

    for l in lines {
        if let Err(e) = verify_attested_batch(&l.record, anchors) {
            findings.push(Finding::SignatureRejected {
                line: l.number,
                sequence: l.record.sequence,
                error: e.to_string(),
            });
        }
    }

    // Chain linkage. `head()` is recomputed from each record's own bytes, so
    // a forged `prev_head` cannot be made to agree with a doctored
    // predecessor: the predecessor's head follows from its content.
    let start = if lines[0].record.prev_head == [0u8; 32] {
        ChainStart::Epoch
    } else {
        ChainStart::MidChain
    };

    let mut expected_seq = lines[0].record.sequence;
    let mut prev: Option<[u8; 32]> = None;
    for l in lines {
        if l.record.sequence != expected_seq {
            findings.push(Finding::SequenceNotContiguous {
                line: l.number,
                expected: expected_seq,
                found: l.record.sequence,
            });
            // Re-anchor on what is actually there, so one gap produces one
            // finding rather than one per remaining record.
            expected_seq = l.record.sequence;
        }
        if let Some(p) = prev {
            if l.record.prev_head != p {
                findings.push(Finding::ChainBroken {
                    line: l.number,
                    sequence: l.record.sequence,
                    expected_prev_head: hex::encode(p),
                    found_prev_head: hex::encode(l.record.prev_head),
                });
            }
        }
        prev = Some(l.record.head());
        expected_seq = expected_seq.saturating_add(1);
    }

    BatchReport {
        records: lines.len(),
        first_sequence: Some(lines[0].record.sequence),
        last_sequence: Some(lines[lines.len() - 1].record.sequence),
        start: Some(start),
        final_head: prev.map(hex::encode),
        observations: lines
            .iter()
            .map(|l| l.record.batch.observations.len())
            .sum(),
        kernel_events: lines
            .iter()
            .map(|l| l.record.batch.kernel_events.len())
            .sum(),
    }
}

/// Verify a health archive, and cross-check its heads against the batch
/// archive where the two cover the same chain position.
///
/// The cross-check is the part that matters and the part a per-file verifier
/// misses. A health record states the observer's head at a position; a batch
/// states the content that produces a head at that position. Both are signed
/// by the same key, so if they disagree the collector signed two different
/// answers about one moment — which no amount of per-record signature
/// checking would reveal.
fn verify_health(
    lines: &[Line<SignedSensorHealth>],
    batches: &[Line<AttestedBatch>],
    anchors: &ObserverTrustAnchors,
    findings: &mut Vec<Finding>,
) -> HealthReport {
    if lines.is_empty() {
        findings.push(Finding::Empty { what: "health" });
    }

    for l in lines {
        if let Err(e) = verify_signed_health(&l.record, anchors) {
            findings.push(Finding::SignatureRejected {
                line: l.number,
                sequence: l.record.health.sequence,
                error: e.to_string(),
            });
        }
    }

    let heads: BTreeMap<u64, [u8; 32]> = batches
        .iter()
        .map(|l| (l.record.sequence, l.record.head()))
        .collect();
    let covered = match (batches.first(), batches.last()) {
        (Some(f), Some(t)) => Some((f.record.sequence, t.record.sequence)),
        _ => None,
    };

    let mut cross_checked = 0usize;
    // Sequence 0 is the pre-first-batch health record: it has no batch to
    // check against, by construction, and is not a missing record.
    for l in lines.iter().filter(|l| l.record.health.sequence > 0) {
        let seq = l.record.health.sequence;
        match heads.get(&seq) {
            Some(batch_head) => {
                cross_checked += 1;
                if *batch_head != l.record.health.head {
                    findings.push(Finding::HealthHeadMismatch {
                        sequence: seq,
                        health_head: hex::encode(l.record.health.head),
                        batch_head: hex::encode(batch_head),
                    });
                }
            }
            None => {
                // Only a finding inside the range the batch archive claims to
                // cover. Outside it, the health record simply refers to a
                // batch this file does not hold, which is a window, not a
                // deletion.
                if let Some((from, to)) = covered {
                    if seq >= from && seq <= to {
                        findings.push(Finding::HealthHeadHasNoBatch { sequence: seq });
                    }
                }
            }
        }
    }

    let mut states: Vec<String> = Vec::new();
    for l in lines {
        let s = format!("{:?}", l.record.health.state);
        if !states.contains(&s) {
            states.push(s);
        }
    }

    // Protocol 12: the clock discipline the collector signed. Reported, not
    // judged. What error bound is acceptable is the institution's policy and
    // belongs in the institution's hands, so the verifier states what the
    // collector claimed and does not convert it into a pass or a failure.
    // What it will not do is let silence read as a good reading: a record
    // with no clock statement is counted apart from one that carries a bad
    // statement.
    let clocks = || lines.iter().filter_map(|l| l.record.health.clock);
    HealthReport {
        records: lines.len(),
        states,
        with_coverage: lines
            .iter()
            .filter(|l| l.record.health.attested_coverage.is_some())
            .count(),
        without_coverage: lines
            .iter()
            .filter(|l| l.record.health.attested_coverage.is_none())
            .count(),
        cross_checked_against_batches: cross_checked,
        clock_synchronised: clocks().filter(|c| c.synchronized).count(),
        clock_unsynchronised: clocks().filter(|c| !c.synchronized).count(),
        clock_not_stated: lines
            .iter()
            .filter(|l| l.record.health.clock.is_none())
            .count(),
        clock_worst_max_error_us: clocks().map(|c| c.max_error_us).max(),
    }
}

/// The whole verification, as one pure function.
///
/// `batches` and `health` are each optional so an auditor can verify whatever
/// they were given, but at least one must be present — the caller enforces
/// that, because "nothing to verify" is a usage error, not a verdict.
pub fn verify_archives(
    observer_id: &str,
    key_version: u32,
    public_key: &[u8],
    batches: Option<Vec<Parsed<AttestedBatch>>>,
    health: Option<Vec<Parsed<SignedSensorHealth>>>,
) -> ChainReport {
    let anchors = ObserverTrustAnchors::new().trust(observer_id, key_version, public_key);
    let mut findings = Vec::new();

    let batch_lines = batches.map(|p| split(p, &mut findings));
    let health_lines = health.map(|p| split(p, &mut findings));

    let batch_report = batch_lines
        .as_ref()
        .map(|l| verify_batches(l, &anchors, &mut findings));
    let health_report = health_lines.as_ref().map(|l| {
        verify_health(
            l,
            batch_lines.as_deref().unwrap_or(&[]),
            &anchors,
            &mut findings,
        )
    });

    ChainReport {
        observer_id: observer_id.to_string(),
        key_version,
        public_key: hex::encode(public_key),
        batches: batch_report,
        health: health_report,
        findings,
    }
}
