//! Operational metrics in Prometheus text exposition format (R15).
//!
//! # Why not the OpenTelemetry SDK
//!
//! The requirement is that an institution's existing observability stack
//! can see this service. Every such stack — Prometheus, Grafana Agent, the
//! OpenTelemetry Collector's `prometheus` receiver, Datadog, Dynatrace —
//! scrapes the Prometheus text format. Emitting it directly satisfies the
//! requirement with **no new dependency**, where the OTel SDK would add a
//! substantial tree (tonic, prost, a second async runtime configuration)
//! to a service whose entire metrics surface is a dozen counters. A
//! deployment that wants OTLP puts a collector in front; that is what a
//! collector is for.
//!
//! # What is deliberately not here
//!
//! **No tenant labels.** A metric labelled by tenant is a cross-tenant
//! disclosure channel: it tells any scraper how many packets each
//! institution filed and when. Counters here are aggregate, and the route
//! is authenticated. Per-tenant volume belongs in a tenant's own view, not
//! in a shared scrape.
//!
//! **No agent identifiers, no packet ids, no verdict digests.** Those are
//! unbounded-cardinality labels, which break a time-series database, and
//! they are evidence — evidence belongs in the store, not in a metric.
//!
//! **No histograms of request latency.** They would be easy to add and
//! easy to get wrong (bucket choice is a deployment decision), and no
//! requirement asks for them. An absent metric is better than a
//! meaningless one.

use std::sync::atomic::{AtomicU64, Ordering};

/// One named counter.
///
/// Counters only ever increase, which is what makes a scrape gap
/// recoverable: a consumer that missed a scrape computes the delta from
/// the next one. A gauge that can fall does not have that property, and
/// none of the quantities here need it.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Add one.
    ///
    /// `Relaxed` is correct and deliberate: a counter carries no
    /// happens-before relationship to anything else, and the only
    /// guarantee needed is that increments are not lost. Stronger
    /// ordering would cost on every request and buy nothing.
    pub fn incr(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Every counter the service keeps.
///
/// Flat and explicit rather than a registry keyed by string: a typo in a
/// metric name then fails to compile instead of silently creating a second
/// series that nobody alerts on.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Evidence packets accepted and stored.
    pub evidence_stored: Counter,
    /// Evidence packets refused because they did not verify.
    pub evidence_rejected: Counter,
    /// Verdicts filed through `POST /v1/verdicts`.
    pub verdicts_stored: Counter,
    /// Verdicts refused because they did not verify under the caller's
    /// anchors. **The one to alert on.** A non-zero rate means something
    /// is submitting documents this service will not stand behind.
    pub verdicts_rejected: Counter,
    /// Access ledgers filed.
    pub ledgers_stored: Counter,
    /// Access ledgers refused.
    pub ledgers_rejected: Counter,
    /// Requests refused for missing or invalid credentials.
    pub auth_failures: Counter,
    /// Requests refused because the role was insufficient.
    pub authz_failures: Counter,
    /// SIEM events emitted.
    pub siem_events_emitted: Counter,
    /// SIEM events **not** emitted because the verdict could not be
    /// rendered safely. Alert on this: it is the only way a refused
    /// export becomes visible, and a refusal means an adverse verdict may
    /// not have reached the analysts' console.
    pub siem_exports_refused: Counter,
}

impl Metrics {
    /// Render the Prometheus text exposition format, version 0.0.4.
    ///
    /// Deterministic field order, one `# HELP` and one `# TYPE` per
    /// metric, and a trailing newline — all three are required by the
    /// format, and a scraper's parser is stricter than most people expect.
    pub fn render(&self) -> String {
        let rows: [(&str, &str, u64); 10] = [
            (
                "aip_evidence_stored_total",
                "Evidence packets verified and stored.",
                self.evidence_stored.get(),
            ),
            (
                "aip_evidence_rejected_total",
                "Evidence packets refused because they did not verify.",
                self.evidence_rejected.get(),
            ),
            (
                "aip_verdicts_stored_total",
                "Reconciliation verdicts verified and stored.",
                self.verdicts_stored.get(),
            ),
            (
                "aip_verdicts_rejected_total",
                "Reconciliation verdicts refused because they did not verify under the \
                 submitter's anchors.",
                self.verdicts_rejected.get(),
            ),
            (
                "aip_ledgers_stored_total",
                "Access ledgers verified and stored.",
                self.ledgers_stored.get(),
            ),
            (
                "aip_ledgers_rejected_total",
                "Access ledgers refused because they did not verify.",
                self.ledgers_rejected.get(),
            ),
            (
                "aip_auth_failures_total",
                "Requests refused for a missing or invalid API key.",
                self.auth_failures.get(),
            ),
            (
                "aip_authz_failures_total",
                "Requests refused because the caller's role was insufficient.",
                self.authz_failures.get(),
            ),
            (
                "aip_siem_events_emitted_total",
                "CEF events emitted for verified verdicts.",
                self.siem_events_emitted.get(),
            ),
            (
                "aip_siem_exports_refused_total",
                "Verdicts not exported to the SIEM because they could not be rendered \
                 unambiguously. A non-zero value means an adverse verdict may not have \
                 reached the analysts' console.",
                self.siem_exports_refused.get(),
            ),
        ];

        let mut out = String::with_capacity(rows.len() * 160);
        for (name, help, value) in rows {
            // HELP text is newline-delimited in the format, so a newline
            // inside it would forge a second metric. Every value here is a
            // literal, and this keeps it that way if one ever is not.
            let help = help.replace(['\n', '\r'], " ");
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The format a scraper parses: HELP, TYPE, value, in that order, once
    /// each, with a trailing newline.
    #[test]
    fn the_exposition_format_is_well_formed() {
        let m = Metrics::default();
        let text = m.render();
        assert!(text.ends_with('\n'));
        let names: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("# TYPE "))
            .map(|l| l.split_whitespace().nth(2).unwrap())
            .collect();
        assert_eq!(names.len(), 10);
        for name in &names {
            assert_eq!(
                text.matches(&format!("# HELP {name} ")).count(),
                1,
                "{name}"
            );
            assert_eq!(text.matches(&format!("# TYPE {name} counter")).count(), 1);
            assert!(text.contains(&format!("\n{name} 0\n")), "{name}");
            assert!(
                name.ends_with("_total"),
                "a counter's name ends in _total: {name}"
            );
        }
    }

    /// Counters count, and the rendering reflects them.
    #[test]
    fn counters_increment_and_render() {
        let m = Metrics::default();
        m.verdicts_rejected.incr();
        m.verdicts_rejected.incr();
        m.evidence_stored.add(7);
        assert_eq!(m.verdicts_rejected.get(), 2);
        let text = m.render();
        assert!(text.contains("\naip_verdicts_rejected_total 2\n"), "{text}");
        assert!(text.contains("\naip_evidence_stored_total 7\n"), "{text}");
    }

    /// **No tenant, agent or document identifier may appear.** A labelled
    /// metric would be a cross-tenant disclosure channel on a shared
    /// scrape, and an unbounded label set breaks the database that stores
    /// it.
    #[test]
    fn no_metric_carries_a_label() {
        let m = Metrics::default();
        m.evidence_stored.incr();
        let text = m.render();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            assert!(
                !line.contains('{'),
                "a labelled series would leak per-tenant volume: {line}"
            );
        }
        for forbidden in ["tenant", "agent", "packet_id", "digest"] {
            assert!(
                !text.to_lowercase().contains(&format!("{forbidden}=")),
                "`{forbidden}` must not be a label"
            );
        }
    }

    /// Deterministic order, so a diff between two scrapes is a change in
    /// the numbers rather than in the iteration.
    #[test]
    fn rendering_is_deterministic() {
        let m = Metrics::default();
        m.ledgers_stored.incr();
        assert_eq!(m.render(), m.render());
    }

    /// Increments from several threads are not lost. `Relaxed` ordering
    /// guarantees atomicity of the increment itself, which is the property
    /// a counter needs.
    #[test]
    fn concurrent_increments_are_not_lost() {
        let m = std::sync::Arc::new(Metrics::default());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = m.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    m.evidence_stored.incr();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.evidence_stored.get(), 8_000);
    }
}
