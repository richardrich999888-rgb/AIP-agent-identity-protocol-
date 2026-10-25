//! Ingress hardening for the service (R9b, matrix E6).
//!
//! # What belongs here, and what belongs at the proxy
//!
//! This service is deployed behind a TLS-terminating reverse proxy — the
//! Docker compose and the pilot topology both say so, and the service
//! speaks plain HTTP on a private network. Two classes of limit follow
//! from that split:
//!
//! * **In-process, because the proxy cannot see it.** A request body is
//!   streamed, and a handler that deserializes a 2 GiB JSON body has
//!   already spent the memory before any proxy body-size rule that inspects
//!   the *parsed* content could apply. The body cap and the per-request
//!   timeout are here, at the one place that owns the deserialization and
//!   the work.
//! * **At the proxy, because it is per-connection and per-client.** TLS,
//!   per-IP rate limiting, and slow-loris connection timeouts need the
//!   client's address and the raw connection, which is exactly what a
//!   reverse proxy has and an application behind it does not (every request
//!   arrives from the proxy's address). `deploy/docker/reverse-proxy.conf`
//!   is the reference, and `deploy/docker/README.md` says why each rule is
//!   there.
//!
//! The one in-process limit that is neither body nor time is a **global
//! in-flight cap**: a ceiling on concurrent requests, so a burst that gets
//! past the proxy cannot exhaust the process's memory or file descriptors.
//! It is global rather than per-client because, behind a proxy, per-client
//! is the proxy's to enforce; this cap is the backstop that keeps the
//! process alive when the proxy's own limits are misconfigured or bypassed.
//!
//! # Fail-closed
//!
//! Every limit has a conservative default and is only ever *lowered or
//! raised deliberately* by an operator through the environment. An
//! unparseable value is refused at start-up (see [`IngressLimits::from_env`]),
//! not silently treated as unlimited — an ingress limit that quietly
//! becomes infinite on a typo is worse than none, because it reads as
//! present.

use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::Router;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// The three in-process ingress limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressLimits {
    /// Largest request body accepted, in bytes. A body larger than this is
    /// rejected with `413 Payload Too Large` before a handler sees it.
    pub max_body_bytes: usize,
    /// Longest a single request may run before `408`/`503`. Bounds a
    /// handler that a slow store or a pathological input would otherwise
    /// pin indefinitely.
    pub request_timeout: Duration,
    /// Largest number of requests processed at once across all clients.
    /// Excess requests wait, then time out under `request_timeout` — the
    /// process stays alive rather than falling over.
    pub max_in_flight: usize,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            // An `EvidencePacket` with a delegation chain and an observation
            // batch is comfortably under this; a body above it is a mistake
            // or an attack, not a legitimate packet.
            max_body_bytes: 1024 * 1024,
            // Verification and a store round trip are milliseconds; 30 s is
            // slack for a loaded PostgreSQL, not a budget any honest request
            // approaches.
            request_timeout: Duration::from_secs(30),
            // Generous for a pilot's request rate, low enough that a flood
            // cannot open unbounded concurrent work.
            max_in_flight: 256,
        }
    }
}

impl IngressLimits {
    /// Read overrides from the environment, refusing an unparseable value.
    ///
    /// A limit is a security control; a typo that turned it off must fail
    /// the start, not disable the control. Each variable is optional and
    /// falls back to the [`Default`]; a value that is present but malformed
    /// is an error.
    pub fn from_env() -> Result<Self, String> {
        let d = Self::default();
        Ok(Self {
            max_body_bytes: parse_usize("AIP_MAX_BODY_BYTES", d.max_body_bytes)?,
            request_timeout: Duration::from_secs(parse_u64(
                "AIP_REQUEST_TIMEOUT_SECS",
                d.request_timeout.as_secs(),
            )?),
            max_in_flight: parse_usize("AIP_MAX_IN_FLIGHT", d.max_in_flight)?,
        })
    }
}

fn parse_usize(key: &str, default: usize) -> Result<usize, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse()
            .map_err(|e| format!("{key}={v:?} is not a non-negative integer: {e}")),
        _ => Ok(default),
    }
}

fn parse_u64(key: &str, default: u64) -> Result<u64, String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse()
            .map_err(|e| format!("{key}={v:?} is not a non-negative integer: {e}")),
        _ => Ok(default),
    }
}

/// Wrap a router with the in-process ingress limits.
///
/// Order matters: the body limit and timeout are per-request and apply
/// after admission; the concurrency limit is the outermost, so a request
/// that cannot be admitted never allocates a body buffer or starts a
/// timer.
pub fn harden(router: Router, limits: IngressLimits) -> Router {
    router
        .layer(DefaultBodyLimit::max(limits.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            // 408, not the layer's default 408/503: a request that ran past
            // the budget is the client's to retry, and the status says so.
            StatusCode::REQUEST_TIMEOUT,
            limits.request_timeout,
        ))
        .layer(ConcurrencyLimitLayer::new(limits.max_in_flight))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The environment is process-wide and the test harness runs tests on
    /// parallel threads. Three tests below set and read the same variables,
    /// so without this lock one reads another's value mid-test: measured at
    /// 31 failures in 60 runs before it was added.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const VARS: [&str; 3] = [
        "AIP_MAX_BODY_BYTES",
        "AIP_REQUEST_TIMEOUT_SECS",
        "AIP_MAX_IN_FLIGHT",
    ];

    /// Hold the lock and start from a clean environment. Poison is
    /// tolerated: one failing test must not turn every later one into a
    /// lock failure that hides the real assertion.
    fn exclusive_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for k in VARS {
            std::env::remove_var(k);
        }
        guard
    }

    #[test]
    fn the_defaults_are_conservative_and_finite() {
        let d = IngressLimits::default();
        assert_eq!(d.max_body_bytes, 1024 * 1024);
        assert_eq!(d.request_timeout, Duration::from_secs(30));
        assert_eq!(d.max_in_flight, 256);
    }

    #[test]
    fn env_overrides_are_read() {
        let _env = exclusive_env();
        std::env::set_var("AIP_MAX_BODY_BYTES", "2048");
        std::env::set_var("AIP_REQUEST_TIMEOUT_SECS", "5");
        std::env::set_var("AIP_MAX_IN_FLIGHT", "16");
        let l = IngressLimits::from_env().unwrap();
        assert_eq!(l.max_body_bytes, 2048);
        assert_eq!(l.request_timeout, Duration::from_secs(5));
        assert_eq!(l.max_in_flight, 16);
        for k in VARS {
            std::env::remove_var(k);
        }
    }

    /// A malformed value fails the start. The alternative — silently using
    /// the default, or worse, unlimited — turns a typo into a disabled
    /// control that reads as present.
    #[test]
    fn a_malformed_limit_is_refused_not_ignored() {
        let _env = exclusive_env();
        std::env::set_var("AIP_MAX_BODY_BYTES", "not-a-number");
        let err = IngressLimits::from_env().unwrap_err();
        assert!(err.contains("AIP_MAX_BODY_BYTES"), "{err}");
        std::env::remove_var("AIP_MAX_BODY_BYTES");
    }

    #[test]
    fn an_empty_value_falls_back_to_the_default() {
        let _env = exclusive_env();
        std::env::set_var("AIP_MAX_IN_FLIGHT", "");
        assert_eq!(
            IngressLimits::from_env().unwrap().max_in_flight,
            IngressLimits::default().max_in_flight
        );
        std::env::remove_var("AIP_MAX_IN_FLIGHT");
    }
}
