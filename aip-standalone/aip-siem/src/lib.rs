//! `aip-siem` — verified reconciliation verdicts as CEF over RFC 5424
//! syslog (R15 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`).
//!
//! # What this crate is for
//!
//! A verdict nobody reads changes nothing. An institution's analysts work
//! in a SIEM, so a verdict has to arrive there in a form their existing
//! rules can route — which in Indian BFSI practice means CEF over syslog.
//!
//! # What it refuses to do
//!
//! * **Emit from an unverified verdict.** The SIEM is exactly where a
//!   forgery would acquire the institution's own provenance, arriving as
//!   something the bank's reconciler said. [`cef::CefEvent::from_verdict`]
//!   verifies under anchors the caller supplies and there is no
//!   constructor that skips it.
//! * **Invent a judgement.** The one number this crate supplies that the
//!   verdict does not — the CEF severity, which the format makes mandatory
//!   — is a documented routing hint from a fixed table, and `CANNOT_PROVE`
//!   does not map to the bottom of it.
//! * **Reach the network.** This crate formats. Delivery — UDP, TCP,
//!   TLS, a local socket, a file the agent tails — is the deployment's
//!   choice, and a formatter that opened sockets would make the format
//!   untestable without one.
//!
//! # Dependencies
//!
//! None beyond the workspace. CEF is a text format and RFC 5424 is a text
//! format; the one thing that usually drags in a crate, converting Unix
//! milliseconds to RFC 3339, is in [`time`] with its derivation and its
//! tests.

pub mod cef;
pub mod escape;
pub mod syslog;
pub mod time;

pub use cef::{is_representable, severity_for, CefEvent, DeviceIdentity, SiemError, CEF_VERSION};
pub use syslog::{frame, level_for_cef_severity, Facility, Level, SyslogIdentity};
pub use time::rfc3339_ms;
