//! `aip-probe` library — the probe daemon's building blocks, exposed so
//! integration tests exercise the real code (the sensor set, the config
//! validation) rather than a copy. The daemon entry point is `src/main.rs`.
//!
//! This matters most for the sensors: `tests/live_sensors.rs` opens the
//! actual fanotify queue and the actual `AF_PACKET` socket through the same
//! [`sensors::SensorSet`] the daemon uses, so what the tests prove is what
//! the daemon does.
//!
//! See `docs/pilot/PHASE1_DAEMONS.md` for the design and the trust model.

pub mod config;
pub mod keyfile;
pub mod sensors;
