//! Clock discipline: is this host's wall clock actually being steered by a
//! time source, and how far might it be out? (Matrix row E4; CERT-In
//! Direction 20(3)/2022 requires NTP-synchronised clocks.)
//!
//! # Why this is not the same as `BootClockAnchor`
//!
//! [`crate::boot_clock_anchor`] samples the realtime and boot clocks
//! back-to-back so a verifier can place a kernel-timestamped event on the
//! wall clock. That relates the two clocks; it says **nothing** about
//! whether the wall clock is right. An undisciplined host can hand out a
//! perfectly self-consistent anchor while being hours out, and every
//! `host_wall_clock_ms` in the evidence would be wrong together.
//!
//! This module asks the kernel the other question, through `ntp_adjtime`:
//! is a time daemon steering this clock, and what does the kernel believe
//! its maximum error to be? It reads; it never sets. `ADJ_OFFSET_SS_READ`
//! is deliberately not used — `modes: 0` is the pure query, and a module
//! that could adjust the clock it also reports on would be a poor witness.
//!
//! # What it can and cannot prove
//!
//! It reports the kernel's own view: `STA_UNSYNC` clear means a disciplining
//! daemon has set the clock recently, and `maxerror` is the kernel's bound
//! on the error, which grows steadily once the daemon stops updating it.
//! That is real evidence about clock hygiene and it is what CERT-In's
//! requirement is about.
//!
//! It is **not** proof that the clock is correct, and it is not proof
//! against a root attacker: root can call `adjtimex` itself and clear
//! `STA_UNSYNC` on a clock it has just moved. Like every other `/proc` and
//! syscall source here, this is honest about a cooperative host and
//! defeated by one whose kernel is owned (N1).
//!
//! Since protocol 12 the reading **is inside the attested bytes**: the
//! collector puts it in every signed health record as
//! [`crate::AttestedClock`], so an offline verifier can confirm from a
//! sealed record whether the clock producing its timestamps was being
//! steered, and by how much the kernel thought it might be out. It was
//! previously an operational control that ran at daemon start and on each
//! health cycle and went only to a log -- and a log is not evidence anyone
//! holds. Signing it raises the bar from "trust the operator's log" to "the
//! key signed this claim"; it does not make the claim unforgeable by a party
//! that holds both the key and the kernel.

/// The kernel's view of whether this host's clock is disciplined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockDiscipline {
    /// `STA_UNSYNC` is clear: a time daemon is steering this clock.
    pub synchronized: bool,
    /// The kernel's bound on the current error, in microseconds. It grows
    /// on its own once nothing is updating the clock, which is what makes
    /// it useful: a large value means "nobody has corrected me in a while",
    /// not merely "I was once set".
    pub max_error_us: i64,
    /// The kernel's estimate of the error, in microseconds.
    pub est_error_us: i64,
    /// Raw `ntp_adjtime` return code (`TIME_OK`, `TIME_ERROR`, …), kept so
    /// an operator can see exactly what the kernel said.
    pub state: i32,
}

impl ClockDiscipline {
    /// Whether this reading satisfies a maximum-error budget, in
    /// milliseconds. Both conditions must hold: a clock nobody is steering
    /// fails however small its stale error bound happens to be.
    pub fn within(&self, budget_ms: i64) -> bool {
        self.synchronized && self.max_error_us <= budget_ms.saturating_mul(1000)
    }

    /// A one-line operator-facing summary.
    pub fn summary(&self) -> String {
        format!(
            "clock {}, max_error {} ms (kernel state {})",
            if self.synchronized {
                "synchronized"
            } else {
                "NOT synchronized (STA_UNSYNC)"
            },
            self.max_error_us / 1000,
            self.state
        )
    }
}

impl From<ClockDiscipline> for crate::health::AttestedClock {
    /// The attested projection of a live reading.
    ///
    /// `est_error_us` is deliberately left out of the signed form. It is the
    /// kernel's *estimate*, which moves continuously and carries no decision;
    /// `max_error_us` is the kernel's *bound*, which is what the budget check
    /// and CERT-In's requirement are about. Signing a field nothing decides on
    /// would add bytes to every record and invite a verifier to reason from it.
    fn from(d: ClockDiscipline) -> Self {
        Self {
            synchronized: d.synchronized,
            max_error_us: d.max_error_us,
            state: d.state,
        }
    }
}

/// Why the clock's discipline could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The platform has no `ntp_adjtime`.
    Unsupported(&'static str),
    /// The syscall failed.
    Failed(String),
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(os) => write!(f, "clock discipline is not readable on {os}"),
            Self::Failed(e) => write!(f, "ntp_adjtime: {e}"),
        }
    }
}

impl std::error::Error for ClockError {}

/// Read the kernel's clock-discipline state. Pure query: `modes` is zero,
/// so nothing about the clock is changed.
#[cfg(target_os = "linux")]
pub fn clock_discipline() -> Result<ClockDiscipline, ClockError> {
    // SAFETY: `timex` is zeroed and `modes == 0`, which makes ntp_adjtime a
    // read-only query. The kernel writes only into this local struct.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = 0;
    let rc = unsafe { libc::ntp_adjtime(&mut tx) };
    if rc < 0 {
        return Err(ClockError::Failed(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(ClockDiscipline {
        synchronized: (tx.status & libc::STA_UNSYNC) == 0,
        // `timex`'s error fields are `c_long`: i64 on 64-bit targets, i32
        // on 32-bit ones (this crate builds for 32-bit ARM edge hosts too).
        // `i64::from` is correct on both and truncates on neither. Clippy
        // sees only the current target, where the conversion is reflexive,
        // and calls it useless; it is not useless on the other target, and
        // dropping it would break that build rather than this one.
        #[allow(clippy::useless_conversion)]
        max_error_us: i64::from(tx.maxerror),
        #[allow(clippy::useless_conversion)]
        est_error_us: i64::from(tx.esterror),
        state: rc,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn clock_discipline() -> Result<ClockDiscipline, ClockError> {
    Err(ClockError::Unsupported(std::env::consts::OS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(synchronized: bool, max_error_us: i64) -> ClockDiscipline {
        ClockDiscipline {
            synchronized,
            max_error_us,
            est_error_us: 0,
            state: 0,
        }
    }

    /// A disciplined clock inside the budget passes.
    #[test]
    fn a_synchronized_clock_within_budget_passes() {
        assert!(reading(true, 50_000).within(100)); // 50 ms error, 100 ms budget
    }

    /// A disciplined clock outside the budget fails: being steered is not
    /// the same as being close enough.
    #[test]
    fn a_synchronized_clock_outside_budget_fails() {
        assert!(!reading(true, 500_000).within(100)); // 500 ms error
    }

    /// **The one that matters.** An unsynchronized clock fails however
    /// small its error bound looks. A stale bound from a daemon that died
    /// is not evidence of accuracy, and treating a small number as a pass
    /// would let an undisciplined host stamp evidence unchallenged.
    #[test]
    fn an_unsynchronized_clock_fails_however_small_its_error_bound() {
        assert!(!reading(false, 0).within(100));
        assert!(!reading(false, 1).within(1_000_000));
    }

    /// The budget is compared in the right units, and a huge budget cannot
    /// overflow into a pass.
    #[test]
    fn the_budget_is_milliseconds_and_does_not_overflow() {
        assert!(reading(true, 1_000).within(1)); // 1 ms error, 1 ms budget
        assert!(!reading(true, 1_001).within(1));
        assert!(reading(true, i64::MAX / 2).within(i64::MAX));
    }

    /// The summary names the failure rather than burying it.
    #[test]
    fn the_summary_names_an_unsynchronized_clock() {
        assert!(reading(false, 0).summary().contains("NOT synchronized"));
        assert!(reading(true, 0).summary().contains("synchronized"));
    }

    /// Live: the reading succeeds on this host and is internally coherent.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_answers_on_this_host() {
        match clock_discipline() {
            Ok(d) => {
                assert!(d.max_error_us >= 0, "a max error is never negative");
                // Whatever the answer, `within` must agree with it.
                if !d.synchronized {
                    assert!(!d.within(i64::MAX));
                }
                eprintln!("this host: {}", d.summary());
            }
            Err(e) => panic!("ntp_adjtime must answer on Linux: {e}"),
        }
    }
}
