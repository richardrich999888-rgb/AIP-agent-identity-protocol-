//! Fail-closed conformance for the consequential effects that have no packet
//! shape to reconcile against.
//!
//! [`crate::reconcile`] pairs an observed tool invocation with the sealed
//! packet that authorised it, keyed on the digest of the call's parameters.
//! Two consequential effects have no such key: raw network egress and a
//! spawned process are observed at the network or OS layer, where there is no
//! `params_digest` to match and often no governed packet at all — a tool the
//! gateway sealed may itself be what opened the socket. `reconcile` says as
//! much and skips them; until now nothing picked them up, so an agent
//! exfiltrating four megabytes to an unlisted host produced no finding
//! whatsoever. That is the exact shape of the July 2026 frontier-lab
//! intrusions, where the escape was a network pivot, not a tool call.
//!
//! The model here is not reconciliation but **conformance**, matching the
//! fail-closed posture the eBPF transport layer (the `sovereign-overlay`
//! `connect4` policy core) already takes: an operator declares the
//! destinations egress may reach and the commands a process may be, and
//! *anything outside the declared set is a finding*. Set non-membership is
//! arithmetic — a destination either is on
//! the allowlist or it is not — so a conforming trusted sensor's report of an
//! unapproved egress is [`crate::finding::Strength::Proof`], the same standard
//! a broken hash chain earns, and can carry the warrant for automatic
//! containment.
//!
//! # Opt-in, then fail-closed inside the declaration
//!
//! A [`Patrol`](crate::patrol::Patrol) with no [`EffectPolicy`] draws no
//! conformance findings at all — a deployment that has not declared its egress
//! posture is "not configured", not "in violation", the same stance
//! [`crate::response::ResponsePolicy`] takes by defaulting to advisory. But
//! the instant a policy *is* declared, it is fail-closed within its scope:
//! every egress to a destination it did not approve is flagged. There is no
//! "declared but permissive" middle state, because that is precisely the gap
//! an escaping agent aims for.

/// The declared conformance posture: what egress may reach, and what a
/// process may be. Absence of a policy means the conformance detector stays
/// silent; presence means fail-closed within the declared dimension.
#[derive(Debug, Clone, Default)]
pub struct EffectPolicy {
    /// Destinations egress is permitted to reach. A destination conforms when
    /// it equals an entry exactly, or is a subdomain of one (so `mission.gov`
    /// approves `telemetry.mission.gov` but never `evil-mission.gov`). Empty
    /// means fail-closed: no egress conforms, every observed egress is a
    /// finding — the correct posture for an air-gapped deployment.
    approved_destinations: Vec<String>,
    /// Whether egress is governed at all. When false, egress observations are
    /// ignored — for a deployment that watches process spawns but not the
    /// network, or vice versa, so declaring one dimension does not silently
    /// fail-close the other.
    govern_egress: bool,
    /// Command lines a spawned process is permitted to be. A command conforms
    /// when it equals an entry exactly or begins with one followed by a space
    /// (so `/usr/bin/python3` approves `/usr/bin/python3 job.py` but never
    /// `/usr/bin/python3-evil`). Empty with `govern_spawn` set is fail-closed.
    approved_commands: Vec<String>,
    /// Whether process spawns are governed at all.
    govern_spawn: bool,
}

impl EffectPolicy {
    /// A policy that governs egress, fail-closed: nothing is approved yet, so
    /// every observed egress is a finding until destinations are allowed in.
    pub fn governing_egress() -> Self {
        Self {
            govern_egress: true,
            ..Self::default()
        }
    }

    /// A policy that governs process spawns, fail-closed.
    pub fn governing_spawn() -> Self {
        Self {
            govern_spawn: true,
            ..Self::default()
        }
    }

    /// Approves an egress destination (and switches egress governance on, so
    /// `EffectPolicy::default().allow_destination(..)` is fail-closed egress
    /// with one hole, never accidentally-permissive).
    pub fn allow_destination(mut self, destination: impl Into<String>) -> Self {
        self.approved_destinations.push(destination.into());
        self.govern_egress = true;
        self
    }

    /// Approves a process-spawn command prefix (and switches spawn governance
    /// on).
    pub fn allow_command(mut self, command: impl Into<String>) -> Self {
        self.approved_commands.push(command.into());
        self.govern_spawn = true;
        self
    }

    /// Whether egress is governed by this policy at all.
    pub fn governs_egress(&self) -> bool {
        self.govern_egress
    }

    /// Whether process spawns are governed by this policy at all.
    pub fn governs_spawn(&self) -> bool {
        self.govern_spawn
    }

    /// True when `destination` is approved: an exact match, or a subdomain of
    /// an approved domain. The subdomain rule requires a `.` boundary so
    /// `mission.gov` cannot approve `evil-mission.gov`.
    pub fn permits_destination(&self, destination: &str) -> bool {
        // A destination may carry a port (`host:443`); conformance is on the
        // host, so compare against the part before the last colon when one is
        // present and the tail is numeric.
        let host = split_host(destination);
        self.approved_destinations
            .iter()
            .any(|approved| host == approved || host.ends_with(&format!(".{approved}")))
    }

    /// True when `command` is approved: an exact match, or an approved entry
    /// followed by a space (an argument boundary), so `/bin/sh` cannot approve
    /// `/bin/sha-evil`.
    pub fn permits_command(&self, command: &str) -> bool {
        self.approved_commands
            .iter()
            .any(|approved| command == approved || command.starts_with(&format!("{approved} ")))
    }
}

/// The host portion of a destination, dropping a trailing `:port` when the
/// port is numeric. `attacker.example.com:443` → `attacker.example.com`;
/// `1.2.3.4` and `[::1]:80` are returned as-is except for a numeric tail.
fn split_host(destination: &str) -> &str {
    match destination.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => destination,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undeclared_policy_governs_nothing() {
        let policy = EffectPolicy::default();
        assert!(!policy.governs_egress());
        assert!(!policy.governs_spawn());
    }

    #[test]
    fn declaring_a_destination_fail_closes_egress_around_it() {
        let policy = EffectPolicy::default().allow_destination("mission.gov");
        assert!(
            policy.governs_egress(),
            "one allow entry turns governance on"
        );
        assert!(policy.permits_destination("mission.gov"));
        assert!(policy.permits_destination("telemetry.mission.gov"));
        assert!(policy.permits_destination("telemetry.mission.gov:443"));
        // The subdomain boundary is a real dot, not a substring.
        assert!(!policy.permits_destination("evil-mission.gov"));
        assert!(!policy.permits_destination("attacker.example.com"));
    }

    #[test]
    fn fail_closed_egress_approves_nothing_until_told_to() {
        let policy = EffectPolicy::governing_egress();
        assert!(policy.governs_egress());
        assert!(!policy.permits_destination("anything.at.all"));
    }

    #[test]
    fn a_command_prefix_stops_at_an_argument_boundary() {
        let policy = EffectPolicy::default().allow_command("/usr/bin/python3");
        assert!(policy.governs_spawn());
        assert!(policy.permits_command("/usr/bin/python3"));
        assert!(policy.permits_command("/usr/bin/python3 mission_job.py"));
        // No boundary-crossing: a lookalike binary is not approved.
        assert!(!policy.permits_command("/usr/bin/python3-evil --exfil"));
    }

    #[test]
    fn a_port_does_not_smuggle_an_unapproved_host_past_the_check() {
        let policy = EffectPolicy::default().allow_destination("mission.gov");
        // Numeric port is stripped for the host comparison…
        assert!(policy.permits_destination("mission.gov:8443"));
        // …but a non-numeric tail is part of the host and must not match.
        assert!(!policy.permits_destination("mission.gov:evil"));
    }
}
