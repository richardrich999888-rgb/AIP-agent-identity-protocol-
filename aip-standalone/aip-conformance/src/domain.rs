//! The seven named domains, and the five crates that realise them.
//!
//! The specification names seven. The repository has five profile crates.
//! Two pairs share one — Skill 24 covers UGV *and* robotics, Skill 25 covers
//! industrial *and* critical edge — so reporting seven independent domains
//! would overstate coverage by two.
//!
//! [`Domain::realisation`] carries the mapping into the emitted artifact so a
//! reviewer sees it without reading this file.

use serde::{Deserialize, Serialize};

/// A domain named by the Skill 28 specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Domain {
    Enterprise,
    Uas,
    Ugv,
    Robotics,
    Industrial,
    CriticalEdge,
    Space,
}

/// Which crate answers for a domain, and whether it answers for others too.
///
/// `Serialize` only: like every other part of the artifact, this is computed
/// from the profiles' own constants and is not readable back in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Realisation {
    /// The crate whose types the domain's cells were read from.
    pub crate_name: &'static str,
    /// The profile identifier that crate registers.
    pub profile_id: &'static str,
    /// The profile's domain-separation tag.
    pub profile_domain: &'static str,
    /// The skill that built it.
    pub skill: u8,
    /// Other named domains realised by the same crate. Non-empty here means
    /// this row is **not** independent evidence from those rows.
    pub shared_with: &'static [Domain],
}

impl Domain {
    pub const ALL: [Domain; 7] = [
        Self::Enterprise,
        Self::Uas,
        Self::Ugv,
        Self::Robotics,
        Self::Industrial,
        Self::CriticalEdge,
        Self::Space,
    ];

    /// Stable code, so a reordering cannot change an emitted artifact's
    /// meaning.
    pub fn code(self) -> u8 {
        match self {
            Self::Enterprise => 0x01,
            Self::Uas => 0x02,
            Self::Ugv => 0x03,
            Self::Robotics => 0x04,
            Self::Industrial => 0x05,
            Self::CriticalEdge => 0x06,
            Self::Space => 0x07,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enterprise => "Enterprise",
            Self::Uas => "UAS",
            Self::Ugv => "UGV",
            Self::Robotics => "Robotics",
            Self::Industrial => "Industrial",
            Self::CriticalEdge => "CriticalEdge",
            Self::Space => "Space",
        }
    }

    /// Whether the domain is embodied — whether its effects happen in the
    /// world rather than on a host.
    ///
    /// This is the one axis ADR-011 found to be real: four embodied verticals
    /// made an embodiment-specific property look universal, and enterprise
    /// disconfirmed it. The matrix carries the axis so the next reader does
    /// not have to rediscover it.
    pub fn is_embodied(self) -> bool {
        !matches!(self, Self::Enterprise)
    }

    pub fn realisation(self) -> Realisation {
        match self {
            Self::Enterprise => Realisation {
                crate_name: "aip-enterprise",
                profile_id: aip_enterprise::ENTERPRISE_PROFILE_ID,
                profile_domain: aip_enterprise::ENTERPRISE_PROFILE_DOMAIN,
                skill: 27,
                shared_with: &[],
            },
            Self::Uas => Realisation {
                crate_name: "aip-uas",
                profile_id: aip_uas::UAS_PROFILE_ID,
                profile_domain: aip_uas::UAS_PROFILE_DOMAIN,
                skill: 23,
                shared_with: &[],
            },
            Self::Ugv => Realisation {
                crate_name: "aip-robotics",
                profile_id: aip_robotics::ROBOTICS_PROFILE_ID,
                profile_domain: aip_robotics::ROBOTICS_PROFILE_DOMAIN,
                skill: 24,
                shared_with: &[Self::Robotics],
            },
            Self::Robotics => Realisation {
                crate_name: "aip-robotics",
                profile_id: aip_robotics::ROBOTICS_PROFILE_ID,
                profile_domain: aip_robotics::ROBOTICS_PROFILE_DOMAIN,
                skill: 24,
                shared_with: &[Self::Ugv],
            },
            Self::Industrial => Realisation {
                crate_name: "aip-industrial",
                profile_id: aip_industrial::INDUSTRIAL_PROFILE_ID,
                profile_domain: aip_industrial::INDUSTRIAL_PROFILE_DOMAIN,
                skill: 25,
                shared_with: &[Self::CriticalEdge],
            },
            Self::CriticalEdge => Realisation {
                crate_name: "aip-industrial",
                profile_id: aip_industrial::INDUSTRIAL_PROFILE_ID,
                profile_domain: aip_industrial::INDUSTRIAL_PROFILE_DOMAIN,
                skill: 25,
                shared_with: &[Self::Industrial],
            },
            Self::Space => Realisation {
                crate_name: "aip-space",
                profile_id: aip_space::SPACE_PROFILE_ID,
                profile_domain: aip_space::SPACE_PROFILE_DOMAIN,
                skill: 26,
                shared_with: &[],
            },
        }
    }

    /// The distinct crates realising all seven domains.
    ///
    /// Five, not seven. A caller counting independent evidence should count
    /// these, and the emitted artifact reports both numbers.
    pub fn distinct_crates() -> Vec<&'static str> {
        let mut v: Vec<&'static str> = Self::ALL
            .iter()
            .map(|d| d.realisation().crate_name)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}
