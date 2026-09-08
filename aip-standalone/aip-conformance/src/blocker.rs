//! Inherited blockers, tracked until closure is **independently verified**
//! (Skill 29, R5).
//!
//! The forensic audit's register (B-1a … B-10) was closed during Skill 16 and
//! its evidence report records the commits. Skill 29's required work is not to
//! restate that register — it is to *track* it, which means re-deriving each
//! status from the repository rather than reading it from a document.
//!
//! So each entry below carries two things that are deliberately kept apart:
//! what the register says, and what the code says. Where they agree, the entry
//! records the mechanism found. Where they would disagree, the code wins and
//! `tests/blocker.rs` fails.
//!
//! One entry is stronger than its register line rather than weaker: B-4 was
//! recorded as *closed by refusing* a bundle-supplied signer key, and the
//! current code has no field for one at all — the attack is unrepresentable,
//! not merely refused.

use serde::{Deserialize, Serialize};

/// Where a blocker stands, as re-derived from the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockerStatus {
    /// The mechanism that closes it is present and was located.
    ClosedAndVerified,
    /// Recorded closed, and the verification here could not reach it. Not a
    /// failure and not a pass: a statement that this tracker did not check.
    ClosedNotVerifiedHere,
    /// Open. Recorded as open regardless of what any document says.
    Open,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClosedAndVerified => "CLOSED-AND-VERIFIED",
            Self::ClosedNotVerifiedHere => "CLOSED-NOT-VERIFIED-HERE",
            Self::Open => "OPEN",
        }
    }
}

/// One inherited blocker.
///
/// `Serialize` only, as with every other artifact type in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    pub id: &'static str,
    pub finding: &'static str,
    pub status: BlockerStatus,
    /// What was located in the repository. Never a commit hash alone: a hash
    /// says a change happened, not that the property holds now.
    pub verified_by: &'static str,
    /// Where the closure stops, when it stops somewhere a reader should know
    /// about.
    pub boundary: &'static str,
}

/// The register, re-derived at this HEAD.
pub fn inherited_blockers() -> Vec<Blocker> {
    vec![
        Blocker {
            id: "B-1a",
            finding: "service verification applied no temporal bound",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "aip-service/src/evidence.rs threads verification_time_ms and future_tolerance_ms into the verification context",
            boundary: "",
        },
        Blocker {
            id: "B-3",
            finding: "reconciler to warrant to containment never driven end to end",
            status: BlockerStatus::Open,
            verified_by: "aip-containment/tests/engine_to_containment.rs drives the crossing on a live process and it terminates in a refusal",
            boundary: "the crossing executes; actuation remains unreachable from genuine reconciliation, by three independent gate closures. Recorded open, and this milestone does not close it",
        },
        Blocker {
            id: "B-4",
            finding: "bundle verifier trusted a key supplied by the bundle",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "SignedHead carries no public-key field; the verifier's only key source is NexoraTrustAnchors::get(signer_id, key_version)",
            boundary: "stronger than the register records: the attack is unrepresentable in the type rather than refused at runtime",
        },
        Blocker {
            id: "B-5",
            finding: "seed written then chmod'd; an overwrite window existed",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "aip-crypto/src/custody.rs takes the mode from OpenOptions::mode rather than a later chmod",
            boundary: "",
        },
        Blocker {
            id: "B-6",
            finding: "key load failure silently generated a new identity",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "aip-service/src/keys.rs load_or_create is explicit about which path mints, and the auth layer fails closed with no keys configured",
            boundary: "",
        },
        Blocker {
            id: "B-7",
            finding: "private agent seeds in HTTP request bodies",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "POST /v1/evidence/generate is not mounted unless AIP_ALLOW_MANAGED_SIGNING=1; the route is chosen at router-build time, so on the refusing path there is no extractor and a seed sent to a default deployment is never deserialised",
            boundary: "the request type still carries the seed fields, because the endpoint still exists behind the opt-in. A deployment that sets the variable has accepted that the service can sign under any identity it is handed",
        },
        Blocker {
            id: "B-8",
            finding: "no replay semantics and no anti-replay mechanism",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "aip-nexora/src/replay.rs ProofSeen ledger, and ObserverLedger refuses a batch at a consumed sequence",
            boundary: "",
        },
        Blocker {
            id: "B-9",
            finding: "Reconciliation construction was not sealed",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "Reconciliation is #[non_exhaustive] with a private provenance field, so no other crate can write a literal, and a deserialised record reports Provenance::Deserialized",
            boundary: "",
        },
        Blocker {
            id: "B-10",
            finding: "aip-service outside the primary build and test boundary",
            status: BlockerStatus::ClosedAndVerified,
            verified_by: "aip-service is a workspace member and CI runs cargo test --all",
            boundary: "",
        },
    ]
}

/// Blockers still open. The list a reader checks first.
pub fn open_blockers() -> Vec<Blocker> {
    inherited_blockers()
        .into_iter()
        .filter(|b| b.status == BlockerStatus::Open)
        .collect()
}
