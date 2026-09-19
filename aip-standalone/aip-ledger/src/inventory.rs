//! The AI-inventory entry a FREE-AI inventory needs (R17 of
//! `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`, matrix row F1).
//!
//! # What this is and is not
//!
//! The RBI's FREE-AI framework asks a regulated entity to keep an inventory
//! of the AI systems it uses and to review it periodically. The inventory is
//! **the entity's**: it names owners, business purposes, model vendors and
//! approval dates, none of which this system knows or should invent.
//!
//! What this system can supply is the part an inventory entry is usually
//! weakest on: what the agent actually reached, in a window, on evidence
//! rather than on the team's recollection. [`InventoryEntry`] is that
//! attachment, derived entirely from a **verified** [`AccessLedger`] so that
//! nothing in it is a fresh assertion.
//!
//! # Why it takes a verified ledger
//!
//! [`InventoryEntry::from_ledger`] takes a `&AccessLedger` and the anchors to
//! check it under, and verifies before deriving. An inventory attachment
//! built from an unverified ledger would launder an unsigned document into a
//! regulatory record — the same failure the verdict API refuses at its own
//! boundary.
//!
//! # What a reader must not conclude
//!
//! The entry counts rows by standing, and a row's standing is never stronger
//! than the verdicts cited to it. A window with no adverse rows is not a
//! clean bill of health: it may be a window nobody observed. `unproven` and
//! `no_verdict` are reported separately from `verified` for exactly that
//! reason, and a reviewer who adds them together has been told not to.

use serde::{Deserialize, Serialize};

use crate::{AccessLedger, LedgerError, LedgerTrustAnchors, ResourceRef, Standing};

/// One resource an agent reached, as an inventory reviewer sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTouched {
    /// The institution's own name for the system, from the registry the
    /// ledger cites, or `None` where the endpoint was not registered.
    pub resource_id: Option<String>,
    /// Criticality class code from the registry entry.
    pub criticality: Option<u8>,
    /// How many distinct endpoint rows resolved to this resource.
    pub rows: usize,
    /// Rows whose standing is `Verified`.
    pub verified: usize,
    /// Rows whose standing is `Adverse`. **The number a reviewer reads
    /// first.**
    pub adverse: usize,
}

/// The evidence attachment for one inventory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub agent_id: String,
    pub window_from_ms: u64,
    pub window_to_ms: u64,
    /// Which registry revision named the resources below. Two entries from
    /// different revisions are not directly comparable, and saying so is
    /// cheaper than a reviewer discovering it.
    pub registry_id: String,
    pub registry_revision: u64,
    /// The ledger this entry was derived from, by digest, so a reviewer can
    /// ask for the document itself.
    pub ledger_digest: String,
    /// Who signed that ledger.
    pub ledger_signer_id: String,
    pub resources: Vec<ResourceTouched>,
    /// Row counts by standing, across every resource.
    pub verified_rows: usize,
    pub adverse_rows: usize,
    /// Rows the evidence did not settle either way.
    pub unproven_rows: usize,
    /// Rows with no verdict cited at all.
    pub no_verdict_rows: usize,
    /// Endpoints the institution's registry never named. A non-zero count is
    /// a question for the infrastructure owner, not necessarily a finding
    /// about the agent.
    pub unregistered_endpoints: usize,
    /// Signed verdicts supplied to the ledger builder that matched no row.
    /// Non-zero means the ledger and the verdicts disagree about what
    /// happened, which a reviewer should resolve before relying on either.
    pub unmatched_verdicts: usize,
}

impl InventoryEntry {
    /// Derive an entry from a ledger, verifying it first.
    ///
    /// Every number below is counted from the ledger's own rows. Nothing is
    /// asserted here that the ledger does not already say.
    pub fn from_ledger(
        ledger: &AccessLedger,
        anchors: &LedgerTrustAnchors,
    ) -> Result<Self, LedgerError> {
        ledger.verify(anchors)?;

        // Group rows by the resource they resolved to. `None` collects every
        // unregistered endpoint into one row, because an inventory reviewer
        // wants the count, not a list of addresses.
        let mut named: std::collections::BTreeMap<(String, u8), ResourceTouched> =
            std::collections::BTreeMap::new();
        let mut unregistered = ResourceTouched {
            resource_id: None,
            criticality: None,
            rows: 0,
            verified: 0,
            adverse: 0,
        };
        let (mut verified_rows, mut adverse_rows, mut unproven_rows, mut no_verdict_rows) =
            (0usize, 0usize, 0usize, 0usize);

        for e in &ledger.entries {
            match e.standing {
                Standing::Verified => verified_rows += 1,
                Standing::Adverse => adverse_rows += 1,
                Standing::Unproven => unproven_rows += 1,
                Standing::NoVerdict => no_verdict_rows += 1,
            }
            let slot = match &e.resource {
                ResourceRef::Named { id, criticality } => named
                    .entry((id.clone(), *criticality))
                    .or_insert_with(|| ResourceTouched {
                        resource_id: Some(id.clone()),
                        criticality: Some(*criticality),
                        rows: 0,
                        verified: 0,
                        adverse: 0,
                    }),
                ResourceRef::Unregistered => &mut unregistered,
            };
            slot.rows += 1;
            match e.standing {
                Standing::Verified => slot.verified += 1,
                Standing::Adverse => slot.adverse += 1,
                _ => {}
            }
        }

        let mut resources: Vec<ResourceTouched> = named.into_values().collect();
        // Most critical first, then most adverse: the order a reviewer with
        // limited time should read.
        resources.sort_by(|a, b| {
            b.criticality
                .cmp(&a.criticality)
                .then(b.adverse.cmp(&a.adverse))
                .then(a.resource_id.cmp(&b.resource_id))
        });
        if unregistered.rows > 0 {
            resources.push(unregistered.clone());
        }

        Ok(Self {
            agent_id: ledger.agent_id.clone(),
            window_from_ms: ledger.window.from_ms,
            window_to_ms: ledger.window.to_ms,
            registry_id: ledger.registry_id.clone(),
            registry_revision: ledger.registry_revision,
            ledger_digest: hex_digest(&ledger.digest()),
            ledger_signer_id: ledger.ledger_signer_id.clone(),
            resources,
            verified_rows,
            adverse_rows,
            unproven_rows,
            no_verdict_rows,
            unregistered_endpoints: unregistered.rows,
            unmatched_verdicts: ledger.unmatched_verdicts as usize,
        })
    }

    /// Whether this window contains anything a reviewer must act on.
    ///
    /// Deliberately narrow: an adverse row, or verdicts that did not match
    /// the ledger. Absence of those is **not** a clean window — see the
    /// module documentation.
    pub fn needs_review(&self) -> bool {
        self.adverse_rows > 0 || self.unmatched_verdicts > 0
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("inventory entry is serialisable")
    }
}

fn hex_digest(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
